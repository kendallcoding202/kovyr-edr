package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kendallcoding202/kovyr-edr/internal/proof"
)

// Transport is how the agent reaches the server. It has exactly two
// operations and neither returns anything the agent could act on: a nonce,
// and whether an envelope was delivered.
type Transport interface {
	Challenge(ctx context.Context) (proof.Nonce, error)
	PostHeartbeat(ctx context.Context, envelope []byte) error
}

// ErrRefused means the server permanently refused an envelope (malformed,
// duplicate or replay). Retrying cannot help, so the agent drops it; the
// receiver keeps its own record of the refusal.
var ErrRefused = errors.New("server refused the envelope")

// ErrNotANonce means the challenge response was anything other than
// exactly {"nonce":"<32 lowercase hex>"}.
var ErrNotANonce = errors.New("challenge response is not a nonce")

const (
	maxChallengeBody = 256
	maxDiscardBody   = 4 << 10
	requestTimeout   = 30 * time.Second
)

// HTTPClient is the HTTPS transport.
type HTTPClient struct {
	base *url.URL
	hc   *http.Client
}

// NewHTTPClient validates the server URL: HTTPS only, except plain HTTP to
// a loopback address when devInsecure is set. No credentials, query or
// fragment may ride in the URL.
func NewHTTPClient(server string, devInsecure bool) (*HTTPClient, error) {
	u, err := url.Parse(server)
	if err != nil {
		return nil, fmt.Errorf("server URL: %w", err)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("server URL must not contain credentials, a query or a fragment")
	}
	if u.Host == "" {
		return nil, errors.New("server URL needs a host")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !devInsecure {
			return nil, errors.New("server URL must use https (plain http is allowed only with --dev-insecure, for localhost)")
		}
		if !isLoopback(u.Hostname()) {
			return nil, errors.New("--dev-insecure allows plain http only to localhost / 127.0.0.1 / ::1")
		}
	default:
		return nil, fmt.Errorf("server URL scheme %q is not allowed", u.Scheme)
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	tr.MaxIdleConns = 2
	tr.IdleConnTimeout = 30 * time.Second
	hc := &http.Client{
		Timeout:   requestTimeout,
		Transport: tr,
		// Never follow redirects: the agent talks to the configured server
		// and nothing else.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return &HTTPClient{base: u, hc: hc}, nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (c *HTTPClient) endpoint(p string) string {
	u := *c.base
	u.Path += p
	return u.String()
}

// Challenge fetches a one-time nonce. The response must be exactly
// {"nonce":"<32 lowercase hex>"} in canonical JSON (one trailing newline
// allowed). Anything else, including any extra field, is rejected: the
// server cannot send the agent instructions.
func (c *HTTPClient) Challenge(ctx context.Context) (proof.Nonce, error) {
	var n proof.Nonce
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint("/v0/challenge"), nil)
	if err != nil {
		return n, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return n, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return n, fmt.Errorf("challenge: HTTP %d", resp.StatusCode)
	}
	if mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mt != "application/json" {
		return n, fmt.Errorf("%w: content type %q", ErrNotANonce, mt)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxChallengeBody+1))
	if err != nil {
		return n, err
	}
	return ParseChallenge(body)
}

// ParseChallenge is the strict challenge parser.
func ParseChallenge(body []byte) (proof.Nonce, error) {
	var n proof.Nonce
	if len(body) > maxChallengeBody {
		return n, fmt.Errorf("%w: too long", ErrNotANonce)
	}
	body = bytes.TrimSuffix(body, []byte("\n"))
	o, err := proof.ParseCanonicalObject(body)
	if err != nil {
		return n, fmt.Errorf("%w: %v", ErrNotANonce, err)
	}
	s, ok := o["nonce"].(string)
	if len(o) != 1 || !ok {
		return n, fmt.Errorf("%w: it must hold exactly one field, \"nonce\"", ErrNotANonce)
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(n) || hex.EncodeToString(b) != s {
		return n, fmt.Errorf("%w: nonce must be 32 lowercase hex characters", ErrNotANonce)
	}
	copy(n[:], b)
	if n == (proof.Nonce{}) {
		return n, fmt.Errorf("%w: all-zero nonce", ErrNotANonce)
	}
	return n, nil
}

// PostHeartbeat delivers one canonical envelope. The response body is
// read (bounded) only to reuse the connection and is never parsed: there
// is nothing a server can say back except the status code.
func (c *HTTPClient) PostHeartbeat(ctx context.Context, envelope []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint("/v0/heartbeat"), bytes.NewReader(envelope))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, maxDiscardBody))
	resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusAccepted:
		return nil
	case http.StatusBadRequest, http.StatusConflict, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity:
		return fmt.Errorf("%w (HTTP %d)", ErrRefused, resp.StatusCode)
	}
	// 401/403/404 (not enrolled yet), 429, 5xx, redirects: keep it queued.
	return fmt.Errorf("heartbeat: HTTP %d", resp.StatusCode)
}
