package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
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
	"github.com/kendallcoding202/kovyr-edr/proof/canon"
)

// Transport is how the agent reaches the server. It has exactly two
// operations and neither returns anything the agent could act on: a nonce,
// and whether an envelope was delivered.
type Transport interface {
	// Challenge asks for a nonce issued for this device (SPEC section 8).
	Challenge(ctx context.Context, deviceID string) (proof.Nonce, error)
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
	// maxResponseHeaders caps the response headers (Go's default is 10
	// MiB). The API needs a Content-Type; 16 KiB leaves room for what a
	// hosting platform adds.
	maxResponseHeaders = 16 << 10
	requestTimeout     = 30 * time.Second
)

// userAgent names the agent on every request: a fixed string, with the
// version every statement already carries.
var userAgent = fmt.Sprintf("kovyr-alarm/%d.%d.%d", Version.Major, Version.Minor, Version.Patch)

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
	// The agent connects directly (docs/testing-on-your-pc.md): no proxy
	// from HTTP_PROXY / HTTPS_PROXY, which would carry its traffic
	// through whatever an administrator, or malware running as one, sets.
	tr.Proxy = nil
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	tr.MaxIdleConns = 2
	tr.IdleConnTimeout = 30 * time.Second
	tr.MaxResponseHeaderBytes = maxResponseHeaders
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

func validDeviceID(s string) bool {
	if len(s) != len(proof.DevicePrefix)+16 || !strings.HasPrefix(s, proof.DevicePrefix) {
		return false
	}
	_, err := hex.DecodeString(s[len(proof.DevicePrefix):])
	return err == nil && strings.ToLower(s) == s
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

// fixedError has fixed text and keeps its cause for errors.Is.
type fixedError struct {
	msg string
	err error
}

func (e *fixedError) Error() string { return e.msg }
func (e *fixedError) Unwrap() error { return e.err }

// requestFailed replaces a failed request's error text with a fixed one.
// Go's text can quote what the server sent (a malformed status or header
// line, the names in its certificate, HTTP/2 GOAWAY debug data), and the
// agent writes nothing the server chooses into its log: only status codes
// and fixed strings.
func requestFailed(op string, err error) error {
	var (
		dns     *net.DNSError
		netOp   *net.OpError
		timeout interface{ Timeout() bool }
		verify  *tls.CertificateVerificationError
		host    x509.HostnameError
		unknown x509.UnknownAuthorityError
		invalid x509.CertificateInvalidError
	)
	reason := "request failed"
	switch {
	case errors.Is(err, context.Canceled):
		reason = "cancelled"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &timeout) && timeout.Timeout():
		reason = "timed out"
	case errors.As(err, &dns):
		reason = "could not resolve the server name"
	case errors.As(err, &verify), errors.As(err, &host), errors.As(err, &unknown), errors.As(err, &invalid):
		reason = "the server's certificate was not accepted"
	case errors.As(err, &netOp) && netOp.Op == "dial":
		reason = "could not connect"
	}
	return &fixedError{msg: op + ": " + reason, err: err}
}

// Challenge fetches a one-time nonce issued for deviceID. The response
// must be exactly
// {"nonce":"<32 lowercase hex>"} in canonical JSON (one trailing newline
// allowed). Anything else, including any extra field, is rejected: the
// server cannot send the agent instructions.
func (c *HTTPClient) Challenge(ctx context.Context, deviceID string) (proof.Nonce, error) {
	var n proof.Nonce
	if !validDeviceID(deviceID) {
		return n, errors.New("challenge: bad device ID")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.endpoint("/v0/challenge")+"?"+url.Values{"device": {deviceID}}.Encode(), nil)
	if err != nil {
		return n, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.hc.Do(req)
	if err != nil {
		return n, requestFailed("challenge", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return n, fmt.Errorf("challenge: HTTP %d", resp.StatusCode)
	}
	if mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mt != "application/json" {
		return n, fmt.Errorf("%w: content type is not application/json", ErrNotANonce)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxChallengeBody+1))
	if err != nil {
		return n, requestFailed("challenge", err)
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
	o, err := canon.ParseObject(body)
	if err != nil {
		// The parser's text can quote the body: keep it out of the log.
		return n, fmt.Errorf("%w: not one canonical JSON object", ErrNotANonce)
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
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.hc.Do(req)
	if err != nil {
		return requestFailed("heartbeat", err)
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
