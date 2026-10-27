package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestServerURLPolicy(t *testing.T) {
	ok := []struct {
		url      string
		insecure bool
	}{
		{"https://halden.example.com", false},
		{"https://halden.example.com/base/", false},
		{"https://halden.example.com", true},
		{"http://localhost:8787", true},
		{"http://127.0.0.1:8787", true},
		{"http://[::1]:8787", true},
	}
	for _, c := range ok {
		if _, err := NewHTTPClient(c.url, c.insecure); err != nil {
			t.Errorf("%s (insecure=%v): %v", c.url, c.insecure, err)
		}
	}
	bad := []struct {
		url      string
		insecure bool
	}{
		{"http://localhost:8787", false},    // http needs the flag
		{"http://halden.example.com", true}, // and only to loopback
		{"http://10.0.0.5:8787", true},      // LAN is not loopback
		{"http://localhost.evil.com", true}, // not loopback either
		{"https://user:pw@halden.example.com", false},
		{"https://halden.example.com/?cmd=x", false},
		{"https://halden.example.com/#x", false},
		{"ftp://halden.example.com", false},
		{"halden.example.com", false},
		{"https://", false},
	}
	for _, c := range bad {
		if _, err := NewHTTPClient(c.url, c.insecure); err == nil {
			t.Errorf("%s (insecure=%v): accepted", c.url, c.insecure)
		}
	}
}

// The challenge response is a nonce and nothing else. Anything a server
// might try to slip in (a command, a script, extra fields) is rejected.
func TestParseChallengeRejectsAnythingButANonce(t *testing.T) {
	const good = `{"nonce":"00112233445566778899aabbccddeeff"}`
	if _, err := ParseChallenge([]byte(good)); err != nil {
		t.Fatalf("good challenge rejected: %v", err)
	}
	if _, err := ParseChallenge([]byte(good + "\n")); err != nil {
		t.Fatalf("one trailing newline must be allowed: %v", err)
	}
	bad := []string{
		`{"command":"isolate","nonce":"00112233445566778899aabbccddeeff"}`,
		`{"nonce":"00112233445566778899aabbccddeeff","script":"Set-MpPreference -DisableRealtimeMonitoring $true"}`,
		`{"nonce":"00112233445566778899aabbccddeeff","update_url":"https://evil.example/agent.exe"}`,
		`{"interval_s":1,"nonce":"00112233445566778899aabbccddeeff"}`,
		`{"nonce":"00112233445566778899AABBCCDDEEFF"}`,
		`{"nonce":"0011"}`,
		`{"nonce":"00000000000000000000000000000000"}`,
		`{"nonce":12345}`,
		`{"nonce":["00112233445566778899aabbccddeeff"]}`,
		`{ "nonce": "00112233445566778899aabbccddeeff" }`,
		`{"nonce":"00112233445566778899aabbccddeeff","nonce":"00112233445566778899aabbccddeef0"}`,
		`{"nonce":"00112233445566778899aabbccddeeff"}{"cmd":"x"}`,
		`{"nonce":"00112233445566778899aabbccddeeff"}` + "\n\n",
		`"00112233445566778899aabbccddeeff"`,
		``,
		strings.Repeat(" ", 300),
	}
	for _, b := range bad {
		if _, err := ParseChallenge([]byte(b)); !errors.Is(err, ErrNotANonce) {
			t.Errorf("accepted %q (err %v)", b, err)
		}
	}
}

const testDevice = "dev_0123456789abcdef"

func TestChallengeOverHTTP(t *testing.T) {
	var ctype, body atomic.Value
	ctype.Store("application/json")
	body.Store(`{"nonce":"00112233445566778899aabbccddeeff"}` + "\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v0/challenge" || r.Method != http.MethodGet || r.URL.Query().Get("device") != testDevice {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", ctype.Load().(string))
		io.WriteString(w, body.Load().(string))
	}))
	defer srv.Close()
	c, err := NewHTTPClient(srv.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	n, err := c.Challenge(context.Background(), testDevice)
	if err != nil || fmt.Sprintf("%x", n[:]) != "00112233445566778899aabbccddeeff" {
		t.Fatalf("challenge %x, %v", n, err)
	}
	for _, bad := range []string{"", "dev_0123", "DEV_0123456789ABCDEF", "dev_0123456789abcdeg", "dev_0123456789abcdef&x=1"} {
		if _, err := c.Challenge(context.Background(), bad); err == nil {
			t.Errorf("challenge sent for device ID %q", bad)
		}
	}
	ctype.Store("text/html")
	if _, err := c.Challenge(context.Background(), testDevice); err == nil {
		t.Error("accepted a non-JSON content type")
	}
	ctype.Store("application/json")
	body.Store(`{"exec":"calc.exe","nonce":"00112233445566778899aabbccddeeff"}`)
	if _, err := c.Challenge(context.Background(), testDevice); !errors.Is(err, ErrNotANonce) {
		t.Errorf("accepted a challenge with a command: %v", err)
	}
}

func TestHeartbeatResponseIsNeverActedOn(t *testing.T) {
	var posts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// A hostile server answers with instructions. PostHeartbeat has no
		// way to return them: its only result is an error value.
		io.WriteString(w, `{"command":"run","script":"powershell -enc ...","download":"https://evil.example/x.exe"}`)
		io.WriteString(w, strings.Repeat("x", 1<<20))
	}))
	defer srv.Close()
	c, _ := NewHTTPClient(srv.URL, true)
	if err := c.PostHeartbeat(context.Background(), []byte(`{}`)); err != nil {
		t.Fatalf("delivery with a hostile body should count as delivered: %v", err)
	}
	if posts.Load() != 1 {
		t.Fatalf("server saw %d posts", posts.Load())
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	var elsewhere atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhere.Add(1)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"nonce":"00112233445566778899aabbccddeeff"}`)
	}))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	c, _ := NewHTTPClient(srv.URL, true)
	if _, err := c.Challenge(context.Background(), testDevice); err == nil {
		t.Error("challenge followed a redirect")
	}
	if err := c.PostHeartbeat(context.Background(), []byte(`{}`)); err == nil {
		t.Error("heartbeat treated a redirect as delivered")
	}
	if elsewhere.Load() != 0 {
		t.Errorf("the agent contacted the redirect target %d times", elsewhere.Load())
	}
}

func TestHeartbeatStatusMapping(t *testing.T) {
	cases := map[int]string{
		200: "ok", 202: "ok",
		400: "refused", 409: "refused", 413: "refused", 422: "refused",
		401: "retry", 403: "retry", 404: "retry", 429: "retry", 500: "retry", 503: "retry",
	}
	for code, want := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code) }))
		c, _ := NewHTTPClient(srv.URL, true)
		err := c.PostHeartbeat(context.Background(), []byte(`{}`))
		got := "retry"
		switch {
		case err == nil:
			got = "ok"
		case errors.Is(err, ErrRefused):
			got = "refused"
		}
		if got != want {
			t.Errorf("HTTP %d: %s, want %s", code, got, want)
		}
		srv.Close()
	}
}

func TestHTTPSWorks(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"nonce":"00112233445566778899aabbccddeeff"}`)
	}))
	defer srv.Close()
	c, err := NewHTTPClient(srv.URL, false)
	if err != nil {
		t.Fatal(err)
	}
	// An untrusted certificate must fail: no InsecureSkipVerify anywhere.
	if _, err := c.Challenge(context.Background(), testDevice); err == nil {
		t.Fatal("accepted an untrusted TLS certificate")
	}
	c.hc.Transport.(*http.Transport).TLSClientConfig.RootCAs = srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	if _, err := c.Challenge(context.Background(), testDevice); err != nil {
		t.Fatalf("trusted TLS: %v", err)
	}
}
