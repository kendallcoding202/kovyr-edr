package main

import (
	"bytes"
	"testing"
)

func TestRefusesPlainHTTPBeyondLoopback(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:8787", ":8787", "192.168.1.10:8787", "[::]:8787"} {
		var out bytes.Buffer
		if code := run([]string{"--addr", addr}, &out); code != 2 {
			t.Errorf("%s: exit %d, want 2 (refused)", addr, code)
		}
	}
	for _, addr := range []string{"127.0.0.1:8787", "localhost:8787", "[::1]:8787"} {
		if !loopbackAddr(addr) {
			t.Errorf("%s should count as loopback", addr)
		}
	}
	var out bytes.Buffer
	if code := run([]string{"--tls-cert", "x.pem"}, &out); code != 2 {
		t.Errorf("cert without key: exit %d", code)
	}
}
