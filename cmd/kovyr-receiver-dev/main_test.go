package main

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"
)

func TestRefusesPlainHTTPBeyondLoopback(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:0", ":0", "192.168.1.10:0", "[::]:0"} {
		done := make(chan int, 1)
		go func() {
			var out bytes.Buffer
			done <- run([]string{"--addr", addr, "--store", filepath.Join(t.TempDir(), "s.jsonl")}, &out)
		}()
		select {
		case code := <-done:
			if code != 2 {
				t.Errorf("%s: exit %d, want 2 (refused)", addr, code)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("%s: served plain HTTP beyond loopback", addr)
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
