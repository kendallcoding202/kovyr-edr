// Command kovyr-receiver-dev is a heartbeat receiver for local testing.
//
// FOR DEVELOPMENT ONLY. It keeps state in memory and a JSON-lines file,
// has no authentication on /v0/status and no rate limits. The production
// receiver is part of Kovyr's halden service and implements the same API
// (docs/api.md).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kendallcoding202/kovyr-edr/internal/receiver"
)

func main() { os.Exit(run(os.Args[1:], os.Stderr)) }

func run(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("kovyr-receiver-dev", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", "127.0.0.1:8787", "listen address (loopback unless --tls-cert/--tls-key are set)")
	devicesPath := fs.String("devices", "devices.json", `enrolled devices: {"devices":[{"device_id":...,"public_key":...,"label":...}]}`)
	storePath := fs.String("store", "kovyr-receiver-dev.jsonl", "JSON-lines file of every envelope received")
	interval := fs.Duration("interval", 15*time.Minute, "expected heartbeat interval, for gap detection")
	tlsCert := fs.String("tls-cert", "", "TLS certificate (PEM); needed to listen beyond loopback")
	tlsKey := fs.String("tls-key", "", "TLS key (PEM)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	logger := log.New(stderr, "kovyr-receiver-dev: ", log.LstdFlags)
	if (*tlsCert == "") != (*tlsKey == "") {
		logger.Print("--tls-cert and --tls-key go together")
		return 2
	}
	if *tlsCert == "" && !loopbackAddr(*addr) {
		logger.Printf("refusing to serve plain HTTP on %s; use a loopback address or --tls-cert/--tls-key", *addr)
		return 2
	}

	loadDevices := func() ([]receiver.Device, error) {
		ds, err := receiver.LoadDevices(*devicesPath)
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return ds, err
	}
	devices, err := loadDevices()
	if err != nil {
		logger.Print(err)
		return 1
	}
	if len(devices) == 0 {
		logger.Printf("no devices enrolled yet; add `kovyr-agent enroll --print-pubkey` output to %s (it is re-read when an unknown device calls)", *devicesPath)
	}
	store, err := receiver.OpenStore(*storePath)
	if err != nil {
		logger.Print(err)
		return 1
	}
	r, err := receiver.New(receiver.Config{Interval: *interval}, devices, store)
	if err != nil {
		logger.Print(err)
		return 1
	}
	r.SetReloader(loadDevices)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           r.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          logger,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	scheme := "http"
	if *tlsCert != "" {
		scheme = "https"
	}
	logger.Printf("DEV ONLY - not the production receiver (that is halden). Listening on %s://%s, %d device(s) enrolled, store %s",
		scheme, *addr, len(devices), *storePath)
	if scheme == "http" {
		fmt.Fprintf(stderr, "  agent: kovyr-agent run --server http://%s --dev-insecure\n  status: curl http://%s/v0/status\n", *addr, *addr)
		err = srv.ListenAndServe()
	} else {
		err = srv.ListenAndServeTLS(*tlsCert, *tlsKey)
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Print(err)
		return 1
	}
	return 0
}

func loopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
