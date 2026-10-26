// Command kovyr-agent is the Kovyr Protection Alarm agent (v0).
//
// It only reads the machine's protection status and reports it in signed
// heartbeats. It never changes a setting, never runs a command and never
// accepts instructions from a server (CLAUDE.md section 2).
//
//	kovyr-agent check   [--state-dir DIR] [--json]
//	kovyr-agent keygen  [--state-dir DIR]
//	kovyr-agent enroll  --print-pubkey [--state-dir DIR]
//	kovyr-agent run     --server URL [--interval 15m] [--dev-insecure] [--once] [--state-dir DIR]
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/kendallcoding202/kovyr-edr/internal/agent"
	"github.com/kendallcoding202/kovyr-edr/internal/checks"
	"github.com/kendallcoding202/kovyr-edr/internal/keystore"
	"github.com/kendallcoding202/kovyr-edr/internal/proof"
)

// systemProbes is replaced in tests.
var systemProbes = checks.SystemProbes

const usage = `kovyr-agent: Kovyr Protection Alarm agent (v0, read-only)

Commands:
  check                  run the protection checks once; print a table and the statement
  keygen                 create this device's signing key
  enroll --print-pubkey  print the public key to enroll this device (enrollment is a stub in v0)
  run --server URL       send a signed heartbeat every interval

Common flag: --state-dir DIR (default %s)
`

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	defDir, err := keystore.DefaultDir()
	if err != nil {
		defDir = "kovyr-state"
	}
	if len(args) == 0 {
		fmt.Fprintf(stderr, usage, defDir)
		return 2
	}
	cmd, rest := args[0], args[1:]
	fs := flag.NewFlagSet("kovyr-agent "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("state-dir", defDir, "directory for the device key, chain state and queue")
	switch cmd {
	case "check":
		jsonOnly := fs.Bool("json", false, "print only the statement JSON")
		if fs.Parse(rest) != nil {
			return 2
		}
		return cmdCheck(*dir, *jsonOnly, stdout, stderr)
	case "keygen":
		if fs.Parse(rest) != nil {
			return 2
		}
		return cmdKeygen(*dir, stdout, stderr)
	case "enroll":
		printPub := fs.Bool("print-pubkey", false, "print this device's enrollment record")
		if fs.Parse(rest) != nil {
			return 2
		}
		if !*printPub {
			fmt.Fprintln(stderr, "enrollment is a stub in v0: use `kovyr-agent enroll --print-pubkey` and add the output to the receiver's devices file")
			return 2
		}
		return cmdEnroll(*dir, stdout, stderr)
	case "run":
		server := fs.String("server", "", "receiver base URL (https://...)")
		interval := fs.Duration("interval", agent.DefaultInterval, "heartbeat interval (1m to 60m)")
		insecure := fs.Bool("dev-insecure", false, "DEV ONLY: allow plain http to localhost")
		once := fs.Bool("once", false, "send one heartbeat (and any queued ones), then exit")
		if fs.Parse(rest) != nil {
			return 2
		}
		if *server == "" {
			fmt.Fprintln(stderr, "run needs --server URL")
			return 2
		}
		return cmdRun(*dir, *server, *interval, *insecure, *once, stderr)
	case "help", "-h", "--help":
		fmt.Fprintf(stdout, usage, defDir)
		return 0
	}
	fmt.Fprintf(stderr, "unknown command %q\n\n"+usage, cmd, defDir)
	return 2
}

func cmdCheck(dir string, jsonOnly bool, stdout, stderr io.Writer) int {
	readings, reports := checks.NewRunner(systemProbes()).Run()
	signer, err := keystore.Load(dir)
	ephemeral := false
	if err != nil {
		// No device key yet: preview with a throwaway key.
		k, kerr := proof.GenerateSoftwareKey()
		if kerr != nil {
			fmt.Fprintln(stderr, kerr)
			return 1
		}
		signer, _ = proof.NewSoftwareSigner(k)
		ephemeral = true
	}
	payload, err := previewStatement(signer, readings)
	if err != nil {
		fmt.Fprintln(stderr, "statement:", err)
		return 1
	}
	var pretty map[string]any
	json.Unmarshal(payload, &pretty)
	out, _ := json.MarshalIndent(pretty, "", "  ")
	if jsonOnly {
		fmt.Fprintln(stdout, string(out))
		return 0
	}
	printTable(stdout, readings, reports)
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "Statement (preview: not sent, not part of the chain; the nonce is random, not a server challenge):")
	if ephemeral {
		fmt.Fprintln(stdout, "(no device key yet, so a throwaway key names the device; run `kovyr-agent keygen`)")
	}
	fmt.Fprintln(stdout, string(out))
	return 0
}

// previewStatement builds a statement exactly as a heartbeat would, with
// seq 1 and a random nonce, and checks it.
func previewStatement(s proof.Signer, r proof.Readings) ([]byte, error) {
	h := proof.Header{Seq: 1, Prev: proof.GenesisPrev, ObservedAt: time.Now(), AgentVersion: agent.Version,
		Schedule: proof.Schedule{IntervalS: uint16(agent.DefaultInterval / time.Second)}}
	var err error
	if h.Salt, err = proof.NewSalt(); err != nil {
		return nil, err
	}
	salt2, err := proof.NewSalt()
	if err != nil {
		return nil, err
	}
	copy(h.Nonce[:], salt2[:])
	payload, err := proof.BuildStatement(s.Public(), h, agent.SensorHealth(), r)
	if err != nil {
		return nil, err
	}
	if _, err := proof.ValidateStatement(payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func cmdKeygen(dir string, stdout, stderr io.Writer) int {
	s, err := keystore.Generate(dir)
	if err != nil {
		fmt.Fprintln(stderr, "keygen:", err)
		return 1
	}
	fmt.Fprintf(stdout, "Created device key %s in %s\n", proof.DeviceID(s.Public()), keystore.Path(dir))
	fmt.Fprintf(stdout, "Evidence strength: %s key", s.Protection())
	if runtime.GOOS == "windows" {
		fmt.Fprintln(stdout, ", sealed with DPAPI (machine scope).")
	} else {
		fmt.Fprintln(stdout, ".\nDEV ONLY: on this OS the private key is an unencrypted 0600 file. Never use it on a customer machine.")
	}
	fmt.Fprintln(stdout, "Next: kovyr-agent enroll --print-pubkey")
	return 0
}

// enrollment is the line to paste into the receiver's devices file. The
// algorithm and key protection are what the SPEC 6.3 attester enrollment
// record will carry once enrollment is built.
type enrollment struct {
	DeviceID      string `json:"device_id"`
	PublicKey     string `json:"public_key"`
	KeyID         string `json:"keyid,omitempty"`
	Alg           string `json:"alg,omitempty"`
	KeyProtection string `json:"key_protection,omitempty"`
}

func cmdEnroll(dir string, stdout, stderr io.Writer) int {
	s, err := keystore.Load(dir)
	if err != nil {
		fmt.Fprintln(stderr, "enroll:", err)
		return 1
	}
	e := enrollment{DeviceID: proof.DeviceID(s.Public()), PublicKey: s.Public().Base64(), KeyID: s.Public().KeyID(),
		Alg: proof.AlgES256, KeyProtection: s.Protection().String()}
	b, _ := json.MarshalIndent(e, "", "  ")
	fmt.Fprintln(stdout, string(b))
	fmt.Fprintln(stderr, "Enrollment is a stub in v0: add {\"device_id\", \"public_key\"} (and a \"label\" if you like) to the receiver's devices file.")
	return 0
}

func cmdRun(dir, server string, interval time.Duration, insecure, once bool, stderr io.Writer) int {
	logger := log.New(stderr, "kovyr-agent: ", log.LstdFlags)
	client, err := agent.NewHTTPClient(server, insecure)
	if err != nil {
		logger.Print(err)
		return 2
	}
	signer, err := keystore.Load(dir)
	if err != nil {
		logger.Print(err)
		return 1
	}
	a, err := agent.New(agent.Config{Dir: dir, Interval: interval, Logf: logger.Printf}, signer, checks.NewRunner(systemProbes()), client)
	if err != nil {
		logger.Print(err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if once {
		st, err := a.Beat(ctx)
		if err != nil {
			logger.Print(err)
		} else {
			logger.Printf("signed statement seq %d", st.Seq)
		}
		if ferr := a.Flush(ctx); ferr != nil {
			logger.Printf("send failed: %v (%d queued)", ferr, a.QueueLen())
			return 1
		}
		if err != nil {
			return 1
		}
		logger.Printf("delivered; chain head seq %d", a.State().Seq)
		return 0
	}
	logger.Printf("device %s reporting to %s every %v (read-only; accepts no commands)", proof.DeviceID(signer.Public()), server, interval)
	if err := a.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		logger.Print(err)
		return 1
	}
	return 0
}
