package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
)

// drive runs the control handler with fake Service Control Manager
// channels.
func drive(t *testing.T, main func(ctx context.Context) error) (chan<- svc.ChangeRequest, <-chan svc.Status, <-chan [2]uint32) {
	t.Helper()
	r := make(chan svc.ChangeRequest)
	s := make(chan svc.Status, 16)
	out := make(chan [2]uint32, 1)
	h := &handler{main: main, logf: t.Logf, grace: StopGrace}
	go func() {
		specific, code := h.Execute(nil, r, s)
		b := uint32(0)
		if specific {
			b = 1
		}
		out <- [2]uint32{b, code}
	}()
	return r, s, out
}

func waitState(t *testing.T, s <-chan svc.Status, want svc.State) svc.Status {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case st := <-s:
			if st.State == want {
				return st
			}
		case <-timeout:
			t.Fatalf("never reached state %d", want)
		}
	}
}

func TestStopEndsTheLoopAndAnswersQuickly(t *testing.T) {
	stopped := make(chan struct{})
	r, s, out := drive(t, func(ctx context.Context) error {
		<-ctx.Done()
		close(stopped)
		return ctx.Err()
	})
	run := waitState(t, s, svc.Running)
	if run.Accepts != svc.AcceptStop|svc.AcceptShutdown {
		t.Fatalf("accepts %v; only stop and shutdown", run.Accepts)
	}
	r <- svc.ChangeRequest{Cmd: svc.Interrogate, CurrentStatus: run}
	if st := <-s; st.State != svc.Running {
		t.Fatalf("interrogate answered %v", st.State)
	}
	t0 := time.Now()
	r <- svc.ChangeRequest{Cmd: svc.Stop}
	waitState(t, s, svc.StopPending)
	res := <-out
	if res != [2]uint32{0, 0} {
		t.Fatalf("clean stop returned %v", res)
	}
	select {
	case <-stopped:
	default:
		t.Fatal("the heartbeat loop was not told to stop")
	}
	if d := time.Since(t0); d > time.Second {
		t.Fatalf("stop took %v", d)
	}
}

// A heartbeat stuck in a slow WMI query must not hold up a shutdown past
// the grace period.
func TestShutdownDoesNotWaitForAStuckHeartbeat(t *testing.T) {
	r, s, out := drive(t, func(ctx context.Context) error {
		select {} // ignores ctx, like a check stuck in WMI
	})
	waitState(t, s, svc.Running)
	t0 := time.Now()
	r <- svc.ChangeRequest{Cmd: svc.Shutdown}
	st := waitState(t, s, svc.StopPending)
	if st.WaitHint == 0 {
		t.Error("stop pending without a wait hint")
	}
	<-out
	if d := time.Since(t0); d < StopGrace || d > StopGrace+time.Second {
		t.Fatalf("shutdown took %v, want about %v", d, StopGrace)
	}
}

// When the agent fails on its own (no key, bad settings) the service
// exits with an error code, so Windows' recovery actions restart it.
func TestAgentFailureIsAServiceFailure(t *testing.T) {
	_, s, out := drive(t, func(ctx context.Context) error { return errors.New("no device key") })
	waitState(t, s, svc.Running)
	res := <-out
	if res != [2]uint32{1, exitAgentFailed} {
		t.Fatalf("failure returned %v", res)
	}
}

func TestOtherControlsAreIgnored(t *testing.T) {
	r, s, out := drive(t, func(ctx context.Context) error { <-ctx.Done(); return nil })
	run := waitState(t, s, svc.Running)
	r <- svc.ChangeRequest{Cmd: svc.Pause, CurrentStatus: run}
	r <- svc.ChangeRequest{Cmd: svc.ParamChange, CurrentStatus: run}
	r <- svc.ChangeRequest{Cmd: svc.Stop}
	if res := <-out; res != [2]uint32{0, 0} {
		t.Fatalf("returned %v", res)
	}
}

func TestQueryWithoutTheServiceInstalled(t *testing.T) {
	if _, err := Query(); err != nil && !errors.Is(err, ErrNotInstalled) {
		t.Logf("query: %v", err) // installed by the CI service test, or not; either way no panic
	}
	if len(ProtectedRoots()) == 0 {
		t.Fatal("no Program Files folder found")
	}
}
