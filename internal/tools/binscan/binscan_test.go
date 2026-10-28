package binscan

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The agent never starts a process (CLAUDE.md section 2: read-only, no
// remote shell). internal/agent's structure test bans the imports that
// could, but only in this module's packages: a direct
// golang.org/x/sys/windows.CreateProcess or ShellExecute call needs no
// banned import, and a library could import os/exec itself (R3-12). So
// this test builds the binary the MSI ships and looks at what is actually
// linked into it: the Go linker drops every function nothing can reach,
// so a launcher's symbol is there only if the agent can call it.

// root is the repository root, relative to this package.
const root = "../../.."

// launcherFuncs match the last part of a function symbol's name (after
// the package path and any receiver), without regard to case.
var launcherFuncs = regexp.MustCompile(`(?i)^(` +
	`createprocess\w*|` + // CreateProcess, CreateProcessAsUser, CreateProcessWithLogonW, ...
	`shellexecute\w*|` + // ShellExecute, ShellExecuteEx
	`winexec|` +
	`createremotethread\w*|` +
	`ntcreateuserprocess|ntcreateprocess\w*|rtlcreateuserprocess|` +
	`startprocess|forkexec\w*` + // os.StartProcess, os.startProcess, syscall.StartProcess
	`)$`)

// launcherPackages may not have a single function in the binary.
var launcherPackages = []string{"os/exec.", "plugin.", "net/rpc."}

// nmLine is one line of `go tool nm`: address (absent for undefined
// symbols), type letter, name (which may hold spaces).
var nmLine = regexp.MustCompile(`^\s*(?:[0-9a-fA-F]+\s+)?([A-Za-z])\s+(.+)$`)

func goTool(t *testing.T) string {
	t.Helper()
	// go test puts its own GOROOT/bin first in PATH.
	g, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("no go command: %v", err)
	}
	return g
}

func run(t *testing.T, env []string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.Output()
	if err != nil {
		var stderr string
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, stderr)
	}
	return string(out)
}

var windowsBuild = []string{"GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0"}

// launchers returns every function symbol in nm output that could start
// a process, and the number of function symbols seen.
func launchers(nm string) (found []string, funcs int) {
	for _, l := range strings.Split(nm, "\n") {
		m := nmLine.FindStringSubmatch(strings.TrimRight(l, "\r"))
		if m == nil || (m[1] != "T" && m[1] != "t") {
			continue
		}
		funcs++
		name := m[2]
		last := name[strings.LastIndex(name, ".")+1:]
		bad := launcherFuncs.MatchString(last)
		for _, p := range launcherPackages {
			bad = bad || strings.HasPrefix(name, p)
		}
		if bad {
			found = append(found, name)
		}
	}
	return found, funcs
}

func TestLauncherPatterns(t *testing.T) {
	nm := strings.Join([]string{
		"  5ea620 T golang.org/x/sys/windows.CreateProcess",
		"  5ea620 T golang.org/x/sys/windows.CreateProcessAsUser",
		"  5ea620 T golang.org/x/sys/windows.ShellExecute",
		"  4a0000 T syscall.StartProcess",
		"  4a0000 t os.startProcess",
		"  4a0000 T os/exec.(*Cmd).Start",
		"  4a0000 T github.com/x/y.WinExec",
		"  4a0000 T github.com/x/y.(*T).CreateRemoteThread",
		// Not launchers.
		"  5ea620 T golang.org/x/sys/windows.CreateFile",
		"  5ea620 T golang.org/x/sys/windows.CreateIoCompletionPort",
		"  ac6ab8 D golang.org/x/sys/windows.procCreateProcessW",
		"  45ed20 T runtime.printcreatedby",
		"  45ed20 T main.main",
		"         U _cgo_init",
	}, "\r\n")
	found, funcs := launchers(nm)
	if len(found) != 8 || funcs != 12 {
		t.Fatalf("found %d of 8 launchers in %d of 12 functions: %q", len(found), funcs, found)
	}
}

// R3-12: the agent binary as shipped holds no function that starts a
// process, and imports no package that could.
func TestAgentBinaryCannotStartAProcess(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the agent")
	}
	gobin := goTool(t)
	exe := filepath.Join(t.TempDir(), "kovyr-agent.exe")
	// As installer/build-msi.sh builds it (no -s: the symbols must stay).
	run(t, windowsBuild, gobin, "build", "-trimpath", "-o", exe, "./cmd/kovyr-agent")
	nm := run(t, nil, gobin, "tool", "nm", exe)
	found, funcs := launchers(nm)
	// The scan must see the binary's functions, or a clean result means
	// nothing.
	if funcs < 1000 {
		t.Fatalf("go tool nm listed only %d functions", funcs)
	}
	for _, want := range []string{" T main.main", " T golang.org/x/sys/windows.CreateFile"} {
		if !strings.Contains(nm, want) {
			t.Fatalf("the symbol table lacks %q; the scan is not looking at the agent", want)
		}
	}
	for _, f := range found {
		t.Errorf("the agent binary contains %s: the agent must not be able to start a process", f)
	}

	// The whole dependency closure, libraries included, not only this
	// module's packages.
	for _, p := range strings.Fields(run(t, windowsBuild, gobin, "list", "-deps", "./cmd/kovyr-agent")) {
		for _, banned := range []string{"os/exec", "plugin", "net/rpc", "net/rpc/jsonrpc"} {
			if p == banned {
				t.Errorf("the agent depends on %s", p)
			}
		}
	}
}
