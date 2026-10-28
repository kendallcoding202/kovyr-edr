package agent

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The agent never runs anything it is sent (CLAUDE.md section 2). Nothing
// the agent binary is built from may even import a way to start a process
// or load code. The test walks every in-module package the agent command
// reaches (all build tags, so Windows files too), starting from the
// command itself, so a new package or library is covered without editing
// a list. It sees imports only: internal/tools/binscan also checks the
// built binary for any function that starts a process, which catches a
// direct CreateProcess call and launchers inside libraries.

const module = "github.com/kendallcoding202/kovyr-edr/"

// root is the repository root, relative to this package.
const root = "../.."

var execImports = map[string]bool{
	"os/exec": true, "plugin": true, "net/rpc": true, "net/rpc/jsonrpc": true,
}

// agentPackages returns the agent command and every in-module package it
// imports, directly or not, as directories relative to root.
func agentPackages(t *testing.T) map[string]bool {
	t.Helper()
	seen := map[string]bool{}
	queue := []string{"cmd/kovyr-agent"}
	for len(queue) > 0 {
		pkg := queue[0]
		queue = queue[1:]
		if seen[pkg] {
			continue
		}
		seen[pkg] = true
		matches, _ := filepath.Glob(filepath.Join(root, pkg, "*.go"))
		if len(matches) == 0 {
			t.Fatalf("no Go files for %s", pkg)
		}
		for _, m := range matches {
			if strings.HasSuffix(m, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(token.NewFileSet(), m, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range f.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				if strings.HasPrefix(p, module) {
					queue = append(queue, strings.TrimPrefix(p, module))
				}
			}
		}
	}
	return seen
}

func TestAgentCannotExecuteAnything(t *testing.T) {
	pkgs := agentPackages(t)
	for _, want := range []string{"cmd/kovyr-agent", "internal/agent", "internal/checks", "internal/keystore",
		"internal/proof", "proof/canon", "proof/sigs", "proof/dsse", "proof/posture"} {
		if !pkgs[want] {
			t.Errorf("%s is not among the agent's packages; the walk is broken", want)
		}
	}
	files := 0
	for pkg := range pkgs {
		// Test files too: nothing in these directories should reach for a
		// process launcher.
		matches, _ := filepath.Glob(filepath.Join(root, pkg, "*.go"))
		for _, m := range matches {
			f, err := parser.ParseFile(token.NewFileSet(), m, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			files++
			for _, imp := range f.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				if execImports[p] {
					t.Errorf("%s imports %q; the agent must not be able to run commands", m, p)
				}
			}
		}
	}
	if files < 40 {
		t.Fatalf("scanned only %d files; the test is not looking in the right place", files)
	}
}
