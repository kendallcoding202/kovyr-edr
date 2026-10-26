package agent

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"testing"
)

// The agent never runs anything it is sent (CLAUDE.md section 2). These
// packages are everything the agent binary is built from; none may even
// import a way to start a process or load code.
var agentPackages = []string{".", "../checks", "../keystore", "../proof", "../fsutil", "../../cmd/kovyr-agent"}

var execImports = map[string]bool{
	"os/exec": true, "plugin": true, "net/rpc": true, "net/rpc/jsonrpc": true,
}

func TestAgentCannotExecuteAnything(t *testing.T) {
	files := 0
	for _, dir := range agentPackages {
		matches, _ := filepath.Glob(filepath.Join(dir, "*.go"))
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
	if files < 20 {
		t.Fatalf("scanned only %d files; the test is not looking in the right place", files)
	}
}
