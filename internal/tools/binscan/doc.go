// Package binscan holds only a test: it builds the agent binary as it
// ships (windows/amd64) and checks its symbol table for any way to start
// a process. It lives outside the agent's packages because it needs
// os/exec to run the go tool, which the agent's own packages may not
// import, not even in tests (internal/agent/structure_test.go).
package binscan
