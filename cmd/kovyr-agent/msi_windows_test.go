package main

import (
	"slices"
	"testing"

	"golang.org/x/sys/windows"
)

// The copy of Go's splitter that the MSI command-line test uses splits
// like Windows' own CommandLineToArgvW.
func TestSplitCommandLineIsWindows(t *testing.T) {
	cmds := []string{`"C:\Program Files\Kovyr\kovyr-agent.exe" service install --server "https://x --watch C:/x" --create-key --start`}
	for c := range splitCases {
		cmds = append(cmds, "kovyr-agent.exe "+c)
	}
	for _, c := range cmds {
		want, err := windows.DecomposeCommandLine(c)
		if err != nil {
			t.Fatal(err)
		}
		if got := splitCommandLine(c); !slices.Equal(got, want) {
			t.Errorf("%s: %q, Windows %q", c, got, want)
		}
	}
}
