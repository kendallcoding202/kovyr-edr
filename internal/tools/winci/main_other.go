//go:build !windows

// Command winci runs Windows-only CI checks; see main_windows.go.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "winci runs only on Windows")
	os.Exit(2)
}
