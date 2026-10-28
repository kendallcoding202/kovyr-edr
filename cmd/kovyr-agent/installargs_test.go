package main

import (
	"encoding/xml"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/kendallcoding202/kovyr-edr/internal/config"
)

func TestCheckInstallServer(t *testing.T) {
	good := []struct {
		url string
		dev bool
	}{
		{"https://agent.kovyr.com/api/agent", false},
		{"https://agent.example:8443/api/agent/", false},
		{"https://agent.example", false},
		{"https://203.0.113.5/x", false},
		{"https://[2001:db8::1]:443/a", false},
		{"http://127.0.0.1:18790", true},
		{"http://localhost:8787/api", true},
		{"http://[::1]:1", true},
	}
	for _, g := range good {
		if err := checkInstallServer(g.url, g.dev); err != nil {
			t.Errorf("%q (dev %v): %v", g.url, g.dev, err)
		}
	}
	bad := []struct {
		url string
		dev bool
	}{
		{"", false},
		// What an MSI SERVER property could carry to break out of its quotes.
		{`https://x" --no-user-folders --watch "C:\`, false},
		{`https://x --no-user-folders`, false},
		{"https://x\t--watch", false},
		{"https://x\n--watch", false},
		{`https://agent.example\`, false},
		{`https://agent.example/a"b`, false},
		{`https://agent.example/api'`, false},
		{"https://agent.example/a`b", false},
		{"https://agent.example/a|b", false},
		// Not a plain address.
		{"https://user@agent.example", false},
		{"https://user:pw@agent.example", false},
		{"https://agent.example/?a=1", false},
		{"https://agent.example/?", false},
		{"https://agent.example/#x", false},
		{"https://agent.example/%2e%2e/x", false},
		{"https://agent.example/../x", false},
		{"https://agent.example/./x", false},
		{"https://agent.example//x", false},
		{"https://agent.example/a;b", false},
		{"https://agent.example:", false},
		{"https://agent.example:0", false},
		{"https://agent.example:080", false},
		{"https://agent.example:99999", false},
		{"https://agent.example:80x", false},
		{"https://-bad.example", false},
		{"https://agent_example.com", false},
		{"https://[203.0.113.5]", false},
		{"https://[fe80::1%25eth0]", false},
		{"https://", false},
		{"https:///path", false},
		{"HTTPS://agent.example", false},
		{"ftp://agent.example", false},
		{"agent.example", false},
		{"https://agent.example/" + strings.Repeat("a", maxServerLen), false},
		{"https://agent.ex\u00e4mple", false},
		// Plain http: only with --dev-insecure, only to this computer.
		{"http://127.0.0.1:8787", false},
		{"http://agent.example", true},
		{"http://10.0.0.5", true},
	}
	for _, b := range bad {
		err := checkInstallServer(b.url, b.dev)
		switch {
		case err == nil:
			t.Errorf("%q (dev %v) was accepted", b.url, b.dev)
		case !strings.Contains(err.Error(), "--server must be a plain https:// address"):
			t.Errorf("%q: unclear error %v", b.url, err)
		case strings.ContainsAny(b.url, "\"\\ \t\n") && !strings.Contains(err.Error(), "is not allowed"):
			// What could split or end a quoted command-line argument is
			// named as such, whatever else is wrong with the value.
			t.Errorf("%q: error does not name the character: %v", b.url, err)
		}
	}
}

// refusedBeforeWriting runs an install and checks that it was refused with
// exit 2 before anything was written or the service manager was called.
func refusedBeforeWriting(t *testing.T, f *fakeSCM, dir string, args []string, want string) {
	t.Helper()
	code, _, errs := runCLI(t, args...)
	if code != 2 || !strings.Contains(errs, want) {
		t.Errorf("%q: exit %d, want 2 with %q:\n%s", args, code, want, errs)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("%q: the state directory was created (%v)", args, err)
	}
	if len(f.calls) != 0 {
		t.Errorf("%q: the service manager was called: %v", args, f.calls)
	}
}

// HOST-2: injection-style values never become extra settings. Each is
// refused before the install writes anything.
func TestInstallRefusesInjectedArguments(t *testing.T) {
	f := useFakeSCM(t)
	dir := filepath.Join(t.TempDir(), "Kovyr")
	base := []string{"service", "install", "--state-dir", dir}
	for _, c := range []struct {
		args []string
		want string
	}{
		// SERVER="https://x" --no-user-folders --watch "C:\" as the old MSI
		// command line could split it: the value itself is clean, the rest
		// arrives as one argument with spaces.
		{[]string{"--server", `https://x" --no-user-folders --watch "C:\`, "--create-key"}, "character"},
		{[]string{"--server", "https://agent.example --watch C:\\Users", "--create-key"}, "character"},
		// DEV_INSECURE="0 --state-dir C:\Users\Public\x" in --dev-insecure=[DEV_INSECURE].
		{[]string{"--server", "https://agent.example", `--dev-insecure=0 --state-dir C:\Users\Public\x`, "--create-key"}, "must be 0, 1, true or false"},
		{[]string{"--server", "https://agent.example", "--dev-insecure=yes", "--create-key"}, "must be 0, 1, true or false"},
		{[]string{"--server", "https://agent.example", "--dev-insecure=TRUE", "--create-key"}, "must be 0, 1, true or false"},
		{[]string{"--server", "https://agent.example", "--dev-insecure=t", "--create-key"}, "must be 0, 1, true or false"},
		{[]string{"--server", "https://agent.example", "--dev-insecure=", "--create-key"}, "must be 0, 1, true or false"},
		// A second value, which flag parsing would otherwise let win.
		{[]string{"--server", "https://agent.example", "--server", "https://evil.example", "--create-key"}, "more than once"},
		{[]string{"--server", "https://agent.example", "--dev-insecure", "--dev-insecure=0", "--create-key"}, "more than once"},
		{[]string{"--server", "https://agent.example", "--state-dir", `C:\Users\Public\x`, "--create-key"}, "more than once"},
		// Anything after the flags: flag parsing stops at the first
		// non-flag, so "--watch" here would silently be ignored.
		{[]string{"--server", "https://agent.example", "junk", "--watch", `C:\`, "--create-key"}, `unexpected argument "junk"`},
		{[]string{"--server", "https://agent.example", "--create-key", "--", "--no-user-folders"}, "unexpected argument"},
	} {
		refusedBeforeWriting(t, f, dir, append(append([]string{}, base...), c.args...), c.want)
	}
}

func TestDevInsecureTakesOnlyPlainValues(t *testing.T) {
	for _, c := range []struct {
		flag string
		want bool
	}{
		{"--dev-insecure", true}, {"--dev-insecure=1", true}, {"--dev-insecure=true", true},
		{"--dev-insecure=0", false}, {"--dev-insecure=false", false},
	} {
		f := useFakeSCM(t)
		dir := filepath.Join(t.TempDir(), "Kovyr")
		code, out, errs := runCLI(t, "service", "install", "--server", "http://127.0.0.1:18790", c.flag, "--state-dir", dir, "--create-key")
		if !c.want {
			if code != 2 || !strings.Contains(errs, "plain http is allowed only with --dev-insecure") {
				t.Errorf("%s with plain http: exit %d %q", c.flag, code, errs)
			}
			continue
		}
		skipWithoutKeyStore(t, errs)
		if code != 0 {
			t.Fatalf("%s: exit %d\n%s%s", c.flag, code, out, errs)
		}
		if s, err := config.Read(dir); err != nil || !s.DevInsecure || len(f.calls) != 1 {
			t.Errorf("%s: settings %+v (%v), calls %v", c.flag, s, err, f.calls)
		}
	}
}

// wix is the part of installer/kovyr-agent.wxs these tests read.
type wix struct {
	Product struct {
		Properties []struct {
			ID    string `xml:"Id,attr"`
			Value string `xml:"Value,attr"`
		} `xml:"Property"`
		Conditions []struct {
			Message string `xml:"Message,attr"`
			Text    string `xml:",chardata"`
		} `xml:"Condition"`
		CustomActions []struct {
			ID         string `xml:"Id,attr"`
			ExeCommand string `xml:"ExeCommand,attr"`
			Execute    string `xml:"Execute,attr"`
		} `xml:"CustomAction"`
		Sequence struct {
			Custom []struct {
				Action    string `xml:"Action,attr"`
				Condition string `xml:",chardata"`
			} `xml:"Custom"`
		} `xml:"InstallExecuteSequence"`
	} `xml:"Product"`
}

func readWix(t *testing.T) wix {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "installer", "kovyr-agent.wxs"))
	if err != nil {
		t.Fatal(err)
	}
	// $(var.X) preprocessor variables are fine for encoding/xml.
	var w wix
	if err := xml.Unmarshal(b, &w); err != nil {
		t.Fatal(err)
	}
	return w
}

// splitCommandLine is how the agent's os.Args are made from its Windows
// command line: commandLineToArgv, readNextArg and appendBSBytes copied
// from Go's os/exec_windows.go (Go 1.24), so it runs on any OS.
func splitCommandLine(cmd string) []string {
	var args []string
	for len(cmd) > 0 {
		if cmd[0] == ' ' || cmd[0] == '\t' {
			cmd = cmd[1:]
			continue
		}
		var arg []byte
		arg, cmd = readNextArg(cmd)
		args = append(args, string(arg))
	}
	return args
}

func readNextArg(cmd string) (arg []byte, rest string) {
	var b []byte
	var inquote bool
	var nslash int
	for ; len(cmd) > 0; cmd = cmd[1:] {
		c := cmd[0]
		switch c {
		case ' ', '\t':
			if !inquote {
				return appendBSBytes(b, nslash), cmd[1:]
			}
		case '"':
			b = appendBSBytes(b, nslash/2)
			if nslash%2 == 0 {
				if inquote && len(cmd) > 1 && cmd[1] == '"' {
					b = append(b, c)
					cmd = cmd[1:]
				}
				inquote = !inquote
			} else {
				b = append(b, c)
			}
			nslash = 0
			continue
		case '\\':
			nslash++
			continue
		}
		b = appendBSBytes(b, nslash)
		nslash = 0
		b = append(b, c)
	}
	return appendBSBytes(b, nslash), ""
}

func appendBSBytes(b []byte, n int) []byte {
	for ; n > 0; n-- {
		b = append(b, '\\')
	}
	return b
}

// splitCases are command lines and how Windows splits them
// (msi_windows_test.go checks them against CommandLineToArgvW).
var splitCases = map[string][]string{
	`a b c`:             {"a", "b", "c"},
	`"a b" c`:           {"a b", "c"},
	`a\\\"b c`:          {`a\"b`, "c"},
	`a\\"b c" d`:        {`a\b c`, "d"},
	`"a\\\\" b`:         {`a\\`, "b"},
	`"a""b" c`:          {`a"b c`},
	`--server "x\" --w`: {"--server", `x" --w`},
}

func TestSplitCommandLine(t *testing.T) {
	for cmd, want := range splitCases {
		if got := splitCommandLine(cmd); !slices.Equal(got, want) {
			t.Errorf("%s: %q, want %q", cmd, got, want)
		}
	}
}

// HOST-2, the installer side: the SYSTEM install step puts only SERVER
// into its command line, inside quotes, never DEV_INSECURE; a launch
// condition refuses a SERVER with a quote or a backslash, the only
// characters that can end those quotes. For any SERVER that passes it,
// the agent receives exactly the intended flags, with SERVER as one
// value, and refuses the value if it is not a plain address.
func TestMSIInstallCommandGivesTheAgentOnlyItsOwnFlags(t *testing.T) {
	w := readWix(t)
	var quote string
	for _, p := range w.Product.Properties {
		if p.ID == "KOVYR_QUOTE" {
			quote = p.Value
		}
	}
	if quote != `"` {
		t.Fatalf("KOVYR_QUOTE is %q, want a double quote", quote)
	}
	guarded := false
	for _, c := range w.Product.Conditions {
		text := strings.Join(strings.Fields(c.Text), " ")
		if strings.HasPrefix(text, "Installed OR ") && strings.Contains(text, `NOT (SERVER >< KOVYR_QUOTE)`) &&
			strings.Contains(text, `NOT (SERVER >< "\")`) && strings.Contains(text, `SERVER << "https://"`) {
			guarded = true
		}
	}
	if !guarded {
		t.Fatal("no launch condition refuses a SERVER with a quote or a backslash")
	}
	devGuarded := false
	for _, c := range w.Product.Conditions {
		if strings.Join(strings.Fields(c.Text), " ") == `Installed OR DEV_INSECURE = "0" OR DEV_INSECURE = "1"` {
			devGuarded = true
		}
	}
	if !devGuarded {
		t.Fatal("no launch condition limits DEV_INSECURE to 0 or 1")
	}

	props := regexp.MustCompile(`\[[^\]]*\]`)
	var installs []string
	for _, ca := range w.Product.CustomActions {
		if !strings.HasPrefix(ca.ExeCommand, "service install") {
			continue
		}
		installs = append(installs, ca.ID)
		if got := props.FindAllString(ca.ExeCommand, -1); !slices.Equal(got, []string{"[SERVER]"}) {
			t.Errorf("%s puts %v into its command line, want only [SERVER]", ca.ID, got)
		}
		if !strings.Contains(ca.ExeCommand, `--server "[SERVER]" `) {
			t.Errorf("%s does not quote [SERVER]: %s", ca.ID, ca.ExeCommand)
		}
		wantDev := strings.Contains(ca.ExeCommand, "--dev-insecure")
		var cond string
		for _, c := range w.Product.Sequence.Custom {
			if c.Action == ca.ID {
				cond = strings.TrimSpace(c.Condition)
			}
		}
		if wantCond := map[bool]string{false: `NOT Installed AND DEV_INSECURE <> "1"`, true: `NOT Installed AND DEV_INSECURE = "1"`}[wantDev]; cond != wantCond {
			t.Errorf("%s runs on %q, want %q", ca.ID, cond, wantCond)
		}

		// Values that pass the launch condition: no quote, no backslash.
		for _, server := range []string{
			"https://agent.kovyr.com/api/agent",
			"https://x --no-user-folders --watch C:/Users/Public",
			"https://x --server https://evil.example --state-dir C:/x",
			"https://x\t--create-key=false",
			"https://x' --watch 'C:/",
			"https://x%22 --watch",
		} {
			if strings.Contains(server, quote) || strings.Contains(server, `\`) {
				t.Fatalf("test value %q would not pass the launch condition", server)
			}
			cmdline := `"C:\Program Files\Kovyr\kovyr-agent.exe" ` + strings.ReplaceAll(ca.ExeCommand, "[SERVER]", server)
			argv := splitCommandLine(cmdline)
			want := []string{`C:\Program Files\Kovyr\kovyr-agent.exe`, "service", "install", "--server", server}
			if wantDev {
				want = append(want, "--dev-insecure")
			}
			want = append(want, "--create-key", "--start")
			if !slices.Equal(argv, want) {
				t.Errorf("%s with SERVER=%q gives %q, want %q", ca.ID, server, argv, want)
				continue
			}
			f := useFakeSCM(t)
			dir := filepath.Join(t.TempDir(), "Kovyr")
			args := append(append([]string{}, argv[1:]...), "--state-dir", dir)
			code, out, errs := runCLI(t, args...)
			if server == "https://agent.kovyr.com/api/agent" {
				skipWithoutKeyStore(t, errs)
				s, err := config.Read(dir)
				if code != 0 || err != nil || s.Server != server || s.DevInsecure != wantDev || !s.Tripwire.UserFolders ||
					len(s.Tripwire.Folders) != 0 || s.IntervalS != 900 {
					t.Errorf("%s: exit %d, settings %+v (%v)\n%s%s", ca.ID, code, s, err, out, errs)
				}
				continue
			}
			refusedBeforeWriting(t, f, dir, args, "--server must be a plain https:// address")
		}
	}
	if !slices.Equal(installs, []string{"KovyrInstallService", "KovyrInstallServiceDevInsecure"}) {
		t.Fatalf("install custom actions %v", installs)
	}
}
