package main

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// The MSI runs `service install` as SYSTEM with --server taken from a
// public property (installer/kovyr-agent.wxs). The installer refuses a
// SERVER that could break out of its quotes, and these checks refuse
// anything else odd in what reaches the agent: a value with spaces,
// quotes or a second address in it, a flag given twice, or a stray
// argument.

// onceString is a string flag that may be given only once, so a second
// --server cannot quietly replace the first.
type onceString struct {
	v   string
	set bool
}

func (s *onceString) String() string {
	if s == nil {
		return ""
	}
	return s.v
}

func (s *onceString) Set(v string) error {
	if s.set {
		return errors.New("given more than once")
	}
	s.v, s.set = v, true
	return nil
}

// strictBool is a boolean flag that accepts only 0, 1, true and false
// (strconv.ParseBool also takes t, F, TRUE, ...), and only once. Given
// alone (--dev-insecure) it is true.
type strictBool struct {
	v   bool
	set bool
}

func (b *strictBool) IsBoolFlag() bool { return true }

func (b *strictBool) String() string {
	if b != nil && b.v {
		return "true"
	}
	return "false"
}

func (b *strictBool) Set(s string) error {
	if b.set {
		return errors.New("given more than once")
	}
	switch s {
	case "1", "true":
		b.v = true
	case "0", "false":
		b.v = false
	default:
		return errors.New("must be 0, 1, true or false")
	}
	b.set = true
	return nil
}

// maxServerLen is generous for a base URL.
const maxServerLen = 512

var (
	dnsLabel   = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	serverPath = regexp.MustCompile(`^(/[A-Za-z0-9._~-]+)*/?$`)
)

// checkInstallServer is the strict check of --server at install: a plain
// https:// URL (http:// only with --dev-insecure, and only to this
// computer) with a host name or IP address, an optional port and an
// optional path of plain segments. No credentials, query, fragment,
// percent-escapes, spaces, quotes or backslashes.
func checkInstallServer(raw string, devInsecure bool) error {
	bad := func(why string) error {
		return fmt.Errorf("--server must be a plain https:// address such as https://agent.kovyr.com/api/agent: %s", why)
	}
	if raw == "" {
		return bad("it is empty")
	}
	if len(raw) > maxServerLen {
		return bad(fmt.Sprintf("it is longer than %d characters", maxServerLen))
	}
	for i := 0; i < len(raw); i++ {
		if c := raw[i]; c <= ' ' || c >= 0x7f || strings.IndexByte("\"'\\`<>^|{}%?#@", c) >= 0 {
			return bad(fmt.Sprintf("character %q is not allowed", c))
		}
	}
	switch {
	case strings.HasPrefix(raw, "https://"):
	case strings.HasPrefix(raw, "http://"):
		if !devInsecure {
			return bad("plain http is allowed only with --dev-insecure, to this computer")
		}
	default:
		return bad("it must start with https://")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return bad("it is not a URL")
	}
	host, port := u.Hostname(), u.Port()
	if host == "" || strings.HasSuffix(u.Host, ":") {
		return bad("it needs a host name")
	}
	if strings.HasPrefix(u.Host, "[") {
		if ip := net.ParseIP(host); ip == nil || ip.To4() != nil {
			return bad("only an IPv6 address goes in brackets")
		}
	} else if net.ParseIP(host) == nil && !dnsName(host) {
		return bad("the host is not a plain host name")
	}
	if port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 || port[0] == '0' {
			return bad("the port must be a number from 1 to 65535")
		}
	}
	if !serverPath.MatchString(u.Path) || u.RawPath != "" {
		return bad("the path may hold only letters, digits and . _ ~ - between slashes")
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == "." || seg == ".." {
			return bad("the path may not hold . or .. segments")
		}
	}
	if u.Scheme == "http" && !isLoopbackHost(host) {
		return bad("plain http is allowed only to localhost, 127.0.0.1 or ::1")
	}
	return nil
}

func dnsName(h string) bool {
	if len(h) > 253 {
		return false
	}
	for _, l := range strings.Split(h, ".") {
		if !dnsLabel.MatchString(l) {
			return false
		}
	}
	return true
}

func isLoopbackHost(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}
