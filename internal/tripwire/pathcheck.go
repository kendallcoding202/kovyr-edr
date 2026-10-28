package tripwire

import (
	"errors"
	"strings"
)

// A watch folder is opened without following a junction or link
// (watch_windows.go), and the agent watches it only if what it opened is
// the folder it meant: a junction swapped in for Documents, or for any
// folder on the way to it, could otherwise steer the SYSTEM service to
// watch C:\ or C:\Windows. These are the checks, kept apart from the
// Windows calls so they are tested everywhere.

// The errors name the reason in the log (by folder number, never path).
var (
	errNotAFolder = errors.New("not a folder")
	errLink       = errors.New("a junction or link")
	errElsewhere  = errors.New("its path leads somewhere else")
)

const (
	fileAttributeDirectory    = 0x10
	fileAttributeReparsePoint = 0x400
	// reparseTagNameSurrogate marks reparse points that redirect a path
	// to another (junctions, mount points, symbolic links). Others, such
	// as OneDrive's cloud placeholders, do not, and those folders are
	// watched as before.
	reparseTagNameSurrogate = 0x20000000
)

// checkOpened judges the attributes and reparse tag of what was opened
// with FILE_FLAG_OPEN_REPARSE_POINT: it must be a folder, and not one that
// redirects to another.
func checkOpened(attrs, tag uint32) error {
	if attrs&fileAttributeDirectory == 0 {
		return errNotAFolder
	}
	if attrs&fileAttributeReparsePoint != 0 && tag&reparseTagNameSurrogate != 0 {
		return errLink
	}
	return nil
}

// samePath reports whether final, the path Windows gives for the opened
// handle (GetFinalPathNameByHandle), is the folder meant: want with its
// short (8.3) names made long (GetLongPathName). They differ when a
// junction or link on the way was followed. Windows compares names
// without regard to case.
func samePath(want, final string) bool {
	return strings.EqualFold(normPath(want), normPath(final))
}

// normPath drops the \\?\ prefix Windows puts on final paths, writes
// \\?\UNC\server\share as \\server\share, uses backslashes and drops
// trailing ones (both sides lose them, so C:\ stays comparable).
func normPath(p string) string {
	switch {
	case strings.HasPrefix(p, `\\?\UNC\`):
		p = `\\` + p[len(`\\?\UNC\`):]
	case strings.HasPrefix(p, `\\?\`):
		p = p[len(`\\?\`):]
	}
	p = strings.ReplaceAll(p, "/", `\`)
	return strings.TrimRight(p, `\`)
}
