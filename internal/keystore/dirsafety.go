package keystore

import (
	"errors"
	"fmt"
	"path/filepath"
)

// The state folder holds the device key, and the service runs as SYSTEM
// and trusts everything in it. On Windows a user without administrator
// rights can make C:\ProgramData\Kovyr before Kovyr is installed, and then
// owns it. So an existing folder is never trusted as it is: checkDir makes
// sure only SYSTEM and Administrators control it before anything in it is
// read or written. This file is the decision; keystore_windows.go reads
// and sets the real access lists through fsSecurity.

// ErrUnsafeDir means the state folder, or the device key in it, may have
// been readable or changeable by someone other than SYSTEM and
// Administrators. Kovyr does not use it, and never takes it over: an
// administrator deletes the folder and installs again.
var ErrUnsafeDir = errors.New("the Kovyr state folder is not safe to use")

type unsafeError struct{ msg string }

func (e *unsafeError) Error() string        { return e.msg }
func (e *unsafeError) Is(target error) bool { return target == ErrUnsafeDir }

// reinstall is the remedy every refusal names.
const reinstall = " Kovyr will not use it. An administrator should delete the folder %s and install Kovyr again; " +
	"the device then gets a new key, so enroll it again and revoke the old one."

func unsafeDir(dir, format string, a ...any) error {
	return &unsafeError{msg: fmt.Sprintf(format, a...) + fmt.Sprintf(reinstall, dir)}
}

// secInfo is what the key store needs to know about a file or folder:
// who owns it and who its access list lets in. It describes the object
// at the path itself, never the target of a junction or link there.
type secInfo struct {
	isDir bool
	// link: a junction, symbolic link or other reparse point that
	// redirects the path (a name surrogate).
	link bool
	// owner is the owner's SID, for messages; ownerOK means it is SYSTEM
	// or Administrators.
	owner   string
	ownerOK bool
	// noDACL: no access list at all, so everyone has full access.
	noDACL bool
	// protected: the access list does not inherit from the parent.
	protected bool
	// others are the SIDs, other than SYSTEM and Administrators, that an
	// entry other than a plain deny names (with any rights at all,
	// including entries only children inherit).
	others []string
}

// who names the owner in a message.
func (s secInfo) who() string {
	if s.owner == "" {
		return "an owner that cannot be read"
	}
	return s.owner
}

// onlyAdmins reports whether only SYSTEM and Administrators get in.
func (s secInfo) onlyAdmins() bool { return !s.noDACL && len(s.others) == 0 }

// fsSecurity reads and sets owners and access lists. Every method acts on
// the object at the path itself and never follows a junction or link.
type fsSecurity interface {
	// stat describes path; an error wraps os.ErrNotExist when it is not
	// there.
	stat(path string) (secInfo, error)
	// lockDown makes Administrators the owner and gives path a protected
	// access list: full control for SYSTEM and Administrators only
	// (inherited by everything inside, for a folder). It refuses a link.
	lockDown(path string) error
	// walk calls fn for every entry below dir, without following links.
	walk(dir string, fn func(path string) error) error
}

// maxEntries bounds the look inside a folder that has to be repaired. The
// agent keeps a few files, at most 500 queued statements and 10 logs.
const maxEntries = 4096

// checkDir makes sure only SYSTEM and Administrators control dir:
//
//   - a link, a file, or a folder someone else owns is refused (never
//     taken over: whoever made it may have read or planted things in it);
//   - a folder Administrators or SYSTEM own whose access list lets anyone
//     else in is repaired by applying the protected list again, unless
//     what is inside shows someone else may have used that access (an
//     entry they own, a link, or a device key they could read): a new
//     access list cannot undo that, so it is refused.
func checkDir(fsec fsSecurity, dir string) error {
	si, err := fsec.stat(dir)
	if err != nil {
		return err
	}
	if si.link || !si.isDir {
		return unsafeDir(dir, "%s is a link or a file, not a folder.", dir)
	}
	if !si.ownerOK {
		return unsafeDir(dir, "%s is owned by %s, not by SYSTEM or Administrators. Someone without administrator rights "+
			"may have made it before Kovyr was installed, and could then read or change what Kovyr keeps there.", dir, si.who())
	}
	if si.protected && si.onlyAdmins() {
		return nil
	}
	if err := checkContents(fsec, dir); err != nil {
		return err
	}
	if err := fsec.lockDown(dir); err != nil {
		return fmt.Errorf("restrict the access list of %s: %w", dir, err)
	}
	if si, err = fsec.stat(dir); err != nil {
		return err
	}
	if si.link || !si.ownerOK || !si.protected || !si.onlyAdmins() {
		return unsafeDir(dir, "the access list of %s could not be restricted to SYSTEM and Administrators.", dir)
	}
	return nil
}

// checkContents looks at everything inside a folder whose access list let
// others in, before it is repaired.
func checkContents(fsec fsSecurity, dir string) error {
	key := Path(dir)
	n := 0
	return fsec.walk(dir, func(p string) error {
		if n++; n > maxEntries {
			return unsafeDir(dir, "%s let others in and holds more than %d entries.", dir, maxEntries)
		}
		e, err := fsec.stat(p)
		if err != nil {
			return unsafeDir(dir, "%s let others in, and %s cannot be checked (%v).", dir, p, err)
		}
		if e.link || !e.ownerOK {
			return unsafeDir(dir, "%s let others in, and %s is a link or is owned by %s, not by SYSTEM or Administrators.", dir, p, e.who())
		}
		if filepath.Clean(p) == key && !e.onlyAdmins() {
			return unsafeDir(dir, "the device key %s could be read by others, so it may have been copied.", p)
		}
		return nil
	})
}

// checkKeyFile refuses a device key that someone other than SYSTEM or
// Administrators owns or can open, and gives one that only inherits its
// access list from the folder a protected list of its own, so a later
// change to the folder cannot expose it.
func checkKeyFile(fsec fsSecurity, path string) error {
	dir := filepath.Dir(path)
	si, err := fsec.stat(path)
	if err != nil {
		return err
	}
	if si.link || si.isDir {
		return unsafeDir(dir, "the device key %s is a link or a folder.", path)
	}
	if !si.ownerOK || !si.onlyAdmins() {
		return unsafeDir(dir, "the device key %s is owned by %s or can be opened by others, so it may have been copied.", path, si.who())
	}
	if si.protected {
		return nil
	}
	if err := fsec.lockDown(path); err != nil {
		return fmt.Errorf("restrict the access list of %s: %w", path, err)
	}
	return nil
}
