package keystore

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// DefaultDir is %ProgramData%\Kovyr.
func DefaultDir() (string, error) {
	pd, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return "", err
	}
	return filepath.Join(pd, "Kovyr"), nil
}

// dirSDDL makes Administrators the owner and gives SYSTEM and
// Administrators full control and nobody else any access; P blocks
// inheritance from %ProgramData%, which lets every user read (and create
// folders, which is why an existing folder is checked: dirsafety.go).
const dirSDDL = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// fileSDDL is the device key file's own protected access list, so the key
// does not depend on what the folder passes down.
const fileSDDL = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"

// PrepareDir creates dir with the restrictive ACL, or checks an existing
// one (CheckDir). Either way, when it returns nil only SYSTEM and
// Administrators control dir.
func PrepareDir(dir string) error {
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
			return err
		}
		sd, err := windows.SecurityDescriptorFromString(dirSDDL)
		if err != nil {
			return err
		}
		sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
		p, err := windows.UTF16PtrFromString(dir)
		if err != nil {
			return err
		}
		// Someone may make it between the Lstat and here: CheckDir below
		// then judges theirs.
		if err := windows.CreateDirectory(p, sa); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return fmt.Errorf("create %s: %w (run as administrator)", dir, err)
		}
	}
	return CheckDir(dir)
}

// CheckDir makes sure only SYSTEM and Administrators control an existing
// state directory: it refuses one someone else owns (ErrUnsafeDir) and
// repairs a loose access list (dirsafety.go). It runs before the agent
// reads or writes anything there: at install, at keygen and every time
// the service starts.
func CheckDir(dir string) error { return checkDir(winSecurity{}, dir) }

// protectKeyFile gives a new key file its own protected access list.
func protectKeyFile(path string) error { return winSecurity{}.lockDown(path) }

// checkFilePerms refuses a key file that anyone but SYSTEM and
// Administrators owns or can open, and gives an older one that only
// inherited its access list its own protected list.
func checkFilePerms(path string) error { return checkKeyFile(winSecurity{}, path) }

// winSecurity is fsSecurity on NTFS. Each object is opened by handle with
// FILE_FLAG_OPEN_REPARSE_POINT, so a junction or link at the path is
// itself what is read or set, never its target.
type winSecurity struct{}

// fileAttributeTagInfo is FILE_ATTRIBUTE_TAG_INFO.
type fileAttributeTagInfo struct {
	FileAttributes uint32
	ReparseTag     uint32
}

// reparseTagNameSurrogate marks reparse points that redirect a path
// (junctions, mount points, symbolic links).
const reparseTagNameSurrogate = 0x20000000

func openNoFollow(path string, access uint32) (windows.Handle, fileAttributeTagInfo, error) {
	var ti fileAttributeTagInfo
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, ti, err
	}
	h, err := windows.CreateFile(p, access|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return windows.InvalidHandle, ti, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	if err := windows.GetFileInformationByHandleEx(h, windows.FileAttributeTagInfo,
		(*byte)(unsafe.Pointer(&ti)), uint32(unsafe.Sizeof(ti))); err != nil {
		windows.CloseHandle(h)
		return windows.InvalidHandle, ti, err
	}
	return h, ti, nil
}

func (ti fileAttributeTagInfo) link() bool {
	return ti.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 && ti.ReparseTag&reparseTagNameSurrogate != 0
}

func trustedSID(s *windows.SID) bool {
	return s != nil && (s.IsWellKnown(windows.WinLocalSystemSid) || s.IsWellKnown(windows.WinBuiltinAdministratorsSid))
}

func (winSecurity) stat(path string) (secInfo, error) {
	h, ti, err := openNoFollow(path, windows.READ_CONTROL)
	if err != nil {
		return secInfo{}, err
	}
	defer windows.CloseHandle(h)
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return secInfo{}, fmt.Errorf("read the access list of %s: %w", path, err)
	}
	si := secInfo{isDir: ti.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0, link: ti.link()}
	if owner, _, err := sd.Owner(); err == nil && owner != nil {
		si.owner, si.ownerOK = owner.String(), trustedSID(owner)
	}
	if ctl, _, err := sd.Control(); err == nil {
		si.protected = ctl&windows.SE_DACL_PROTECTED != 0
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		si.noDACL = true // no list, or a NULL one: everyone has full access
		return si, nil
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return secInfo{}, fmt.Errorf("read the access list of %s: %w", path, err)
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue // a plain deny takes nothing away from safety
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			if sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)); !trustedSID(sid) {
				si.others = append(si.others, sid.String())
			}
		default:
			// Any other kind of entry (conditional, object, ...) is not one
			// the agent writes; count it as letting someone in.
			si.others = append(si.others, fmt.Sprintf("an entry of type %d", ace.Header.AceType))
		}
	}
	return si, nil
}

func (winSecurity) lockDown(path string) error {
	h, ti, err := openNoFollow(path, windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	if ti.link() {
		return fmt.Errorf("%s is a link", path)
	}
	sddl := fileSDDL
	if ti.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		sddl = dirSDDL
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	// By handle, so the object checked is the one changed. Setting a
	// folder's list passes its inheritable entries down to what is inside.
	return windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil)
}

// walk does not follow junctions or links: WalkDir does not descend into
// them (os.Lstat semantics), and each entry is reported to fn.
func (winSecurity) walk(dir string, fn func(path string) error) error {
	return filepath.WalkDir(dir, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == dir {
			return nil
		}
		return fn(p)
	})
}

// dpapiEntropy binds blobs to this use, so a DPAPI blob made for something
// else cannot be swapped in. It is not a secret: it is in this source and
// in the binary.
var dpapiEntropy = []byte("kovyr-device-key/v1")

func blob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

// seal encrypts with DPAPI in machine scope. That ties the blob to this
// computer, so a copy of the file (in a backup, say) cannot be opened on
// another one. It does not keep anyone on this computer out: with
// CRYPTPROTECT_LOCAL_MACHINE any process here can unseal it, whatever
// user it runs as, and the entropy is public. What keeps other users from
// the key is only the access list on the state folder and on the key file
// (CheckDir, protectKeyFile). A TPM key will replace this (see
// proof.Signer).
func seal(der []byte) ([]byte, string, error) {
	var out windows.DataBlob
	desc, _ := windows.UTF16PtrFromString("Kovyr device key")
	err := windows.CryptProtectData(blob(der), desc, blob(dpapiEntropy), 0, nil,
		windows.CRYPTPROTECT_LOCAL_MACHINE|windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	if err != nil {
		return nil, "", err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), storageDPAPI, nil
}

func unseal(storage string, sealed []byte) ([]byte, error) {
	if storage != storageDPAPI {
		return nil, fmt.Errorf("key storage %q is not accepted on Windows", storage)
	}
	if len(sealed) == 0 {
		return nil, errors.New("empty sealed key")
	}
	var out windows.DataBlob
	err := windows.CryptUnprotectData(blob(sealed), nil, blob(dpapiEntropy), 0, nil,
		windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	plain := unsafe.Slice(out.Data, out.Size)
	res := append([]byte(nil), plain...)
	clear(plain)
	return res, nil
}
