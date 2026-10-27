package keystore

import (
	"errors"
	"fmt"
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

// dirSDDL gives SYSTEM and Administrators full control and nobody else
// any access; P blocks inheritance from %ProgramData%, which lets every
// user read.
const dirSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// PrepareDir creates dir with the restrictive ACL. An existing directory
// is left as it is.
func PrepareDir(dir string) error {
	if fi, err := os.Stat(dir); err == nil {
		if !fi.IsDir() {
			return fmt.Errorf("%s is not a directory", dir)
		}
		return nil
	}
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
	if err := windows.CreateDirectory(p, sa); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return fmt.Errorf("create %s: %w (run as administrator)", dir, err)
	}
	return nil
}

// dpapiEntropy binds blobs to this use, so a DPAPI blob made for something
// else cannot be swapped in.
var dpapiEntropy = []byte("kovyr-device-key/v1")

func blob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

// seal encrypts with DPAPI in machine scope: any process on this machine
// running as an administrator or SYSTEM can unseal it, which is what a
// service needs; the file ACL keeps other users out. A TPM key will
// replace this (see proof.Signer).
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

// checkFilePerms only checks existence on Windows; the directory ACL
// protects the file.
func checkFilePerms(path string) error {
	_, err := os.Stat(path)
	return err
}
