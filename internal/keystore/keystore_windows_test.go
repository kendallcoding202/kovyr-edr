package keystore

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/kendallcoding202/kovyr-edr/internal/proof"
)

// skipIfCannotPrepare skips when the test is not elevated: the key
// directory is created for SYSTEM and Administrators only.
func skipIfCannotPrepare(t *testing.T, dir string) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated (administrator) process, as the agent does")
	}
}

func TestDPAPISealIsNotPlaintext(t *testing.T) {
	k, err := proof.GenerateSoftwareKey()
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	sealed, storage, err := seal(der)
	if err != nil {
		t.Fatal(err)
	}
	if storage != storageDPAPI || bytes.Contains(sealed, der) {
		t.Fatal("DPAPI output contains the plain key")
	}
	plain, err := unseal(storage, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, der) {
		t.Fatal("unseal did not return the key")
	}
	if _, err := unseal(storageDevFile, der); err == nil {
		t.Fatal("Windows accepted a plain dev key file")
	}
	corrupt := append([]byte(nil), sealed...)
	corrupt[len(corrupt)/2] ^= 0xff
	if _, err := unseal(storage, corrupt); err == nil {
		t.Fatal("unsealed a corrupted blob")
	}
}

func TestKeyFileHoldsNoPlainKey(t *testing.T) {
	dir := testDir(t)
	skipIfCannotPrepare(t, dir)
	if _, err := Generate(dir); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(Path(dir))
	var kf keyFile
	json.Unmarshal(b, &kf)
	sealed, _ := base64.StdEncoding.DecodeString(kf.Sealed)
	if _, err := x509.ParsePKCS8PrivateKey(sealed); err == nil {
		t.Fatal("key file holds a plain PKCS#8 key")
	}
}

// The state folder on a real NTFS volume (HOST-1, HOST-4, HOST-7). These
// make folders under the test's temporary directory with the owners and
// access lists an attacker, an older version or a careless administrator
// would leave, then run the key store's own code on them.

const (
	sddlUsers = "S-1-5-32-545" // BUILTIN\Users: a principal that is not an administrator
)

// withRestorePrivilege enables SeRestorePrivilege, which an elevated
// process holds: it lets the test make any SID the owner, as a user who
// created the folder would be.
func withRestorePrivilege(t *testing.T) {
	t.Helper()
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
		t.Skip(err)
	}
	defer tok.Close()
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeRestorePrivilege"), &luid); err != nil {
		t.Skip(err)
	}
	// An elevated process holds the privilege (skipIfCannotPrepare); if
	// it were not held, setOwner below fails the test.
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
	if err := windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil); err != nil {
		t.Skipf("cannot enable SeRestorePrivilege: %v", err)
	}
	t.Cleanup(func() {
		var tok windows.Token
		if windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES, &tok) == nil {
			tp := windows.Tokenprivileges{PrivilegeCount: 1}
			tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid}
			windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil)
			tok.Close()
		}
	})
}

func setOwner(t *testing.T, path, sid string) {
	t.Helper()
	s, err := windows.StringToSid(sid)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, s, nil, nil, nil); err != nil {
		t.Fatalf("set the owner of %s to %s: %v", path, sid, err)
	}
}

// setDACL replaces path's access list; unprotected lists also inherit
// from the parent, as a folder a user makes in ProgramData does.
func setDACL(t *testing.T, path, sddl string, protected bool) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.UNPROTECTED_DACL_SECURITY_INFORMATION)
	if protected {
		info = windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, nil, nil, dacl, nil); err != nil {
		t.Fatalf("set the access list of %s: %v", path, err)
	}
}

func sddlOf(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	return sd.String()
}

// onlyAdminsSDDL checks an SDDL string: owner SYSTEM or Administrators, a
// protected list, and only SYSTEM and Administrators in it.
func onlyAdminsSDDL(t *testing.T, what, sddl string) {
	t.Helper()
	if !strings.HasPrefix(sddl, "O:SY") && !strings.HasPrefix(sddl, "O:BA") {
		t.Errorf("%s owner is not SYSTEM or Administrators: %s", what, sddl)
	}
	if !strings.Contains(sddl, "D:P") {
		t.Errorf("%s access list is not protected: %s", what, sddl)
	}
	for _, ace := range regexp.MustCompile(`\(([^)]*)\)`).FindAllStringSubmatch(sddl, -1) {
		f := strings.Split(ace[1], ";")
		if who := f[len(f)-1]; who != "SY" && who != "BA" {
			t.Errorf("%s access list grants %s: %s", what, who, sddl)
		}
	}
}

// keyBytes makes a real sealed key file elsewhere and returns its bytes,
// as an attacker could (machine-scope DPAPI needs no rights).
func keyBytes(t *testing.T) []byte {
	t.Helper()
	other := testDir(t)
	if _, err := Generate(other); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(Path(other))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A user made the folder before Kovyr was installed, and maybe planted a
// key they know. Install (Generate) and every later start (Load, CheckDir)
// refuse it, say what to do, and change nothing.
func TestPreCreatedFolderWithAnotherOwnerIsRefused(t *testing.T) {
	dir := testDir(t)
	skipIfCannotPrepare(t, dir)
	withRestorePrivilege(t)
	planted := keyBytes(t)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	setDACL(t, dir, "D:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;"+sddlUsers+")", false)
	setOwner(t, dir, sddlUsers)
	before := sddlOf(t, dir)

	for name, f := range map[string]func() error{
		"PrepareDir": func() error { return PrepareDir(dir) },
		"CheckDir":   func() error { return CheckDir(dir) },
		"Generate":   func() error { _, err := Generate(dir); return err },
	} {
		err := f()
		if !errors.Is(err, ErrUnsafeDir) || !strings.Contains(err.Error(), sddlUsers) ||
			!strings.Contains(err.Error(), "delete the folder") {
			t.Errorf("%s: %v, want a refusal naming the owner and the remedy", name, err)
		}
	}
	if _, err := os.Stat(Path(dir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a device key was written into the folder (%v)", err)
	}
	if after := sddlOf(t, dir); after != before {
		t.Fatalf("the folder was changed:\nbefore %s\nafter  %s", before, after)
	}
	// The planted key is never used.
	if err := os.WriteFile(Path(dir), planted, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); !errors.Is(err, ErrUnsafeDir) {
		t.Fatalf("Load used a key in a folder a user owns: %v", err)
	}
}

// A junction or symbolic link where the folder should be is refused.
func TestStateFolderThatIsALinkIsRefused(t *testing.T) {
	dir := testDir(t)
	skipIfCannotPrepare(t, dir)
	target := filepath.Join(filepath.Dir(dir), "elsewhere")
	if err := PrepareDir(target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, dir); err != nil {
		t.Skipf("cannot make a symbolic link here: %v", err)
	}
	if err := CheckDir(dir); !errors.Is(err, ErrUnsafeDir) {
		t.Fatalf("CheckDir on a link: %v", err)
	}
	if _, err := Generate(dir); !errors.Is(err, ErrUnsafeDir) {
		t.Fatalf("Generate through a link: %v", err)
	}
}

// The owner is right but the list lets users in (an administrator
// loosened it): it is repaired, down to what is inside, and the key
// still loads.
func TestLooseFolderIsRepaired(t *testing.T) {
	dir := testDir(t)
	skipIfCannotPrepare(t, dir)
	s, err := Generate(dir)
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "agent-config.json")
	if err := os.WriteFile(other, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	setOwner(t, other, "S-1-5-32-544") // as the service (SYSTEM) or an elevated install leaves it
	setDACL(t, dir, "D:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;"+sddlUsers+")", false)
	if sddl := sddlOf(t, other); !strings.Contains(sddl, ";BU)") {
		t.Fatalf("setup: the loose list did not reach the file inside: %s", sddl)
	}

	if err := CheckDir(dir); err != nil {
		t.Fatalf("CheckDir on a loose folder: %v", err)
	}
	onlyAdminsSDDL(t, "state folder", sddlOf(t, dir))
	if sddl := sddlOf(t, other); strings.Contains(sddl, ";BU)") {
		t.Errorf("after the repair a file inside still lets users in: %s", sddl)
	}
	again, err := Load(dir)
	if err != nil || again.Public().KeyID() != s.Public().KeyID() {
		t.Fatalf("Load after the repair: %v", err)
	}
}

// A loose list may already have been used: a file a user owns inside is
// refused, not repaired.
func TestLooseFolderWithAUsersFileIsRefused(t *testing.T) {
	dir := testDir(t)
	skipIfCannotPrepare(t, dir)
	withRestorePrivilege(t)
	if _, err := Generate(dir); err != nil {
		t.Fatal(err)
	}
	setDACL(t, dir, "D:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;"+sddlUsers+")", false)
	planted := filepath.Join(dir, "agent-config.json")
	if err := os.WriteFile(planted, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	setOwner(t, planted, sddlUsers)
	if err := CheckDir(dir); !errors.Is(err, ErrUnsafeDir) || !strings.Contains(err.Error(), sddlUsers) {
		t.Fatalf("CheckDir with a user's file inside: %v", err)
	}
}

// HOST-4: a new key file has its own protected list; a key others can
// read is refused.
func TestKeyFileHasItsOwnProtectedACL(t *testing.T) {
	dir := testDir(t)
	skipIfCannotPrepare(t, dir)
	if _, err := Generate(dir); err != nil {
		t.Fatal(err)
	}
	onlyAdminsSDDL(t, "state folder", sddlOf(t, dir))
	onlyAdminsSDDL(t, "key file", sddlOf(t, Path(dir)))

	setDACL(t, Path(dir), "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;"+sddlUsers+")", true)
	if _, err := Load(dir); !errors.Is(err, ErrUnsafeDir) {
		t.Fatalf("Load of a key users can read: %v", err)
	}
}

// The upgrade path: a folder and key an earlier version made (the MSI
// runs as SYSTEM; the key only inherited the folder's list) are accepted,
// and the key gets its own protected list.
func TestEarlierInstallIsAcceptedAndItsKeyHardened(t *testing.T) {
	dir := testDir(t)
	skipIfCannotPrepare(t, dir)
	withRestorePrivilege(t)
	key := keyBytes(t)
	// What the earlier PrepareDir did: no owner given, so the creator's.
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		t.Fatal(err)
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	if err := windows.CreateDirectory(windows.StringToUTF16Ptr(dir), sa); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(Path(dir), key, 0o600); err != nil {
		t.Fatal(err)
	}
	setOwner(t, dir, "S-1-5-18")
	setOwner(t, Path(dir), "S-1-5-18")
	if sddl := sddlOf(t, Path(dir)); strings.Contains(sddl, "D:P") {
		t.Fatalf("setup: the old key file already has its own list: %s", sddl)
	}
	if _, err := Load(dir); err != nil {
		t.Fatalf("Load of an earlier install: %v", err)
	}
	onlyAdminsSDDL(t, "key file after the upgrade", sddlOf(t, Path(dir)))
}
