package keystore

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// fakeSecurity is a folder tree with owners and access lists, for the
// state-folder decisions on any OS.
type fakeSecurity struct {
	objs     map[string]secInfo
	order    []string // walk order, below the folder
	locked   []string // lockDown calls
	noEffect bool     // lockDown "succeeds" but changes nothing
}

const (
	sidUsers = "S-1-5-32-545"
	sidBob   = "S-1-5-21-1-2-3-1001"
)

var (
	adminDir  = secInfo{isDir: true, owner: "S-1-5-32-544", ownerOK: true, protected: true}
	adminFile = secInfo{owner: "S-1-5-18", ownerOK: true}
)

func newFake(dir string) *fakeSecurity {
	return &fakeSecurity{objs: map[string]secInfo{dir: adminDir}}
}

func (f *fakeSecurity) add(path string, si secInfo) {
	f.objs[path] = si
	f.order = append(f.order, path)
}

func (f *fakeSecurity) stat(path string) (secInfo, error) {
	si, ok := f.objs[path]
	if !ok {
		return secInfo{}, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
	}
	return si, nil
}

func (f *fakeSecurity) lockDown(path string) error {
	f.locked = append(f.locked, path)
	si := f.objs[path]
	if si.link {
		return errors.New("a link")
	}
	if !f.noEffect {
		si.owner, si.ownerOK, si.protected, si.noDACL, si.others = "S-1-5-32-544", true, true, false, nil
		f.objs[path] = si
	}
	return nil
}

func (f *fakeSecurity) walk(dir string, fn func(string) error) error {
	for _, p := range f.order {
		if err := fn(p); err != nil {
			return err
		}
	}
	return nil
}

var stateDir = filepath.Join("C:", "ProgramData", "Kovyr")

func mustRefuse(t *testing.T, err error, want ...string) {
	t.Helper()
	if !errors.Is(err, ErrUnsafeDir) {
		t.Fatalf("err %v, want ErrUnsafeDir", err)
	}
	for _, w := range append(want, "delete the folder "+stateDir, "install Kovyr again", "enroll it again") {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("message lacks %q:\n%s", w, err)
		}
	}
}

// HOST-1: a folder a user made before Kovyr was installed is refused, not
// taken over, whatever its access list says.
func TestCheckDirRefusesAFolderSomeoneElseOwns(t *testing.T) {
	for name, si := range map[string]secInfo{
		"squatted, loose":     {isDir: true, owner: sidBob, others: []string{sidBob}},
		"squatted, protected": {isDir: true, owner: sidUsers, protected: true},
		"no owner read":       {isDir: true, protected: true},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(stateDir)
			f.objs[stateDir] = si
			f.add(Path(stateDir), adminFile)
			mustRefuse(t, checkDir(f, stateDir), "not by SYSTEM or Administrators")
			if len(f.locked) != 0 {
				t.Fatalf("it changed the access list of a folder someone else owns: %v", f.locked)
			}
		})
	}
}

func TestCheckDirRefusesALinkOrAFile(t *testing.T) {
	for name, si := range map[string]secInfo{
		"junction": {isDir: true, link: true, owner: "S-1-5-32-544", ownerOK: true, protected: true},
		"file":     {owner: "S-1-5-32-544", ownerOK: true, protected: true},
	} {
		f := newFake(stateDir)
		f.objs[stateDir] = si
		t.Run(name, func(t *testing.T) {
			mustRefuse(t, checkDir(f, stateDir), "not a folder")
			if len(f.locked) != 0 {
				t.Fatalf("lockDown called: %v", f.locked)
			}
		})
	}
}

func TestCheckDirLeavesALockedDownFolderAlone(t *testing.T) {
	f := newFake(stateDir)
	f.add(Path(stateDir), adminFile)
	if err := checkDir(f, stateDir); err != nil {
		t.Fatal(err)
	}
	if len(f.locked) != 0 {
		t.Fatalf("lockDown called on a folder that was fine: %v", f.locked)
	}
	if _, err := (&fakeSecurity{objs: map[string]secInfo{}}).stat(stateDir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("the fake does not report a missing folder")
	}
	if err := checkDir(&fakeSecurity{objs: map[string]secInfo{}}, stateDir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing folder: %v, want not-exist", err)
	}
}

// The owner is right but the list lets others in: it is repaired, then
// checked again.
func TestCheckDirRepairsALooseAccessList(t *testing.T) {
	for name, si := range map[string]secInfo{
		"users can write":       {isDir: true, owner: "S-1-5-18", ownerOK: true, protected: true, others: []string{sidUsers}},
		"inherits from parent":  {isDir: true, owner: "S-1-5-32-544", ownerOK: true},
		"no access list at all": {isDir: true, owner: "S-1-5-32-544", ownerOK: true, protected: true, noDACL: true},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(stateDir)
			f.objs[stateDir] = si
			f.add(Path(stateDir), secInfo{owner: "S-1-5-18", ownerOK: true, protected: true})
			f.add(filepath.Join(stateDir, "logs"), secInfo{isDir: true, owner: "S-1-5-18", ownerOK: true, others: []string{sidUsers}})
			if err := checkDir(f, stateDir); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(f.locked, []string{stateDir}) {
				t.Fatalf("lockDown calls %v, want the folder once", f.locked)
			}
		})
	}
}

func TestCheckDirRefusesARepairThatDidNotTake(t *testing.T) {
	f := newFake(stateDir)
	f.objs[stateDir] = secInfo{isDir: true, owner: "S-1-5-18", ownerOK: true, others: []string{sidUsers}}
	f.noEffect = true
	mustRefuse(t, checkDir(f, stateDir), "could not be restricted")
}

// A loose list may already have been used: what someone else owns or
// planted, and a key they could read, are refused rather than repaired.
func TestCheckDirRefusesWhatALooseListLetIn(t *testing.T) {
	loose := secInfo{isDir: true, owner: "S-1-5-32-544", ownerOK: true, others: []string{sidUsers}}
	for name, c := range map[string]struct {
		path string
		si   secInfo
		want string
	}{
		"planted settings": {filepath.Join(stateDir, "agent-config.json"), secInfo{owner: sidBob, protected: true}, sidBob},
		"logs junction":    {filepath.Join(stateDir, "logs"), secInfo{isDir: true, link: true, owner: "S-1-5-32-544", ownerOK: true}, "is a link"},
		"readable key":     {Path(stateDir), secInfo{owner: "S-1-5-18", ownerOK: true, others: []string{sidUsers}}, "may have been copied"},
		"key, no list":     {Path(stateDir), secInfo{owner: "S-1-5-18", ownerOK: true, noDACL: true}, "may have been copied"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(stateDir)
			f.objs[stateDir] = loose
			f.add(filepath.Join(stateDir, "chain-state.json"), adminFile)
			f.add(c.path, c.si)
			mustRefuse(t, checkDir(f, stateDir), c.want)
			if len(f.locked) != 0 {
				t.Fatalf("lockDown called: %v", f.locked)
			}
		})
	}
	// Too much to look through.
	f := newFake(stateDir)
	f.objs[stateDir] = loose
	for i := 0; i <= maxEntries; i++ {
		f.add(filepath.Join(stateDir, "queue", fmt.Sprint(i)), adminFile)
	}
	mustRefuse(t, checkDir(f, stateDir), "more than")
}

// HOST-4: the key is refused if anyone else owns or can open it, and an
// older key that only inherits the folder's list gets its own.
func TestCheckKeyFile(t *testing.T) {
	key := Path(stateDir)
	for name, si := range map[string]secInfo{
		"owned by a user":  {owner: sidBob, protected: true},
		"users can read":   {owner: "S-1-5-18", ownerOK: true, protected: true, others: []string{sidUsers}},
		"no access list":   {owner: "S-1-5-18", ownerOK: true, noDACL: true},
		"a link":           {link: true, owner: "S-1-5-18", ownerOK: true, protected: true},
		"a folder instead": {isDir: true, owner: "S-1-5-18", ownerOK: true, protected: true},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(stateDir)
			f.add(key, si)
			mustRefuse(t, checkKeyFile(f, key))
			if len(f.locked) != 0 {
				t.Fatalf("lockDown called: %v", f.locked)
			}
		})
	}
	f := newFake(stateDir)
	f.add(key, secInfo{owner: "S-1-5-18", ownerOK: true}) // inherited SYSTEM/Administrators only
	if err := checkKeyFile(f, key); err != nil || !slices.Equal(f.locked, []string{key}) {
		t.Fatalf("older key: %v, lockDown %v", err, f.locked)
	}
	f = newFake(stateDir)
	f.add(key, secInfo{owner: "S-1-5-32-544", ownerOK: true, protected: true})
	if err := checkKeyFile(f, key); err != nil || len(f.locked) != 0 {
		t.Fatalf("protected key: %v, lockDown %v", err, f.locked)
	}
	if err := checkKeyFile(newFake(stateDir), key); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing key: %v", err)
	}
}
