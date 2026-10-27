package tripwire

import (
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
)

func TestFolders(t *testing.T) {
	root := t.TempDir()
	p := func(parts ...string) string { return filepath.Join(append([]string{root}, parts...)...) }
	got := Folders([]string{
		p("Clients"),
		p("jane", "Documents"),
		p("Clients", "2026"),    // inside Clients
		p("JANE", "documents"),  // the same folder, other case
		p("jane", "Documents2"), // a sibling with a longer name, not inside
		"",
		p("Clients") + string(filepath.Separator), // a duplicate with a trailing separator
		p("Shared", "Tax"),                        // gives way to Shared, listed later
		p("Shared"),
	})
	want := []string{p("Clients"), p("jane", "Documents"), p("jane", "Documents2"), p("Shared")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q\nwant %q", got, want)
	}
	// Duplicates keep their first spelling, however it is written.
	sep := string(filepath.Separator)
	if got := Folders([]string{p("A") + sep, p("A"), p("B", "..", "A", "x")}); !reflect.DeepEqual(got, []string{p("A") + sep}) {
		t.Fatalf("spellings: %q", got)
	}
	vol := filepath.VolumeName(root) + string(filepath.Separator) // C:\ or /
	if got := Folders([]string{p("x"), vol}); !reflect.DeepEqual(got, []string{vol}) {
		t.Fatalf("a drive root covers its folders: %q", got)
	}
	var many []string
	for i := 0; i < 50; i++ {
		many = append(many, p(fmt.Sprintf("user%02d", i)))
	}
	if got := Folders(many); len(got) != MaxFolders || got[0] != many[0] {
		t.Fatalf("cap: %d folders", len(got))
	}
}
