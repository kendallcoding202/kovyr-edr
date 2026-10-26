package tripwire

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func TestClassifyRename(t *testing.T) {
	for _, c := range []struct {
		from, to string
		want     Kind
	}{
		{`taxes\2025\return.pdf`, `taxes\2025\return.pdf.locked`, ExtensionChanged}, // appended extension
		{`budget.xlsx`, `budget.xlsx.8f3a9c`, ExtensionChanged},
		{`photo.JPG`, `photo.jpg`, Renamed},            // case only
		{`draft.docx`, `final.docx`, Renamed},          // name only
		{`report.docx`, `~WRL0001.tmp`, Renamed},       // Word saving
		{`~WRD0000.tmp`, `report.docx`, Renamed},       // Word saving
		{`setup.exe.crdownload`, `setup.exe`, Renamed}, // browser download
		{`big.iso.part`, `big.iso`, Renamed},           // download manager
		{`notes.txt`, `notes.txt~`, Renamed},           // editor backup
		{`Makefile`, `Makefile.bak`, Renamed},          // backup copy
		{`a\b\scan001.png`, `a\b\scan001.png.enc`, ExtensionChanged},
	} {
		if got := ClassifyRename(c.from, c.to); got != c.want {
			t.Errorf("%s -> %s: %d, want %d", c.from, c.to, got, c.want)
		}
	}
}

func TestRansomNotesAndRandomNames(t *testing.T) {
	for _, n := range []string{"README_TO_DECRYPT.txt", `docs\HOW_TO_RECOVER_FILES.html`, "_readme.txt", "!!!RESTORE_FILES!!!.TXT",
		"#DECRYPT_MY_FILES#.hta", "Your_Files_Are_Encrypted.rtf", "HELP_RESTORE.txt"} {
		if !IsRansomNote(n) || ClassifyCreate(n) != SuspiciousCreated {
			t.Errorf("%s not seen as a ransom note", n)
		}
	}
	for _, n := range []string{"README.txt", "readme.md", "decrypt.go", "Decryption lecture notes.docx", "restore.txt.bak", "notes.txt"} {
		if IsRansomNote(n) {
			t.Errorf("%s seen as a ransom note", n)
		}
	}
	for _, n := range []string{"a8F3kLm9QzX2pR7wT4.locked", "Q2hd8KZx9mPq4Ws1Lr7T.docx"} {
		if !IsRandomName(n) || ClassifyCreate(n) != SuspiciousCreated {
			t.Errorf("%s not seen as random", n)
		}
	}
	for _, n := range []string{"IMG_20261026_123456.jpg", "Invoice 2026-10 Maple Street.pdf", "quarterlyreportfinal.docx",
		"aaaaaaaaaaaaaaaaaaaa.txt", "AbAbAbAbAbAbAbAbAbAb.txt", "Ab12Ab12Ab12Ab12Ab12.dat", "short.txt", "0123456789012345.csv", "Résumé de l'année 2026.docx"} {
		if IsRandomName(n) {
			t.Errorf("%s seen as random", n)
		}
	}
	if ClassifyCreate("Q3 board deck.pptx") != Created {
		t.Error("an ordinary file is suspicious")
	}
}

// record builds one FILE_NOTIFY_INFORMATION record.
func record(action uint32, name string, last bool) []byte {
	u := utf16.Encode([]rune(name))
	n := 12 + 2*len(u)
	size := (n + 3) &^ 3 // DWORD aligned
	b := make([]byte, size)
	if !last {
		binary.LittleEndian.PutUint32(b[0:], uint32(size))
	}
	binary.LittleEndian.PutUint32(b[4:], action)
	binary.LittleEndian.PutUint32(b[8:], uint32(2*len(u)))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[12+2*i:], c)
	}
	return b
}

func buffer(recs ...[]byte) []byte {
	var out []byte
	for _, r := range recs {
		out = append(out, r...)
	}
	return out
}

func parse(t *testing.T, p *Parser, buf []byte) map[Kind]int {
	t.Helper()
	got := map[Kind]int{}
	p.Parse(buf, func(k Kind) { got[k]++ })
	return got
}

func TestParserClassifiesARealBuffer(t *testing.T) {
	var p Parser
	got := parse(t, &p, buffer(
		record(actionModified, `Q3\budget.xlsx`, false),
		record(actionRenamedOldName, `Q3\budget.xlsx`, false),
		record(actionRenamedNewName, `Q3\budget.xlsx.locked`, false),
		record(actionAdded, `Q3\HOW_TO_DECRYPT.txt`, false),
		record(actionAdded, `Q3\minutes.docx`, false),
		record(actionRemoved, `Q3\old.pdf`, false),
		record(actionRenamedOldName, `draft.docx`, false),
		record(actionRenamedNewName, `final.docx`, true),
	))
	want := map[Kind]int{Modified: 1, ExtensionChanged: 1, SuspiciousCreated: 1, Created: 1, Deleted: 1, Renamed: 1}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, n := range want {
		if got[k] != n {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestParserKeepsARenameAcrossBuffers(t *testing.T) {
	var p Parser
	if got := parse(t, &p, record(actionRenamedOldName, `a.docx`, true)); len(got) != 0 {
		t.Fatalf("half a rename counted: %v", got)
	}
	if got := parse(t, &p, record(actionRenamedNewName, `a.docx.crypt`, true)); got[ExtensionChanged] != 1 {
		t.Fatalf("split rename: %v", got)
	}
	// An old name with no new half moved out of view.
	parse(t, &p, record(actionRenamedOldName, `b.docx`, true))
	if got := parse(t, &p, record(actionModified, `c.docx`, true)); got[Renamed] != 1 || got[Modified] != 1 {
		t.Fatalf("moved out: %v", got)
	}
	var flushed int
	parse(t, &p, record(actionRenamedOldName, `d.docx`, true))
	p.Flush(func(Kind) { flushed++ })
	if flushed != 1 {
		t.Fatal("flush lost a pending rename")
	}
	// A new name with no old half moved in.
	if got := parse(t, &p, record(actionRenamedNewName, `e.docx`, true)); got[Renamed] != 1 {
		t.Fatalf("moved in: %v", got)
	}
}

// A damaged buffer is read as far as it is sound; the rest is unknown
// activity, never a crash or an out-of-range read.
func TestParserSurvivesMalformedBuffers(t *testing.T) {
	good := record(actionModified, `x.txt`, false)
	bad := map[string][]byte{
		"truncated header":   good[:7],
		"name past the end":  append(append([]byte{}, good[:8]...), 0xff, 0xff, 0, 0, 'a', 0),
		"odd name length":    func() []byte { b := append([]byte{}, record(actionModified, "x", true)...); b[8] = 3; return b }(),
		"next past the end":  func() []byte { b := append([]byte{}, good...); b[0] = 0xf0; return b }(),
		"next inside record": func() []byte { b := append([]byte{}, good...); b[0] = 4; return b }(),
		"unknown action":     record(99, `x.txt`, true),
	}
	for name, b := range bad {
		var p Parser
		got := parse(t, &p, b)
		if got[Unknown] == 0 {
			t.Errorf("%s: no unknown activity counted (%v)", name, got)
		}
	}
	// A record whose next offset points into its own name, where a fake
	// "created" record hides: it must not be parsed.
	hidden := []byte{12, 0, 0, 0, actionModified, 0, 0, 0, 14, 0, 0, 0,
		0, 0, 0, 0, actionAdded, 0, 0, 0, 2, 0, 0, 0, 'a', 0}
	var hp Parser
	if got := parse(t, &hp, hidden); got[Created] != 0 || got[Unknown] != 1 {
		t.Errorf("overlapping record parsed: %v", got)
	}
	var p Parser
	if got := parse(t, &p, nil); len(got) != 0 {
		t.Errorf("empty buffer: %v", got)
	}
}

func FuzzParser(f *testing.F) {
	f.Add(buffer(record(actionAdded, "a.txt", false), record(actionRemoved, "b", true)))
	f.Fuzz(func(t *testing.T, b []byte) {
		var p Parser
		p.Parse(b, func(k Kind) {
			if k >= numKinds {
				t.Fatalf("kind %d", k)
			}
		})
	})
}
