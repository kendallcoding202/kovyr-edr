// Package tripwire is a read-only ransomware tripwire. It receives the
// operating system's change notifications for a bounded set of folders,
// classifies each change in memory (the file name is looked at and
// dropped), counts the classes in a sliding window, and trips on the
// pattern ransomware leaves: mass renames to a new extension, or ransom
// notes appearing during a burst. It never opens, reads, hashes, creates
// or changes a file, and it never acts: it only reports (CLAUDE.md
// section 2).
package tripwire

import (
	"math"
	"strings"
	"unicode/utf16"
)

// Kind is what one file-system change was, once classified. A Kind is
// all that survives of a change: the file name it came with is looked at
// in memory, here, and dropped.
type Kind uint8

const (
	Modified          Kind = iota // a file's contents were written
	Renamed                       // renamed, extension kept (or a temporary-file rename)
	ExtensionChanged              // renamed to a different, non-temporary extension
	Deleted                       // a file was removed
	Created                       // an ordinary file was created
	SuspiciousCreated             // created with a ransom-note name or a random-looking name
	Unknown                       // the notification buffer overflowed: changes were lost
	numKinds
)

// Classification is a heuristic; docs/tripwire.md lists what it can
// mistake for ransomware and what it can miss.

// tempExts are extensions of files that programs write and then rename
// into place (or rename away to): Office's ~WRL0001.tmp dance, browser
// downloads, sync engines' partial files. A rename to or from one of these
// is ordinary, not an extension change.
var tempExts = map[string]bool{
	"": false, ".tmp": true, ".temp": true, ".crdownload": true, ".part": true, ".partial": true,
	".download": true, ".opdownload": true, ".dwl": true, ".dwl2": true, ".bak": true, ".swp": true,
	".~tmp": true, ".dropbox": true, ".gdtmp": true,
}

func isTempExt(ext string) bool {
	return tempExts[ext] || strings.HasPrefix(ext, ".~") || strings.HasSuffix(ext, "~")
}

// ext returns the lowercase extension of the last path element.
func ext(name string) string {
	base := baseName(name)
	if i := strings.LastIndexByte(base, '.'); i > 0 {
		return strings.ToLower(base[i:])
	}
	return ""
}

func baseName(name string) string {
	if i := strings.LastIndexAny(name, `\/`); i >= 0 {
		return name[i+1:]
	}
	return name
}

// ClassifyRename classifies a rename from old to new name (relative paths
// inside a watched folder).
func ClassifyRename(oldName, newName string) Kind {
	a, b := ext(oldName), ext(newName)
	if a == b || isTempExt(a) || isTempExt(b) || isOfficeTemp(oldName) || isOfficeTemp(newName) {
		return Renamed
	}
	return ExtensionChanged
}

// isOfficeTemp matches Office's owner files and temporary names
// (~$report.docx, ~WRL0001.tmp, ~WRD0000.tmp).
func isOfficeTemp(name string) bool {
	b := baseName(name)
	return strings.HasPrefix(b, "~$") || strings.HasPrefix(b, "~wr") || strings.HasPrefix(b, "~WR")
}

// ClassifyCreate classifies a newly created file.
func ClassifyCreate(name string) Kind {
	if IsRansomNote(name) || IsRandomName(name) {
		return SuspiciousCreated
	}
	return Created
}

// noteWords are fragments of ransom-note file names seen across common
// families ("README_TO_DECRYPT.txt", "HOW_TO_RECOVER_FILES.html",
// "_readme.txt", "!!!RESTORE_FILES!!!.txt", "#DECRYPT_MY_FILES#.html").
// They are matched in memory against the lowercase name with separators
// removed; the name is never recorded.
var noteWords = []string{
	"decrypt", "recoverfiles", "restorefiles", "howtorecover", "howtorestore", "readmetorestore",
	"unlockfiles", "yourfilesare", "filesencrypted", "encryptedfiles", "ransom", "restoremyfiles",
	"recovermyfiles", "helprestore", "helprecover",
}

// noteExts are the formats ransom notes are written in.
var noteExts = map[string]bool{".txt": true, ".html": true, ".htm": true, ".hta": true, ".rtf": true, ".url": true}

// IsRansomNote reports whether a file name looks like a ransom note.
func IsRansomNote(name string) bool {
	e := ext(name)
	if !noteExts[e] {
		return false
	}
	b := baseName(name)
	b = strings.ToLower(b[:len(b)-len(e)])
	var sb strings.Builder
	for i := 0; i < len(b); i++ {
		if c := b[i]; c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			sb.WriteByte(c)
		}
	}
	squashed := sb.String()
	if squashed == "readme" && strings.Contains(b, "_readme") {
		return true // STOP/Djvu writes "_readme.txt" into every folder
	}
	for _, w := range noteWords {
		if strings.Contains(squashed, w) {
			return true
		}
	}
	return false
}

// IsRandomName reports whether a file's name (without extension) looks
// randomly generated: long, letters and digits only, mixed, and with high
// character entropy, as some families name their encrypted files.
// Ordinary names (words, dates, "IMG_20261026_1234") do not qualify.
func IsRandomName(name string) bool {
	b := baseName(name)
	if i := strings.IndexByte(b, '.'); i > 0 {
		b = b[:i]
	}
	if len(b) < 16 || len(b) > 128 {
		return false
	}
	var upper, lower, digit int
	freq := map[byte]int{}
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case c >= 'A' && c <= 'Z':
			upper++
		case c >= 'a' && c <= 'z':
			lower++
		case c >= '0' && c <= '9':
			digit++
		default:
			return false // separators, spaces, non-ASCII: written by people
		}
		freq[c]++
	}
	classes := 0
	for _, n := range []int{upper, lower, digit} {
		if n > 0 {
			classes++
		}
	}
	if classes < 2 {
		return false
	}
	return entropy(freq, len(b)) >= 3.5
}

// entropy is the Shannon entropy in bits per character.
func entropy(freq map[byte]int, n int) float64 {
	var h float64
	for _, c := range freq {
		p := float64(c) / float64(n)
		h -= p * math.Log2(p)
	}
	return h
}

// File actions in FILE_NOTIFY_INFORMATION (winnt.h).
const (
	actionAdded          = 1
	actionRemoved        = 2
	actionModified       = 3
	actionRenamedOldName = 4
	actionRenamedNewName = 5
)

// Parser turns ReadDirectoryChangesW buffers into Kinds. It keeps one
// name between calls, the old half of a rename whose new half is still to
// come, and nothing else.
type Parser struct {
	pendingOld  string
	havePending bool
}

// Parse classifies one buffer of FILE_NOTIFY_INFORMATION records
// (NextEntryOffset, Action, FileNameLength, then the UTF-16LE name) and
// calls add for each change. A malformed buffer is read as far as it is
// well formed; the rest counts as Unknown.
func (p *Parser) Parse(buf []byte, add func(Kind)) {
	off := 0
	for {
		if off+12 > len(buf) {
			if off < len(buf) {
				add(Unknown)
			}
			return
		}
		next := int(le32(buf[off:]))
		action := le32(buf[off+4:])
		n := int(le32(buf[off+8:]))
		if n < 0 || n%2 != 0 || off+12+n > len(buf) {
			add(Unknown)
			return
		}
		name := utf16Name(buf[off+12 : off+12+n])
		p.classify(action, name, add)
		if next == 0 {
			return
		}
		if next < 12+n || off+next > len(buf) {
			add(Unknown)
			return
		}
		off += next
	}
}

// Flush ends a batch: an old name whose new half never came was moved out
// of the watched folders.
func (p *Parser) Flush(add func(Kind)) {
	if p.havePending {
		add(Renamed)
		p.pendingOld, p.havePending = "", false
	}
}

func (p *Parser) classify(action uint32, name string, add func(Kind)) {
	if action != actionRenamedNewName && p.havePending {
		add(Renamed) // the old half of a rename moved out of view
		p.pendingOld, p.havePending = "", false
	}
	switch action {
	case actionAdded:
		add(ClassifyCreate(name))
	case actionRemoved:
		add(Deleted)
	case actionModified:
		add(Modified)
	case actionRenamedOldName:
		p.pendingOld, p.havePending = name, true
	case actionRenamedNewName:
		if p.havePending {
			add(ClassifyRename(p.pendingOld, name))
		} else {
			add(Renamed) // moved in from outside
		}
		p.pendingOld, p.havePending = "", false
	default:
		add(Unknown)
	}
}

func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// utf16Name decodes a UTF-16LE name. Unpaired surrogates become U+FFFD;
// the result is only ever compared in memory.
func utf16Name(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	return string(utf16.Decode(u))
}
