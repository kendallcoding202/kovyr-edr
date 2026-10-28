package tripwire

import (
	"errors"
	"testing"
)

func TestCheckOpened(t *testing.T) {
	const dir, reparse = fileAttributeDirectory, fileAttributeReparsePoint
	for _, c := range []struct {
		name       string
		attrs, tag uint32
		want       error
	}{
		{"plain folder", dir, 0, nil},
		{"read-only folder", dir | 0x1, 0, nil},
		{"junction", dir | reparse, 0xA0000003, errLink},
		{"directory symbolic link", dir | reparse, 0xA000000C, errLink},
		{"other name surrogate", dir | reparse, 0x20000099, errLink},
		{"OneDrive placeholder folder", dir | reparse, 0x9000601A, nil},
		{"deduplicated", dir | reparse, 0x80000013, nil},
		{"a file", 0x20, 0, errNotAFolder},
		{"a file link", reparse, 0xA000000C, errNotAFolder},
	} {
		if got := checkOpened(c.attrs, c.tag); !errors.Is(got, c.want) && got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func TestSamePath(t *testing.T) {
	same := [][2]string{
		{`C:\Users\maria\Documents`, `\\?\C:\Users\maria\Documents`},
		{`c:\users\Maria\documents`, `\\?\C:\Users\maria\Documents`},
		{`C:\Users\maria\Documents\`, `\\?\C:\Users\maria\Documents`},
		{`C:/Users/maria/Documents`, `\\?\C:\Users\maria\Documents`},
		{`C:\`, `\\?\C:\`},
		{`\\fileserver\clients\2026`, `\\?\UNC\fileserver\clients\2026`},
	}
	for _, c := range same {
		if !samePath(c[0], c[1]) {
			t.Errorf("%s and %s should be the same folder", c[0], c[1])
		}
	}
	different := [][2]string{
		// Documents replaced by a junction to the whole drive, or a
		// folder on the way that leads elsewhere.
		{`C:\Users\maria\Documents`, `\\?\C:\`},
		{`C:\Users\maria\Documents`, `\\?\C:\Windows`},
		{`D:\Shared\Clients`, `\\?\C:\Windows\Clients`},
		{`C:\Users\maria\Documents`, `\\?\C:\Users\maria\Documents\inner`},
		{`C:\Users\maria\Documents`, `\\?\C:\Users\maria`},
		{`C:\`, `\\?\D:\`},
		{`\\fileserver\clients`, `\\?\UNC\otherserver\clients`},
		{`C:\Users\maria\Documents`, `\\?\UNC\C:\Users\maria\Documents`},
	}
	for _, c := range different {
		if samePath(c[0], c[1]) {
			t.Errorf("%s and %s should differ", c[0], c[1])
		}
	}
}
