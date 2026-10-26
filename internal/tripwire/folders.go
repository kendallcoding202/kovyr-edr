package tripwire

import (
	"path/filepath"
	"strings"
)

// Folders prepares a watch list: it drops duplicates and folders inside
// another listed folder (a watch covers its subfolders, so they would be
// counted twice), keeps the order, and stops at MaxFolders. Paths compare
// without regard to case, as on Windows.
func Folders(list []string) []string {
	keys := make([]string, len(list))
	for i, f := range list {
		keys[i] = strings.ToLower(filepath.Clean(f))
	}
	inside := func(child, parent string) bool {
		return child == parent ||
			strings.HasPrefix(child, strings.TrimSuffix(parent, string(filepath.Separator))+string(filepath.Separator))
	}
	var out []string
	for i, f := range list {
		keep := f != ""
		for j := 0; keep && j < len(list); j++ {
			// An exact duplicate keeps its first entry; a nested folder
			// gives way to the folder that holds it.
			if j != i && list[j] != "" && inside(keys[i], keys[j]) && (keys[i] != keys[j] || j < i) {
				keep = false
			}
		}
		if keep {
			out = append(out, f)
		}
		if len(out) == MaxFolders {
			break
		}
	}
	return out
}
