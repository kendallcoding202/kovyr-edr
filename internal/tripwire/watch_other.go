//go:build !windows

package tripwire

import "github.com/kendallcoding202/kovyr-edr/internal/proof"

// Watch is a running watcher. Outside Windows there is none.
type Watch struct{}

// Start reports the tripwire as not applicable: it watches Windows
// folders only.
func Start(folders []string, det *Detector, logf func(string, ...any)) (*Watch, error) {
	det.SetState(proof.AvailNotApplicable, 0)
	return &Watch{}, nil
}

// Close does nothing.
func (w *Watch) Close() {}

// UserFolders is empty outside Windows.
func UserFolders() []string { return nil }

// SystemEngines has no engines outside Windows.
func SystemEngines() Engines { return nil }
