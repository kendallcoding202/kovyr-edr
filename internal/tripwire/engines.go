package tripwire

import (
	"strings"
	"sync"
)

// engineImages are the process image names of sync and backup engines
// whose bulk writes look like ransomware to a file watcher. A burst is
// suppressed only when one of them is running and wrote at least as often
// as files changed during the window (Detector.byEngine). Names marked
// unverified are from vendor documentation, not yet seen on a real
// install; confirm them like the EDR service names.
var engineImages = map[string]bool{
	"onedrive.exe":               true, // Microsoft OneDrive
	"filecoauth.exe":             true, // Office co-authoring with OneDrive/SharePoint
	"dropbox.exe":                true, // Dropbox
	"googledrivefs.exe":          true, // Google Drive for desktop
	"googledrivesync.exe":        true, // Backup and Sync (retired, still installed in places)
	"box.exe":                    true, // Box Drive (unverified)
	"icloudservices.exe":         true, // iCloud for Windows (unverified)
	"icloudckks.exe":             true, // iCloud for Windows (unverified)
	"bztransmit64.exe":           true, // Backblaze (unverified)
	"carboniteservice.exe":       true, // Carbonite (unverified)
	"code42service.exe":          true, // CrashPlan / Code42 (unverified)
	"veeam.endpoint.service.exe": true, // Veeam Agent for Windows (unverified)
	"tib_mounter_monitor.exe":    true, // Acronis True Image (unverified)
	"syncthing.exe":              true, // Syncthing
	"nextcloud.exe":              true, // Nextcloud desktop
	"owncloud.exe":               true, // ownCloud desktop
}

// IsEngine reports whether a process image name is a known sync or
// backup engine. The name is compared in memory and never stored.
func IsEngine(image string) bool { return engineImages[strings.ToLower(image)] }

// FakeEngines is an Engines for tests.
type FakeEngines struct {
	mu      sync.Mutex
	ops     uint64
	running bool
}

// WriteOps implements Engines.
func (f *FakeEngines) WriteOps() (uint64, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ops, f.running
}

// Write records engine writes (and that an engine runs).
func (f *FakeEngines) Write(n uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ops += n
	f.running = true
}
