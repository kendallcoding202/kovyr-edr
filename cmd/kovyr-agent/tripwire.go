package main

import (
	"errors"
	"path/filepath"
	"strings"

	"github.com/kendallcoding202/kovyr-edr/internal/agent"
	"github.com/kendallcoding202/kovyr-edr/internal/config"
	"github.com/kendallcoding202/kovyr-edr/internal/proof"
	"github.com/kendallcoding202/kovyr-edr/internal/tripwire"
)

// userFolders is replaced in tests.
var userFolders = tripwire.UserFolders

// startTripwire starts the ransomware tripwire on the configured folders
// and, when asked, each user's Desktop and Documents. It never stops the
// agent: a tripwire that cannot start is reported as unknown. It logs
// counts, never paths (they hold user names). The returned function stops
// it.
func startTripwire(t config.Tripwire, logf func(string, ...any)) (agent.Tripwire, func()) {
	if !t.Enabled {
		logf("tripwire: turned off in the settings (reported as unknown)")
		return nil, func() {}
	}
	all := append([]string(nil), t.Folders...)
	if t.UserFolders {
		all = append(all, userFolders()...)
	}
	folders := tripwire.Folders(all)
	det, err := tripwire.NewDetector(t.Thresholds(), tripwire.SystemEngines(), nil)
	if err != nil {
		logf("tripwire: %v", err)
		return nil, func() {}
	}
	w, err := tripwire.Start(folders, det, logf)
	if err != nil {
		logf("tripwire: cannot start (%v)", err)
		return det, func() {}
	}
	switch tw, _ := det.Snapshot(); tw.State {
	case proof.AvailNotApplicable:
		logf("tripwire: not available on this system")
	default:
		logf("tripwire: watching %d folder(s) of %d listed (read-only; it reports and takes no action)", tw.FoldersWatched, len(all))
	}
	return det, w.Close
}

// folderList is a repeatable --watch flag.
type folderList []string

func (f *folderList) String() string { return strings.Join(*f, ",") }

// Set takes a folder, made absolute (the service does not run in this
// console's folder).
func (f *folderList) Set(v string) error {
	if v == "" {
		return errors.New("empty folder")
	}
	abs, err := filepath.Abs(v)
	if err != nil {
		return err
	}
	*f = append(*f, abs)
	return nil
}
