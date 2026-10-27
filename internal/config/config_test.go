package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kendallcoding202/kovyr-edr/internal/agent"
	"github.com/kendallcoding202/kovyr-edr/internal/tripwire"
)

func valid() Settings {
	s := Defaults()
	s.Server = "https://halden.example"
	return s
}

func TestDefaultsAreSafeAndValid(t *testing.T) {
	s := valid()
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	th, err := s.Throttle().WithDefaults()
	if err != nil {
		t.Fatal(err)
	}
	if th.BatteryIntervalFactor != 2 || th.KeepHeavyOnBattery || th.BusyPercent != 80 || th.Window != time.Minute ||
		th.DeferStep != time.Minute || th.MaxDefer != 5*time.Minute || s.Interval() != agent.DefaultInterval {
		t.Fatalf("defaults %+v", th)
	}
	if s.Log.MaxFileBytes != 1<<20 || s.Log.Files != 5 {
		t.Fatalf("log defaults %+v", s.Log)
	}
	if !s.Tripwire.Enabled || !s.Tripwire.UserFolders || len(s.Tripwire.Folders) != 0 {
		t.Fatalf("tripwire defaults %+v", s.Tripwire)
	}
	def, _ := tripwire.Thresholds{}.WithDefaults()
	if s.Tripwire.Thresholds() != def {
		t.Fatalf("tripwire thresholds %+v, want the detector's defaults %+v", s.Tripwire.Thresholds(), def)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := valid()
	s.IntervalS = 600
	s.Tripwire.Folders = []string{filepath.Join(dir, "Client Files")}
	s.Tripwire.MinActivity = 200
	if err := Write(dir, s); err != nil {
		t.Fatal(err)
	}
	got, err := Read(dir)
	if err != nil || !reflect.DeepEqual(got, s) {
		t.Fatalf("got %+v %v", got, err)
	}
}

func TestMissingFieldsKeepTheirDefaults(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(Path(dir), []byte(`{"server":"https://halden.example","load":{"busy_percent":90}}`), 0o600)
	s, err := Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := valid()
	want.Load.BusyPercent = 90
	if !reflect.DeepEqual(s, want) {
		t.Fatalf("got %+v", s)
	}
}

func TestBadSettingsAreRefused(t *testing.T) {
	for name, body := range map[string]string{
		"typo":            `{"server":"https://halden.example","intreval_s":60}`,
		"no server":       `{}`,
		"plain http":      `{"server":"http://halden.example"}`,
		"dev http remote": `{"server":"http://192.168.1.5:8787","dev_insecure":true}`,
		"interval 10s":    `{"server":"https://halden.example","interval_s":10}`,
		"interval 2h":     `{"server":"https://halden.example","interval_s":7200}`,
		"factor 9":        `{"server":"https://halden.example","battery":{"interval_factor":9}}`,
		"busy 10":         `{"server":"https://halden.example","load":{"busy_percent":10}}`,
		"no window":       `{"server":"https://halden.example","load":{"window_s":-1}}`,
		"huge logs":       `{"server":"https://halden.example","log":{"max_file_bytes":1073741824}}`,
		"100 log files":   `{"server":"https://halden.example","log":{"files":100}}`,
		"two objects":     `{"server":"https://halden.example"}{}`,
		"a command":       `{"server":"https://halden.example","run":"powershell -c evil"}`,
		"too big":         `{"server":"https://halden.example","x":"` + strings.Repeat("a", 20<<10) + `"}`,
		"zero window":     `{"server":"https://halden.example","tripwire":{"window_s":0}}`,
		"window 45s":      `{"server":"https://halden.example","tripwire":{"window_s":45}}`,
		"min activity 5":  `{"server":"https://halden.example","tripwire":{"min_activity":5}}`,
		"negative notes":  `{"server":"https://halden.example","tripwire":{"notes_activity":-3}}`,
		"huge cooldown":   `{"server":"https://halden.example","tripwire":{"cooldown_s":4294967297}}`,
		"share 0":         `{"server":"https://halden.example","tripwire":{"extension_changed_percent":0}}`,
		"relative folder": `{"server":"https://halden.example","tripwire":{"folders":["Documents"]}}`,
		"17 folders":      `{"server":"https://halden.example","tripwire":{"folders":[` + strings.Repeat(`"/a",`, 16) + `"/a"]}}`,
		"long folder":     `{"server":"https://halden.example","tripwire":{"folders":["/` + strings.Repeat("a", 600) + `"]}}`,
		"tripwire typo":   `{"server":"https://halden.example","tripwire":{"enable":false}}`,
		"activity wraps":  `{"server":"https://halden.example","tripwire":{"min_activity":4294967396}}`,
		"NUL in folder":   `{"server":"https://halden.example","tripwire":{"folders":["/a\u0000b"]}}`,
	} {
		dir := t.TempDir()
		os.WriteFile(Path(dir), []byte(body), 0o600)
		if _, err := Read(dir); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := Write(t.TempDir(), Defaults()); err == nil {
		t.Error("saved settings without a server")
	}
}

func TestTripwireCanBeTurnedOff(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(Path(dir), []byte(`{"server":"https://halden.example","tripwire":{"enabled":false,"user_folders":false}}`), 0o600)
	s, err := Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.Tripwire.Enabled || s.Tripwire.UserFolders || s.Tripwire.MinActivity != tripwire.DefaultMinActivity {
		t.Fatalf("got %+v", s.Tripwire)
	}
}

// A refused folder is named by its number, never by its path.
func TestFolderErrorsDoNotEchoThePath(t *testing.T) {
	s := valid()
	s.Tripwire.Folders = []string{"Users/jane.doe/Taxes"}
	err := s.Validate()
	if err == nil || strings.Contains(err.Error(), "jane") || !strings.Contains(err.Error(), "folder 1") {
		t.Fatalf("error %v", err)
	}
}
