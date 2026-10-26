package config

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kendallcoding202/kovyr-edr/internal/agent"
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
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := valid()
	s.IntervalS = 600
	if err := Write(dir, s); err != nil {
		t.Fatal(err)
	}
	got, err := Read(dir)
	if err != nil || got != s {
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
	if s != want {
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
