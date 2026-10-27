// Package sample generates the demo: a fictional firm's month of statements
// run through the real ingest server, timestamp authorities, log and
// witnesses, plus the attack scenarios the demo page lets people try.
package sample

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kendallcoding202/kovyr-edr/proof/keys"
	"github.com/kendallcoding202/kovyr-edr/proof/sigs"
)

// DemoWarning is written into every demo key file.
const DemoWarning = "DEMO KEY. Published on purpose so the sample can be regenerated. Anyone can sign with it. Never use it for real data."

// Keys holds every key the demo world uses.
type Keys struct {
	Log       *keys.KeyFile
	Scanner   *keys.KeyFile // the vendor's service key for external scans, shared by all firms
	Witnesses []*keys.KeyFile
	TSAs      []*keys.KeyFile
	Firms     []FirmKeys // Firms[0] is the sample firm; the rest share the log
}

// FirmKeys are one firm's keys.
type FirmKeys struct {
	Tenant    *keys.KeyFile
	Connector *keys.KeyFile
	Staff     *keys.KeyFile
	Devices   []*keys.KeyFile
}

// Sizes of the demo world.
const (
	sampleDevices = 12
	witnessCount  = 3
)

var otherFirmDevices = []int{6, 4}

// GenerateKeys creates a fresh set of software keys.
func GenerateKeys() (*Keys, error) {
	gen := func(alg sigs.Alg, role, name string) *keys.KeyFile {
		kf, err := keys.Generate(alg, role, name)
		if err != nil {
			panic(err)
		}
		kf.DemoOnly, kf.Warning = true, DemoWarning
		return kf
	}
	k := &Keys{Log: gen(sigs.Ed25519, "log", "log"), Scanner: gen(sigs.Ed25519, "scanner", "scanner")}
	for i := 0; i < witnessCount; i++ {
		k.Witnesses = append(k.Witnesses, gen(sigs.Ed25519, "witness", fmt.Sprintf("witness-%c", 'a'+i)))
	}
	for i := 0; i < 2; i++ {
		k.TSAs = append(k.TSAs, gen(sigs.Ed25519, "tsa", fmt.Sprintf("tsa-%c", 'a'+i)))
	}
	counts := append([]int{sampleDevices}, otherFirmDevices...)
	for f, n := range counts {
		fk := FirmKeys{
			Tenant:    gen(sigs.ES256, "tenant", fmt.Sprintf("firm%d-tenant", f)),
			Connector: gen(sigs.Ed25519, "connector", fmt.Sprintf("firm%d-connector", f)),
			Staff:     gen(sigs.ES256, "staff", fmt.Sprintf("firm%d-staff", f)),
		}
		for d := 1; d <= n; d++ {
			fk.Devices = append(fk.Devices, gen(sigs.ES256, "device", fmt.Sprintf("firm%d-device%02d", f, d)))
		}
		k.Firms = append(k.Firms, fk)
	}
	return k, nil
}

func (k *Keys) all() []*keys.KeyFile {
	out := append([]*keys.KeyFile{k.Log, k.Scanner}, k.Witnesses...)
	out = append(out, k.TSAs...)
	for _, f := range k.Firms {
		out = append(out, f.Tenant, f.Connector, f.Staff)
		out = append(out, f.Devices...)
	}
	return out
}

// Save writes every key to dir as <name>.key.json.
func (k *Keys) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, kf := range k.all() {
		if err := kf.Save(filepath.Join(dir, kf.Name+".key.json")); err != nil {
			return err
		}
	}
	return nil
}

// LoadKeys reads a key set written by Save.
func LoadKeys(dir string) (*Keys, error) {
	load := func(name string) (*keys.KeyFile, error) {
		kf, err := keys.Load(filepath.Join(dir, name+".key.json"))
		if err != nil {
			return nil, err
		}
		if !kf.DemoOnly {
			return nil, errors.New(name + ": the generator only uses keys marked demo_only")
		}
		return kf, nil
	}
	var err error
	k := &Keys{}
	if k.Log, err = load("log"); err != nil {
		return nil, err
	}
	if k.Scanner, err = load("scanner"); err != nil {
		return nil, err
	}
	for i := 0; i < witnessCount; i++ {
		w, err := load(fmt.Sprintf("witness-%c", 'a'+i))
		if err != nil {
			return nil, err
		}
		k.Witnesses = append(k.Witnesses, w)
	}
	for i := 0; i < 2; i++ {
		t, err := load(fmt.Sprintf("tsa-%c", 'a'+i))
		if err != nil {
			return nil, err
		}
		k.TSAs = append(k.TSAs, t)
	}
	counts := append([]int{sampleDevices}, otherFirmDevices...)
	for f, n := range counts {
		var fk FirmKeys
		if fk.Tenant, err = load(fmt.Sprintf("firm%d-tenant", f)); err != nil {
			return nil, err
		}
		if fk.Connector, err = load(fmt.Sprintf("firm%d-connector", f)); err != nil {
			return nil, err
		}
		if fk.Staff, err = load(fmt.Sprintf("firm%d-staff", f)); err != nil {
			return nil, err
		}
		for d := 1; d <= n; d++ {
			dk, err := load(fmt.Sprintf("firm%d-device%02d", f, d))
			if err != nil {
				return nil, err
			}
			fk.Devices = append(fk.Devices, dk)
		}
		k.Firms = append(k.Firms, fk)
	}
	return k, nil
}

func mustSigner(kf *keys.KeyFile) sigs.Signer {
	s, err := kf.Signer()
	if err != nil {
		panic(err)
	}
	return s
}

func mustEd25519(kf *keys.KeyFile) ed25519.PrivateKey {
	cs, err := kf.CryptoSigner()
	if err != nil {
		panic(err)
	}
	return cs.(ed25519.PrivateKey)
}
