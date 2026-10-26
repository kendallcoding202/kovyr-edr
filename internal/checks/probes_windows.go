package checks

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/mgr"
)

// SystemProbes returns the real Windows probes. Every probe is a read:
// WQL SELECTs, registry reads with QUERY_VALUE, and a service list taken
// with SC_MANAGER_CONNECT|SC_MANAGER_ENUMERATE_SERVICE only.
func SystemProbes() Probes { return windowsProbes{} }

type windowsProbes struct{}

func (windowsProbes) AVProductStates() ([]uint32, error) {
	var rows []struct{ ProductState *uint32 }
	// Not on Windows Server (incl. CI runners): invalid namespace, which
	// classifyWMI turns into ErrNotApplicable.
	if err := wmiQuery(`root\SecurityCenter2`, "SELECT productState FROM AntiVirusProduct", &rows); err != nil {
		return nil, err
	}
	out := make([]uint32, 0, len(rows))
	for _, r := range rows {
		if r.ProductState == nil {
			out = append(out, unknownProductState)
			continue
		}
		out = append(out, *r.ProductState)
	}
	return out, nil
}

func (windowsProbes) DefenderStatus() (DefenderStatus, error) {
	// SELECT * so a property missing on an older Defender platform (for
	// example IsTamperProtected) is a nil field, not an invalid query.
	var rows []DefenderStatus
	if err := wmiQuery(`root\Microsoft\Windows\Defender`, "SELECT * FROM MSFT_MpComputerStatus", &rows); err != nil {
		return DefenderStatus{}, err
	}
	if len(rows) == 0 {
		return DefenderStatus{}, ErrNotFound
	}
	return rows[0], nil
}

func (windowsProbes) Services() ([]Service, error) {
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return nil, classifyWin(err)
	}
	m := &mgr.Mgr{Handle: h}
	defer m.Disconnect()
	return listServices(m)
}

// listServices is mgr.ListServices keeping each service's state: the
// state comes from the same EnumServicesStatusEx call, so we never open a
// service (EDR self-protection may refuse that).
func listServices(m *mgr.Mgr) ([]Service, error) {
	var bytesNeeded, returned uint32
	var buf []byte
	for {
		var p *byte
		if len(buf) > 0 {
			p = &buf[0]
		}
		err := windows.EnumServicesStatusEx(m.Handle, windows.SC_ENUM_PROCESS_INFO,
			windows.SERVICE_WIN32, windows.SERVICE_STATE_ALL,
			p, uint32(len(buf)), &bytesNeeded, &returned, nil, nil)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_MORE_DATA) || bytesNeeded <= uint32(len(buf)) || bytesNeeded > 16<<20 {
			return nil, classifyWin(err)
		}
		buf = make([]byte, bytesNeeded)
	}
	if returned == 0 {
		return nil, nil
	}
	entries := unsafe.Slice((*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buf[0])), int(returned))
	var out []Service
	for _, e := range entries {
		name := windows.UTF16PtrToString(e.ServiceName)
		if _, ok := VendorForService(name); !ok {
			continue // other services' names are not kept
		}
		out = append(out, Service{Name: name, Running: e.ServiceStatusProcess.CurrentState == windows.SERVICE_RUNNING})
	}
	return out, nil
}

func (windowsProbes) OSVolumeProtectionStatus() (uint32, error) {
	// VolumeType 0 is the OS volume. Needs administrator rights: otherwise
	// access denied, reported as unknown.
	var rows []struct{ ProtectionStatus *uint32 }
	err := wmiQuery(`root\CIMV2\Security\MicrosoftVolumeEncryption`,
		"SELECT ProtectionStatus FROM Win32_EncryptableVolume WHERE VolumeType = 0", &rows)
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 || rows[0].ProtectionStatus == nil {
		return 0, ErrNotFound
	}
	return *rows[0].ProtectionStatus, nil
}

// Firewall registry locations. Group Policy writes under Policies and
// overrides the local setting. The local key calls the private profile
// "StandardProfile".
// TODO: Intune (MDM) firewall policy is stored separately and is not read
// yet; on MDM-managed machines the local value may not be effective.
const (
	fwPolicyBase = `SOFTWARE\Policies\Microsoft\WindowsFirewall\`
	fwLocalBase  = `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\`
)

func (windowsProbes) Firewall() (FirewallSettings, error) {
	var s FirewallSettings
	var err error
	read := func(path string) *uint32 {
		if err != nil {
			return nil
		}
		v, e := readDWORD(path, "EnableFirewall")
		switch {
		case e == nil:
			return &v
		case errors.Is(e, ErrNotFound):
			return nil
		}
		err = e
		return nil
	}
	s.Domain = FirewallProfile{Policy: read(fwPolicyBase + "DomainProfile"), Local: read(fwLocalBase + "DomainProfile")}
	s.Private = FirewallProfile{Policy: read(fwPolicyBase + "PrivateProfile"), Local: read(fwLocalBase + "StandardProfile")}
	s.Public = FirewallProfile{Policy: read(fwPolicyBase + "PublicProfile"), Local: read(fwLocalBase + "PublicProfile")}
	return s, err
}

func (windowsProbes) DriverBlocklist() (uint32, error) {
	return readDWORD(`SYSTEM\CurrentControlSet\Control\CI\Config`, "VulnerableDriverBlocklistEnable")
}

func (windowsProbes) DeviceGuardServicesRunning() ([]uint32, error) {
	// uint32[] arrives as a VT_I4 SAFEARRAY, so it is read as []int32.
	var rows []struct{ SecurityServicesRunning []int32 }
	if err := wmiQuery(`root\Microsoft\Windows\DeviceGuard`, "SELECT SecurityServicesRunning FROM Win32_DeviceGuard", &rows); err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, ErrNotFound
	}
	out := make([]uint32, 0, len(rows[0].SecurityServicesRunning))
	for _, v := range rows[0].SecurityServicesRunning {
		out = append(out, uint32(v))
	}
	return out, nil
}

// readDWORD reads an HKLM DWORD from the 64-bit registry view, read-only.
func readDWORD(path, name string) (uint32, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return 0, classifyWin(err)
	}
	defer k.Close()
	v, typ, err := k.GetIntegerValue(name)
	if err != nil {
		return 0, classifyWin(err)
	}
	if typ != registry.DWORD || v > 0xFFFFFFFF {
		return 0, fmt.Errorf("registry value has type %d", typ)
	}
	return uint32(v), nil
}

func classifyWin(err error) error {
	switch {
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return fmt.Errorf("%w: %v", ErrAccessDenied, err)
	case errors.Is(err, windows.ERROR_FILE_NOT_FOUND), errors.Is(err, windows.ERROR_PATH_NOT_FOUND):
		return fmt.Errorf("%w: %v", ErrNotFound, err)
	}
	return err
}
