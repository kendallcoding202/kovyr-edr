package checks

import (
	"errors"
	"fmt"

	"github.com/go-ole/go-ole"
	"github.com/yusufpapurcu/wmi"
)

// WMI HRESULTs that classify a failure.
const (
	wbemEInvalidNamespace           = 0x8004100E
	wbemEInvalidClass               = 0x80041010
	wbemENotFound                   = 0x80041002
	wbemEAccessDenied               = 0x80041003
	eAccessDenied                   = 0x80070005
	wbemEEncryptedConnectionRequire = 0x80041087
)

// wmiClient returns NULL properties as nil pointers and tolerates missing
// properties, so either becomes "unknown" instead of an error.
var wmiClient = &wmi.Client{PtrNil: true, AllowMissingFields: true}

// wmiQuery runs a read-only WQL SELECT in namespace. The WMI library
// serializes queries; Runner bounds how long we wait for them.
func wmiQuery(namespace, query string, dst any) error {
	if err := wmiClient.Query(query, dst, nil, namespace); err != nil {
		return classifyWMI(err)
	}
	return nil
}

// classifyWMI maps a COM error to a probe error class. The HRESULT is in
// the OleError or, for DISP_E_EXCEPTION, in the EXCEPINFO scode.
func classifyWMI(err error) error {
	var code uint32
	var oe *ole.OleError
	if errors.As(err, &oe) {
		code = uint32(oe.Code())
		if ex, ok := oe.SubError().(ole.EXCEPINFO); ok && ex.SCODE() != 0 {
			code = ex.SCODE()
		}
	}
	switch code {
	case wbemEInvalidNamespace, wbemEInvalidClass:
		return fmt.Errorf("%w (0x%08x)", ErrNotApplicable, code)
	case wbemEAccessDenied, eAccessDenied:
		return fmt.Errorf("%w (0x%08x)", ErrAccessDenied, code)
	case wbemEEncryptedConnectionRequire:
		return fmt.Errorf("%w (0x%08x)", ErrEncryptionRequired, code)
	case wbemENotFound:
		return fmt.Errorf("%w (0x%08x)", ErrNotFound, code)
	}
	if code != 0 {
		return fmt.Errorf("wmi: 0x%08x", code)
	}
	return fmt.Errorf("wmi: %T", err) // never the message: it is not needed and could carry machine text
}
