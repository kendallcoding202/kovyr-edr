module github.com/kendallcoding202/kovyr-edr

go 1.27.3

require (
	github.com/go-ole/go-ole v1.3.0
	github.com/yusufpapurcu/wmi v1.2.4
	golang.org/x/sys v0.49.0
)

// Since Go 1.27, an SSL_CERT_FILE or SSL_CERT_DIR environment variable
// replaces the Windows certificate store. The agent keeps trusting only
// the Windows store (checked by .github/scripts/check-policy.sh).
godebug x509sslcertoverrideplatform=0
