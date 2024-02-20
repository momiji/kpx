//go:build windows

package kpx

import (
	"encoding/base64"
	"github.com/alexbrainman/sspi"
	"github.com/alexbrainman/sspi/negotiate"
	"github.com/palantir/stacktrace"
	"net"
	"strings"
	"sync"
)

var NativeKerberos = &WindowsKerberos{}

type WindowsKerberos struct {
	done  bool
	mutex sync.Mutex
}

func (k *WindowsKerberos) SafeTryLogin() error {
	k.mutex.Lock()
	defer k.mutex.Unlock()
	if k.done {
		return nil
	}
	k.done = true
	logInfo("[-] Authenticating user with Windows native kerberos")
	_, err := negotiate.AcquireCurrentUserCredentials()
	if err != nil {
		return stacktrace.Propagate(err, "unable to acquire kerberos credentials from Windows")
	}
	return nil
}

func (k *WindowsKerberos) SafeGetToken(protocol string, host string) (*string, error) {
	cred, err := negotiate.AcquireCurrentUserCredentials()
	if err != nil {
		return nil, stacktrace.Propagate(err, "unable to acquire kerberos credentials from Windows")
	}
	defer func(cred *sspi.Credentials) {
		_ = cred.Release()
	}(cred)
	cname, err := k.getCanonicalHostname(host)
	if err != nil {
		return nil, stacktrace.Propagate(err, "unable to resolve host from hostname: %s", host)
	}
	spn := protocol + "/" + cname
	sec, token, err := negotiate.NewClientContext(cred, spn)
	if err != nil {
		return nil, stacktrace.Propagate(err, "unable to acquire kerberos client context from Windows for spn: %s", spn)
	}
	defer func(sec *negotiate.ClientContext) {
		_ = sec.Release()
	}(sec)
	hs := base64.StdEncoding.EncodeToString(token)
	return &hs, nil
}

func (k *WindowsKerberos) getCanonicalHostname(hostname string) (string, error) {
	cname, err := net.LookupCNAME(hostname)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(cname, "."), nil
}
