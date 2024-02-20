//go:build !windows

package kpx

import (
	"encoding/base64"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/palantir/stacktrace"
	"net"
	"os"
	"os/user"
	"strings"
	"sync"
)

var NativeKerberos = &LinuxKerberos{}

type LinuxKerberos struct {
	mutex sync.Mutex
	cfg   *config.Config
}

func (k *LinuxKerberos) SafeTryLogin() error {
	k.mutex.Lock()
	defer k.mutex.Unlock()

	if k.cfg != nil {
		return nil
	}

	logInfo("[-] Authenticating user with Linux native kerberos")

	var err error

	err = k.makeCfg()
	if err != nil {
		return stacktrace.Propagate(err, "unable to acquire kerberos config from Linux")
	}

	_, err = k.makeClient()
	if err != nil {
		return stacktrace.Propagate(err, "unable to acquire kerberos ccache from Linux")
	}

	return nil
}

func (k *LinuxKerberos) SafeGetToken(protocol string, host string) (*string, error) {
	err := k.makeCfg()
	if err != nil {
		return nil, stacktrace.Propagate(err, "unable to acquire kerberos config from Linux")
	}
	kcl, err := k.makeClient()
	if err != nil {
		return nil, stacktrace.Propagate(err, "unable to acquire kerberos ccache from Linux")
	}
	cname, err := k.getCanonicalHostname(host)
	if err != nil {
		return nil, stacktrace.Propagate(err, "unable to resolve host from hostname: %s", host)
	}
	spn := protocol + "/" + cname
	nego := spnego.SPNEGOClient(kcl, spn)
	err = nego.AcquireCred()
	if err != nil {
		return nil, stacktrace.Propagate(err, "unable to acquire client credential from Linux for spn: %s", spn)
	}
	sec, err := nego.InitSecContext()
	if err != nil {
		return nil, stacktrace.Propagate(err, "unable to initialize security context from Linux for spn: %s", spn)
	}
	nb, err := sec.Marshal()
	if err != nil {
		return nil, stacktrace.Propagate(err, "unable to marshal security token from Linux for spn: %s", spn)
	}
	hs := base64.StdEncoding.EncodeToString(nb)
	return &hs, nil
}

func (k *LinuxKerberos) getCanonicalHostname(hostname string) (string, error) {
	cname, err := net.LookupCNAME(hostname)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(cname, "."), nil
}

func (k *LinuxKerberos) makeCfg() error {
	k.mutex.Lock()
	defer k.mutex.Unlock()

	if k.cfg != nil {
		return nil
	}

	// Macs and Windows have different path, also some Unix may have /etc/krb5/krb5.conf
	cfgPath := os.Getenv("KRB5_CONFIG")
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		cfgPath = "/etc/krb5.conf"
	}
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		cfgPath = "/etc/krb5/krb5.conf"
	}

	// Load config
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}

	k.cfg = cfg
	return nil
}

func (k *LinuxKerberos) makeClient() (*client.Client, error) {
	u, err := user.Current()
	if err != nil {
		return nil, err
	}

	ccPath := "/tmp/krb5cc_" + u.Uid

	// Only support KRB5CCNAME as FILE: path to use another path than default /tmp
	ccName := os.Getenv("KRB5CCNAME")
	if strings.HasPrefix(ccName, "FILE:") {
		ccPath = strings.SplitN(ccName, ":", 2)[1]
	}

	cCache, err := credentials.LoadCCache(ccPath)
	if err != nil {
		return nil, err
	}

	kcl, err := client.NewFromCCache(cCache, k.cfg, client.DisablePAFXFAST(true))
	if err != nil {
		return nil, err
	}

	return kcl, nil
}
