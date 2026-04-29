package auth

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/momiji/kpx/log"
	"github.com/momiji/kpx/utils"
	"github.com/palantir/stacktrace"
)

type KerberosConfig struct {
	KrbString       string
	DefaultDomain   string
	DomainMapper    map[string]*string
	KdcConnTimeout  time.Duration
	KdcCacheTimeout time.Duration
}

type Kerberos struct {
	config       *KerberosConfig
	krbCfg       *config.Config // all calls to NewWithPassword use a copy of this
	explodedKdcs map[string]*Kdc
	explodeMutex sync.Mutex
	logger       log.Logger
}

type Kdc struct {
	kdcs []string
	next time.Time
}

func NewKerberos(krbConfig *KerberosConfig, logger log.Logger) (*Kerberos, error) {
	krbCfg, err := config.NewFromString(krbConfig.KrbString)
	if err != nil {
		return nil, stacktrace.Propagate(err, "Kerberos error, unable to create config")
	}
	// fix KDC list by extending KDC list with server ip, when it contains alpha characters
	for i, realm := range krbCfg.Realms {
		// backup KDC
		realm.KPasswdServer = realm.KDC
		// update
		krbCfg.Realms[i] = realm
	}
	return &Kerberos{
		config:       krbConfig,
		krbCfg:       krbCfg,
		explodedKdcs: make(map[string]*Kdc),
		logger:       logger,
	}, nil
}

func (k *Kerberos) explodeKdcs(realmKdcs []string) []string {
	k.explodeMutex.Lock()
	defer k.explodeMutex.Unlock()
	key := fmt.Sprintf("%v", realmKdcs)
	val := k.explodedKdcs[key]
	if val != nil {
		if len(val.kdcs) > 0 || time.Now().Before(val.next) {
			return val.kdcs
		}
	}
	newKdcs := make([]string, 0)
	for _, kdcs := range realmKdcs {
		for _, kdc := range strings.Split(kdcs, " ") {
			kdc = strings.TrimSpace(kdc)
			if strings.ContainsAny(strings.ToLower(kdc), "abcdefghijklmnopqrstuvwxyz") {
				host, port := utils.SplitHostPort(kdc, "127.0.0.1", "88", false)
				ips, err := net.LookupHost(host)
				if err != nil {
					newKdcs = append(newKdcs, host+":"+port)
				} else {
					for _, ip := range ips {
						newKdcs = append(newKdcs, ip+":"+port)
					}
				}
			} else {
				host, port := utils.SplitHostPort(kdc, "127.0.0.1", "88", false)
				newKdcs = append(newKdcs, host+":"+port)
			}
		}
	}
	// check if any kdcs can be reached over the network
	reachable := false
	for _, kdc := range newKdcs {
		if k.testConn(kdc) {
			reachable = true
			break
		}
	}
	// else, just empty the kdcs list so it can be checked later
	if !reachable {
		newKdcs = []string{}
	}
	// cache result
	k.explodedKdcs[key] = &Kdc{
		kdcs: newKdcs,
		next: time.Now().Add(k.config.KdcCacheTimeout),
	}
	// return
	return newKdcs
}

func (k *Kerberos) testConn(hostPort string) bool {
	dialer := new(net.Dialer)
	dialer.Timeout = k.config.KdcConnTimeout
	checkConn, err := dialer.Dial("tcp4", hostPort)
	if err != nil {
		return false
	}
	_ = checkConn.Close()
	return true
}

func (k *Kerberos) NewWithPassword(username, realm, password string) *client.Client {
	// deep-copy krbCfg so concurrent callers don't share the Realms backing array
	krbCfgCopy := *k.krbCfg
	krbCfgCopy.Realms = make([]config.Realm, len(k.krbCfg.Realms))
	copy(krbCfgCopy.Realms, k.krbCfg.Realms)
	krbCfg := &krbCfgCopy
	// derive realm from username if present
	username, realm = utils.SplitUsername(username, realm)
	// map realm if needed
	if mappedRealm, ok := k.config.DomainMapper[realm]; ok {
		realm = *mappedRealm
	} else if !strings.Contains(realm, ".") {
		// if no dot, append default domain which must start with a dot
		realm = realm + strings.ToUpper(k.config.DefaultDomain)
	}
	// set default domain, which is required to be good for krb5 library to work (bug?)
	krbCfg.LibDefaults.DefaultRealm = realm
	// inject realm with default kdc equals to realm name
	var foundRealm *config.Realm
	for _, r := range krbCfg.Realms {
		if r.Realm == realm {
			foundRealm = &r
			break
		}
	}
	if foundRealm == nil {
		// work on a copy of krbCfg
		newRealm := config.Realm{
			Realm:         realm,
			KPasswdServer: []string{realm + ":88"},
		}
		// also explode kdc to all its known ips, allowing to find a working IP (firewall restriction)
		// unfortunately, this is not working with cross-domain calls, as all domains must be defined but are not known
		// newRealm.KDC = k.explodeKdcs(newRealm.KDC)
		krbCfg.Realms = append(krbCfg.Realms, newRealm)
		foundRealm = &newRealm
	}
	// if no kdcs, do not create client
	if len(foundRealm.KDC) == 0 {
		foundRealm.KDC = k.explodeKdcs(foundRealm.KPasswdServer)
		if len(foundRealm.KDC) == 0 {
			return nil
		}
	}
	// create new client
	k.logger.Infof("[-] Authenticating user '%s' on realm '%s'", username, realm)
	cl := client.NewWithPassword(username, realm, password, krbCfg, client.DisablePAFXFAST(true))
	return cl
}
