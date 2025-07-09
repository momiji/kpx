package kpx

import (
	"fmt"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/palantir/stacktrace"
	"net"
	"strings"
	"sync"
	"time"
)

type Kerberos struct {
	config       *Config
	krbCfg       *config.Config // all calls to NewWithPassword use a copy of this
	explodedKdcs map[string]*Kdc
	explodeMutex sync.Mutex
}

type Kdc struct {
	kdcs []string
	next time.Time
}

func NewKerberos(config *Config) *Kerberos {
	return &Kerberos{
		config:       config,
		explodedKdcs: make(map[string]*Kdc),
	}
}

func (k *Kerberos) init() error {
	krb5 := k.config.conf.Krb5
	if krb5 == "" {
		krb5 = AppDefaultKrb5
	}
	krbCfg, err := config.NewFromString(krb5)
	if err != nil {
		return stacktrace.Propagate(err, "Kerberos error, unable to create config")
	}
	// fix KDC list by extending KDC list with server ip, when it contains alpha characters
	for i, realm := range krbCfg.Realms {
		// backup KDC
		realm.KPasswdServer = realm.KDC
		// update
		krbCfg.Realms[i] = realm
	}
	k.krbCfg = krbCfg
	return nil
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
				host, port := splitHostPort(kdc, "127.0.0.1", "88", false)
				ips, err := net.LookupHost(host)
				if err != nil {
					newKdcs = append(newKdcs, host+":"+port)
				} else {
					for _, ip := range ips {
						newKdcs = append(newKdcs, ip+":"+port)
					}
				}
			} else {
				host, port := splitHostPort(kdc, "127.0.0.1", "88", false)
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
		next: time.Now().Add(KDC_TEST_TIMEOUT * time.Second),
	}
	// return
	return newKdcs
}

func (k *Kerberos) testConn(hostPort string) bool {
	dialer := new(net.Dialer)
	dialer.Timeout = time.Duration(k.config.conf.ConnectTimeout) * time.Second
	checkConn, err := dialer.Dial("tcp4", hostPort)
	if err != nil {
		return false
	}
	_ = checkConn.Close()
	return true
}

func (k *Kerberos) NewWithPassword(username, realm, password string) *client.Client {
	// work on a copy of krbCfg
	krbCfg := &(*k.krbCfg)
	// derive realm from username if present
	username, realm = splitUsername(username, realm)
	if k.config.conf.Domains[realm] != nil {
		realm = *k.config.conf.Domains[realm]
	} else if !strings.Contains(realm, ".") {
		// if no dot, append default domain
		realm = realm + AppDefaultDomain
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
	logInfo("[-] Authenticating user '%s' on realm '%s'", username, realm)
	cl := client.NewWithPassword(username, realm, password, krbCfg, client.DisablePAFXFAST(true))
	return cl
}
