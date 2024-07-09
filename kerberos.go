package kpx

import (
	"fmt"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/palantir/stacktrace"
	"net"
	"strings"
	"sync"
)

type Kerberos struct {
	config       *Config
	krbCfg       *config.Config
	clients      *string
	explodedKdcs map[string][]string
	explodeMutex sync.Mutex
}

func NewKerberos(config *Config) *Kerberos {
	return &Kerberos{
		config:       config,
		explodedKdcs: make(map[string][]string),
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
		realm.KDC = k.explodeKdcs(realm.KDC)
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
		return val
	}
	newKdcs := make([]string, 0, 16)
	for _, kdcs := range realmKdcs {
		for _, kdc := range strings.Split(kdcs, " ") {
			kdc = strings.TrimSpace(kdc)
			if strings.ContainsAny(strings.ToLower(kdc), "abcdefghijklmnopqrstuvwxyz") {
				port := "88"
				c := strings.LastIndex(kdc, ":")
				if c >= 0 {
					port = kdc[c+1:]
					kdc = kdc[0:c]
				}
				ips, err := net.LookupHost(kdc)
				if err != nil {
					newKdcs = append(newKdcs, kdc+":"+port)
				} else {
					for _, ip := range ips {
						newKdcs = append(newKdcs, ip+":"+port)
					}
				}
			} else {
				newKdcs = append(newKdcs, kdc)
			}
		}
	}
	k.explodedKdcs[key] = newKdcs
	return newKdcs
}

func (k *Kerberos) NewWithPassword(username, realm, password string) *client.Client {
	// derive realm from username if present
	var domain string
	username, domain = splitUsername(username)
	if domain != "" {
		realm = domain
	}
	if k.config.conf.Domains[realm] != nil {
		realm = *k.config.conf.Domains[realm]
	}
	//inject default domain, which is required to be good for krb5 library to work (bug?)
	krbCfg := k.krbCfg
	if krbCfg.LibDefaults.DefaultRealm != realm {
		newKrbCfg := *krbCfg
		newKrbCfg.LibDefaults.DefaultRealm = realm
		krbCfg = &newKrbCfg
	}
	//inject realm with default kdc equals to realm name
	if krbCfg.Realms == nil {
		newKrbCfg := *krbCfg
		newKrbCfg.Realms = make([]config.Realm, 0)
		krbCfg = &newKrbCfg
	}
	foundRealm := false
	for _, r := range krbCfg.Realms {
		if r.Realm == realm {
			foundRealm = true
			break
		}
	}
	if !foundRealm {
		newKrbCfg := *krbCfg
		newRealm := config.Realm{
			Realm: realm,
			KDC:   []string{realm + ":88"},
		}
		//also explode kdc to all its known ips, allowing to find a working IP (firewall restriction)
		//unfortunately, this is not working with cross-domain calls, as all domains must be defined but are not known
		newRealm.KDC = k.explodeKdcs(newRealm.KDC)
		newKrbCfg.Realms = append(newKrbCfg.Realms, newRealm)
		krbCfg = &newKrbCfg
	}
	// create new client
	logInfo("[-] Authenticating user '%s' on realm '%s'", username, realm)
	cl := client.NewWithPassword(username, realm, password, krbCfg, client.DisablePAFXFAST(true))
	return cl
}
