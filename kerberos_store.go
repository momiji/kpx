package kpx

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/krberror"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/palantir/stacktrace"
	"strings"
	"sync"
)

type KerberosStore struct {
	kerberos     *Kerberos
	clients      map[string]*KerberosClient
	clientsMutex sync.Mutex
}

func NewKerberosStore(config *Config) (*KerberosStore, error) {
	kerberos := NewKerberos(config)
	err := kerberos.init()
	if err != nil {
		return nil, stacktrace.Propagate(err, "unable to initialize kerberos")
	}
	return &KerberosStore{
		kerberos: kerberos,
		clients:  make(map[string]*KerberosClient),
	}, nil
}

func (ks *KerberosStore) safeGetClient(key string) *KerberosClient {
	ks.clientsMutex.Lock()
	cl := ks.clients[key]
	ks.clientsMutex.Unlock()
	return cl
}

func (ks *KerberosStore) safeSaveClient(key string, client *KerberosClient) {
	ks.clientsMutex.Lock()
	ks.clients[key] = client
	ks.clientsMutex.Unlock()
}

func (ks *KerberosStore) safeRemoveClient(key string) {
	ks.clientsMutex.Lock()
	ks.clients[key] = nil
	ks.clientsMutex.Unlock()
}

// Try to login with the given credentials, only if not yet logged in
func (ks *KerberosStore) safeTryLogin(username, realm, password string, force bool) (*KerberosClient, error) {
	// create key
	key := ks.clientKey(username, realm, password)
	// remove client to force login?
	if force {
		ks.safeRemoveClient(key)
	}
	// get existing client
	kcl := ks.safeGetClient(key)
	if kcl != nil {
		return kcl, nil
	}
	// create new client
	krbClient := ks.kerberos.NewWithPassword(username, realm, password)
	err := krbClient.Login()
	if err != nil {
		if e, ok := err.(krberror.Krberror); ok {
			return nil, stacktrace.Propagate(err, "Invalid login/password for '%s@%s'\n%s\n%s", username, realm, e.RootCause, strings.Join(e.EText, "\n"))
		}
		return nil, stacktrace.Propagate(err, "Invalid login/password for '%s@%s'", username, realm)
	}
	// save client
	kcl = NewKerberosClient(krbClient)
	ks.safeSaveClient(key, kcl)
	return kcl, nil
}

func (ks *KerberosStore) safeGetToken(username, realm, password, protocol string, host string) (*string, error) {
	kcl, err := ks.safeTryLogin(username, realm, password, false)
	if err != nil {
		return nil, stacktrace.Propagate(err, "unable to login to kerberos")
	}
	token, err := kcl.safeGetToken(protocol, host)
	if err != nil {
		kcl, err = ks.safeTryLogin(username, realm, password, true)
		if err != nil {
			return nil, stacktrace.Propagate(err, "unable to login to kerberos")
		}
		token, err = kcl.safeGetToken(protocol, host)
		if err != nil {
			return nil, stacktrace.Propagate(err, "unable to get kerberos token")
		}
	}
	return token, nil
}

func (ks *KerberosStore) clientKey(username string, realm string, password string) string {
	hasher := sha1.New()
	hasher.Write([]byte(password))
	hash := hasher.Sum(nil)
	key := fmt.Sprintf("%s\x00%s\x00%s", hash, username, realm)
	return key
}

type KerberosClient struct {
	mutex     sync.Mutex
	krbClient *client.Client
}

func NewKerberosClient(krbClient *client.Client) *KerberosClient {
	return &KerberosClient{
		krbClient: krbClient,
		mutex:     sync.Mutex{},
	}
}

func (kc *KerberosClient) safeGetToken(protocol string, host string) (*string, error) {
	kc.mutex.Lock()
	defer kc.mutex.Unlock()
	spn := protocol + "/" + host
	s := spnego.SPNEGOClient(kc.krbClient, spn)
	err := s.AcquireCred()
	if err != nil {
		return nil, stacktrace.Propagate(err, "unable to acquire client credential for spn: %s", spn)
	}
	st, err := s.InitSecContext()
	if err != nil {
		return nil, stacktrace.Propagate(err, "unable to initialize security context for spn: %s", spn)
	}
	nb, err := st.Marshal()
	if err != nil {
		return nil, stacktrace.Propagate(err, "unable to marshal security token for spn: %s", spn)
	}
	hs := base64.StdEncoding.EncodeToString(nb)
	return &hs, nil
}
