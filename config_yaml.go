package kpx

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"

	"github.com/palantir/stacktrace"
	yaml2 "gopkg.in/yaml.v2"
)

// ProxyType identifies the kind of upstream proxy.
type ProxyType string

const (
	ProxyKerberos  ProxyType = "kerberos"
	ProxySocks     ProxyType = "socks"
	ProxyAnonymous ProxyType = "anonymous"
	ProxyDirect    ProxyType = "direct"
	ProxyBasic     ProxyType = "basic"
	ProxyNone      ProxyType = "none"
	ProxyPac       ProxyType = "pac"
)

// ConfProxyContinue is a sentinel returned by resolve() when a PAC script says DIRECT,
// meaning the rule loop should continue to the next entry.
var ConfProxyContinue = ConfProxy{}

func (pt ProxyType) Name() string {
	return string(pt)
}

func (pt ProxyType) Value() int {
	switch pt {
	case ProxyKerberos:
		return 0
	case ProxySocks:
		return 1
	case ProxyAnonymous:
		return 2
	case ProxyDirect:
		return 3
	case ProxyBasic:
		return 4
	case ProxyNone:
		return 5
	case ProxyPac:
		return 6
	}
	return -1
}

// Conf is the raw YAML/JSON configuration loaded from disk.
// All exported fields map 1-to-1 to YAML keys; unexported fields are runtime-only
// and must not be set during deserialization.
type Conf struct {
	Bind           string
	Port           int
	SocksPort      int              `yaml:"socksPort"`
	Verbose        bool
	Debug          bool
	Trace          bool
	Proxies        map[string]*ConfProxy
	Credentials    map[string]*ConfCred
	Domains        map[string]*string
	Rules          []*ConfRule
	SocksRules     []*ConfRule      `yaml:"socksRules"`
	Krb5           string
	ConnectTimeout int              `yaml:"connectTimeout"`
	IdleTimeout    int              `yaml:"idleTimeout"`
	CloseTimeout   int              `yaml:"closeTimeout"`
	Check          *bool
	Update         bool
	Restart        bool
	UseEnvProxy    bool
	Experimental   string
	ACL            []string         `yaml:"acl"`
	ConsoleUI      bool             `yaml:"ui"`
}

// ConfCred holds credential data loaded from YAML.
// Runtime fields (name, isNull, isPerUser, isUsed, isNative) are populated during build
// and are kept here for proximity to the data they extend; they will move to Config in a
// future step once process.go / proxy.go are decoupled.
type ConfCred struct {
	Login    *string
	Password *string
	// runtime state – not read from YAML
	name      *string
	isNull    bool
	isPerUser bool
	isUsed    bool
	isNative  bool
}

// ConfProxy holds proxy data loaded from YAML.
// Runtime fields (name, typeValue, cred, pac*, isUsed, pacRuntime) are populated during
// build and are kept here until process.go / proxy.go are decoupled from *ConfProxy.
type ConfProxy struct {
	Type        *ProxyType
	Host        *string
	Port        int
	Verbose     *bool
	Ssl         bool
	Spn         *string
	Realm       *string
	Credential  *string
	Credentials *string
	Pac         *string
	PacOrder    int    `yaml:"pacOrder"`
	Url         *string
	// runtime state – not read from YAML
	name       *string
	typeValue  int
	cred       *ConfCred
	pacRegex   *ConfRegex
	pacJs      *string
	pacProxy   *string
	isUsed     bool
	pacRuntime *PacExecutor
}

// ConfRule is a single routing rule loaded from YAML.
type ConfRule struct {
	Host    *string
	Proxy   *string
	Dns     *string
	Verbose *bool
	Mitm    bool
	// runtime state – not read from YAML
	regex *ConfRegex
}

func (r *ConfRule) firstProxy() string {
	return strings.Split(*r.Proxy, ",")[0]
}

func (r *ConfRule) allProxiesName() []string {
	return strings.Split(*r.Proxy, ",")
}

// readConfFromFile reads a YAML or JSON file and returns a populated Conf.
// Default timeout values are pre-filled; the file may override them.
// CLI overrides (--listen, --user) are applied after parsing.
func readConfFromFile(filename string) (*Conf, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, stacktrace.Propagate(err, "unable to read file")
	}
	conf := &Conf{
		ConnectTimeout: DEFAULT_CONNECT_TIMEOUT,
		IdleTimeout:    DEFAULT_IDLE_TIMOUT,
		CloseTimeout:   DEFAULT_CLOSE_TIMEOUT,
	}
	if strings.HasPrefix(strings.TrimSpace(string(b)), "{") {
		err = json.Unmarshal(b, conf)
	} else {
		err = yaml2.Unmarshal(b, conf)
	}
	if err != nil {
		return nil, stacktrace.Propagate(err, "unable to parse file as yaml/json")
	}
	if options.Listen != "" {
		h, p := splitHostPort(options.Listen, "127.0.0.1", "0", true)
		conf.Bind = h
		conf.Port, _ = strconv.Atoi(p)
	}
	if options.User != "" {
		for _, cred := range conf.Credentials {
			if cred.Login == nil {
				cred.Login = &options.User
				cred.Password = nil
			}
		}
	}
	return conf, nil
}

// readConfFromOptions builds a Conf entirely from CLI flags, no config file involved.
func readConfFromOptions() *Conf {
	conf := &Conf{
		Bind:           options.bindHost,
		Port:           options.bindPort,
		Proxies:        map[string]*ConfProxy{},
		Credentials:    map[string]*ConfCred{},
		ConnectTimeout: DEFAULT_CONNECT_TIMEOUT,
		IdleTimeout:    DEFAULT_IDLE_TIMOUT,
		CloseTimeout:   DEFAULT_CLOSE_TIMEOUT,
	}

	proxyName := "proxy"
	if options.proxyPort == 0 {
		proxyName = "direct"
	} else if options.login == "" {
		proxyType := ProxyAnonymous
		conf.Proxies[proxyName] = &ConfProxy{
			Type: &proxyType,
			Host: &options.proxyHost,
			Port: options.proxyPort,
		}
	} else {
		proxyType := ProxyKerberos
		proxySpn := "HTTP"
		proxyCred := "user"
		conf.Proxies[proxyName] = &ConfProxy{
			Type:       &proxyType,
			Spn:        &proxySpn,
			Realm:      &options.domain,
			Host:       &options.proxyHost,
			Port:       options.proxyPort,
			Credential: &proxyCred,
		}
		conf.Credentials[proxyCred] = &ConfCred{
			Login: &options.login,
		}
	}

	ruleHost := "*"
	conf.Rules = []*ConfRule{{
		Host:  &ruleHost,
		Proxy: &proxyName,
	}}

	if options.ACL != "" {
		conf.ACL = strings.Split(options.ACL, ",")
	}

	return conf
}
