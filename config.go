package kpx

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/howeyc/gopass"
	"github.com/palantir/stacktrace"
	"golang.org/x/text/encoding/charmap"
	yaml2 "gopkg.in/yaml.v2"
)

type Config struct {
	conf              Conf
	pac               string
	lastProxies       map[string]time.Time
	lastMMutex        sync.RWMutex
	certsManager      *CertsManager
	disableAutoUpdate bool
	hostsCache        map[string]*HostCache
	hostsCacheMutex   sync.RWMutex
	pacsCache         map[string]string
	needFastReload    bool
}

type HostCache struct {
	rule  *ConfRule
	proxy []*ConfProxy
}

const EXPERIMENTAL_CONNETION_POOLS = "connection-pools"
const EXPERIMENTAL_HOSTS_CACHE = "hosts-cache"

const CREDENTIAL_KERBEROS = "kerberos"

func NewConfig(name string) (*Config, error) {
	var config = Config{
		conf: Conf{
			Proxies:        make(map[string]*ConfProxy),
			Rules:          make([]*ConfRule, 0),
			SocksRules:     make([]*ConfRule, 0),
			ConnectTimeout: DEFAULT_CONNECT_TIMEOUT,
			IdleTimeout:    DEFAULT_IDLE_TIMOUT,
			CloseTimeout:   DEFAULT_CLOSE_TIMEOUT,
		},
		lastProxies: map[string]time.Time{},
		hostsCache:  map[string]*HostCache{},
		pacsCache:   map[string]string{},
	}
	var err error
	if name == "" {
		err = config.readFromConfig()
	} else {
		err = config.readFromFile(name)
	}
	config.conf.Trace = config.conf.Trace || options.Trace
	config.conf.Debug = config.conf.Debug || options.Debug || config.conf.Trace
	config.conf.Verbose = config.conf.Verbose || options.Verbose || config.conf.Debug
	config.conf.experimentalConnectionPools = isExperimental(config.conf.Experimental, EXPERIMENTAL_CONNETION_POOLS)
	config.conf.experimentalHostsCache = isExperimental(config.conf.Experimental, EXPERIMENTAL_HOSTS_CACHE)
	if err != nil {
		return nil, stacktrace.Propagate(err, "unable to read config")
	}
	err = config.check()
	if err != nil {
		return nil, stacktrace.Propagate(err, "invalid config")
	}
	err = config.build()
	if err != nil {
		return nil, stacktrace.Propagate(err, "unable to build config")
	}
	err = config.genPac()
	if err != nil {
		return nil, stacktrace.Propagate(err, "unable to build config pac")
	}
	err = config.genCerts()
	if err != nil {
		return nil, stacktrace.Propagate(err, "unable to load certificates")
	}
	return &config, nil
}

func isExperimental(conf string, name string) bool {
	return strings.Contains(" "+strings.ReplaceAll(conf, ",", " ")+" ", " "+name+" ")
}

func (c *Config) readFromConfig() error {
	c.conf.Bind = options.bindHost
	c.conf.Port = options.bindPort

	c.conf.Proxies = map[string]*ConfProxy{}
	proxyName := "krb"
	proxyType := ProxyKerberos
	proxySpn := "HTTP"
	proxyCred := "user"
	c.conf.Proxies[proxyName] = &ConfProxy{
		Type:       &proxyType,
		Spn:        &proxySpn,
		Realm:      &options.domain,
		Host:       &options.proxyHost,
		Port:       options.proxyPort,
		Credential: &proxyCred,
	}

	c.conf.Credentials = map[string]*ConfCred{}
	c.conf.Credentials[proxyCred] = &ConfCred{
		Login: &options.login,
	}

	c.conf.Rules = make([]*ConfRule, 1)
	ruleHost := "*"
	c.conf.Rules[0] = &ConfRule{
		Host:  &ruleHost,
		Proxy: &proxyName,
	}

	c.conf.ACL = options.ACL

	return nil
}

func (c *Config) readFromFile(filename string) error {
	var yaml []byte
	var err error
	yaml, err = os.ReadFile(filename)
	if err != nil {
		return stacktrace.Propagate(err, "unable to read file")
	}
	if strings.HasPrefix(strings.TrimSpace(string(yaml)), "{") {
		err = json.Unmarshal(yaml, &c.conf)
	} else {
		err = yaml2.Unmarshal(yaml, &c.conf)
	}
	if err != nil {
		return stacktrace.Propagate(err, "unable to read file as yaml/json")
	}
	if options.Listen != "" {
		h, p := splitHostPort(options.Listen, "127.0.0.1", "0", true)
		c.conf.Bind = h
		c.conf.Port, _ = strconv.Atoi(p)
	}
	if options.User != "" {
		for _, cred := range c.conf.Credentials {
			// auto-fill missing login
			if cred.Login == nil {
				cred.Login = &options.User
				cred.Password = nil
			}
		}
	}
	return nil
}

func (c *Config) check() (err error) {
	// check proxies
	for name, proxy := range c.conf.Proxies {
		if name == "" || name == ProxyDirect.Name() || name == ProxyNone.Name() || strings.HasPrefix(name, "$") {
			return stacktrace.NewError("proxy '%s': name cannot be empty, 'direct', 'none' or start with a '$'", name)
		}
		if proxy.Type == nil {
			return stacktrace.NewError("proxy '%s': must contain 'type' (kerberos,socks,basic,anonymous,pac)", name)
		}
		proxy.typeValue = proxy.Type.Value()
		if proxy.typeValue == -1 {
			return stacktrace.NewError("proxy '%s': must contain 'type' (kerberos,socks,basic,anonymous,pac)", name)
		}
		if *proxy.Type != ProxyPac {
			if proxy.Url != nil {
				return stacktrace.NewError("proxy '%s': non-pac proxy must not contain 'url'", name)
			}
			if proxy.Host == nil {
				return stacktrace.NewError("proxy '%s': non-pac proxy must contain 'host'", name)
			}
			if proxy.Port == 0 {
				return stacktrace.NewError("proxy '%s': non-pac proxy port number must be > 0", name)
			}
			if proxy.Credentials != nil {
				return stacktrace.NewError("proxy '%s': non-pac proxy must not contain 'credentials'", name)
			}
		} else {
			if proxy.Url == nil {
				return stacktrace.NewError("proxy '%s': pac proxy must contain 'url'", name)
			}
			if proxy.Host != nil {
				return stacktrace.NewError("proxy '%s': pac proxy must not contain 'host'", name)
			}
			if proxy.Port != 0 {
				return stacktrace.NewError("proxy '%s': pac proxy port number must be > 0", name)
			}
		}
		if *proxy.Type == ProxyAnonymous || *proxy.Type == ProxyPac {
			if proxy.Credential != nil {
				return stacktrace.NewError("proxy '%s': anonymous and pac proxies must not contain 'credential'", name)
			}
		}
		if proxy.Credential != nil && *proxy.Credential != "" && *proxy.Credential != CREDENTIAL_KERBEROS && c.conf.Credentials[*proxy.Credential] == nil {
			return stacktrace.NewError("proxy '%s': credential '%s' must exist in 'credentials'", name, *proxy.Credential)
		}
		for _, cred := range c.splitCredentials(proxy.Credentials) {
			if cred != CREDENTIAL_KERBEROS && c.conf.Credentials[cred] == nil {
				return stacktrace.NewError("proxy '%s': credential '%s' must exist in 'credentials'", name, cred)
			}
		}
	}
	// check credentials
	for name, cred := range c.conf.Credentials {
		if name == "" || name == CREDENTIAL_KERBEROS || strings.HasPrefix(name, "$") {
			return stacktrace.NewError("credential '%s': name cannot be empty, 'kerberos' or start with '$'", name)
		}
		if cred.Password != nil && cred.Login == nil {
			return stacktrace.NewError("credential '%s': password cannot be set without login being set", name)
		}
	}
	// check http rules
	for i, rule := range c.conf.Rules {
		if rule.Host == nil {
			return stacktrace.NewError("rule %d: must contain 'host'", i)
		}
		if rule.Proxy == nil && rule.Dns == nil {
			return stacktrace.NewError("rule %d: must contain 'proxy' or 'dns'", i)
		}
		if rule.Proxy != nil {
			if *rule.Proxy != ProxyDirect.Name() && *rule.Proxy != ProxyNone.Name() {
				for _, p := range rule.allProxiesName() {
					if c.conf.Proxies[p] == nil {
						return stacktrace.NewError("rule %d: '%s' must exist in 'proxies', or be 'direct' or 'none'", i, p)
					}
				}
			}
		}
		if rule.Proxy != nil && rule.Dns != nil {
			if *rule.Proxy == ProxyDirect.Name() {
			} else if c.conf.Proxies[*rule.Proxy] != nil {
				for _, p := range rule.allProxiesName() {
					if *c.conf.Proxies[p].Type != ProxySocks {
						return stacktrace.NewError("rule %d: rule with dns must have a 'direct' proxy or proxy of type 'socks'", i)
					}
				}
			}
		}
		if rule.Dns != nil {
			hp := strings.Split(*rule.Dns, ":")
			if len(hp) == 0 || len(hp) > 2 {
				return stacktrace.NewError("rule %d: dns must be like '[IP][:PORT]', i.e 'IP' or 'IP:PORT' or ':PORT'", i)
			}
		}
	}

	// check socks rules
	for i, rule := range c.conf.SocksRules {
		if rule.Host == nil {
			return stacktrace.NewError("socks rule %d: must contain 'host'", i)
		}
		if rule.Proxy == nil && rule.Dns == nil {
			return stacktrace.NewError("socks rule %d: must contain 'proxy' or 'dns'", i)
		}
		if rule.Proxy != nil {
			if *rule.Proxy != ProxyDirect.Name() && *rule.Proxy != ProxyNone.Name() {
				for _, p := range rule.allProxiesName() {
					if c.conf.Proxies[p] == nil {
						return stacktrace.NewError("socks rule %d: '%s' must exist in 'proxies', or be 'direct' or 'none'", i, p)
					}
				}
			}
		}
		if rule.Proxy != nil {
			if *rule.Proxy == ProxyDirect.Name() {
			} else if c.conf.Proxies[*rule.Proxy] != nil {
				for _, p := range rule.allProxiesName() {
					if *c.conf.Proxies[p].Type != ProxySocks {
						return stacktrace.NewError("socks rule %d: must have a 'direct' proxy or proxy of type 'socks'", i)
					} else if c.conf.Proxies[p].Credential != nil && *c.conf.Proxies[p].Credential == "" {
						return stacktrace.NewError("socks rule %d: must not have a per-user credential (empty value)", i)
					}
				}
			}
		}
		if rule.Proxy != nil && rule.Dns != nil {
			if *rule.Proxy == ProxyDirect.Name() {
			} else if c.conf.Proxies[*rule.Proxy] != nil {
				for _, p := range rule.allProxiesName() {
					if *c.conf.Proxies[p].Type != ProxySocks {
						return stacktrace.NewError("socks rule %d: rule with dns must have a 'direct' proxy or proxy of type 'socks'", i)
					}
				}
			}
		}
		if rule.Dns != nil {
			hp := strings.Split(*rule.Dns, ":")
			if len(hp) == 0 || len(hp) > 2 {
				return stacktrace.NewError("socks rule %d: dns must be like '[IP][:PORT]', i.e 'IP' or 'IP:PORT' or ':PORT'", i)
			}
		}
	}

	return nil
}

func (c *Config) build() error {
	if c.conf.Credentials == nil {
		c.conf.Credentials = make(map[string]*ConfCred)
	}
	// build server bind
	if c.conf.Bind == "" {
		c.conf.Bind = "127.0.0.1"
	}
	// build server pac proxy string
	c.conf.pacProxy = fmt.Sprint("PROXY ", c.conf.Bind, ":", c.conf.Port)
	// build rules
	for _, rule := range c.conf.Rules {
		regex, err := c.regex(*rule.Host)
		if err != nil {
			return stacktrace.Propagate(err, "unable to compile rule regex")
		}
		rule.regex = regex
	}
	for _, rule := range c.conf.SocksRules {
		regex, err := c.regex(*rule.Host)
		if err != nil {
			return stacktrace.Propagate(err, "unable to compile rule regex")
		}
		rule.regex = regex
	}
	// add none proxy
	noneName := ProxyNone.Name()
	noneType := ProxyNone
	noneProxy := ConfProxy{
		name:      &noneName,
		Type:      &noneType,
		typeValue: ProxyNone.Value(),
	}
	c.conf.Proxies[noneName] = &noneProxy
	// add direct proxy
	directName := ProxyDirect.Name()
	directType := ProxyDirect
	directProxy := ConfProxy{
		name:      &directName,
		Type:      &directType,
		typeValue: ProxyDirect.Value(),
	}
	c.conf.Proxies[directName] = &directProxy
	// add native kerberos credential
	kerberosName := CREDENTIAL_KERBEROS
	kerberosCred := ConfCred{
		name:     &kerberosName,
		isNative: true,
	}
	c.conf.Credentials[kerberosName] = &kerberosCred
	// build proxies
	for name, proxy := range c.conf.Proxies {
		proxyName := name
		proxy.name = &proxyName
		if *proxy.Type == ProxyKerberos || *proxy.Type == ProxyBasic || *proxy.Type == ProxySocks {
			//proxy.krb = fmt.Sprint(krb)
			switch {
			case proxy.Credential == nil:
				if *proxy.Type == ProxyKerberos || *proxy.Type == ProxyBasic {
					name := fmt.Sprint("$null-", *proxy.name)
					proxy.cred = &ConfCred{
						name:   &name,
						isNull: true,
					}
					c.conf.Credentials[name] = proxy.cred
				}
			case *proxy.Credential == "":
				name := fmt.Sprint("$user-", *proxy.name)
				proxy.cred = &ConfCred{
					name:      &name,
					isPerUser: true,
				}
				c.conf.Credentials[name] = proxy.cred
			default:
				proxy.cred = c.conf.Credentials[*proxy.Credential]
			}
		}
		switch *proxy.Type {
		case ProxyKerberos, ProxyBasic:
			proxy.pacProxy = nil
			// if per user, directly proxy to target who will ask for credentials
			if proxy.cred.isPerUser {
				pacProxy := c.genProxy("PROXY", *proxy.Host, proxy.Port)
				proxy.pacProxy = &pacProxy
			}
		case ProxyDirect:
			pacProxy := "DIRECT"
			proxy.pacProxy = &pacProxy
		case ProxySocks:
			proxy.pacProxy = nil
			// if no authentication, directly proxy to target
			if proxy.cred == nil {
				pacProxy := c.genProxy("SOCKS", *proxy.Host, proxy.Port)
				proxy.pacProxy = &pacProxy
			}
		case ProxyAnonymous:
			pacProxy := c.genProxy("PROXY", *proxy.Host, proxy.Port)
			proxy.pacProxy = &pacProxy
		}
		if proxy.Pac != nil {
			regex, err := c.regex(*proxy.Pac)
			if err != nil {
				return stacktrace.Propagate(err, "proxy '%s': unable to compile pac regex", *proxy.name)
			}
			proxy.pacRegex = regex
		}
	}
	// build creds
	for name, cred := range c.conf.Credentials {
		credName := name
		cred.name = &credName
		if cred.Password != nil && strings.HasPrefix(*cred.Password, ENCRYPTED) {
			password, err := decrypt((*cred.Password)[len(ENCRYPTED):])
			if err != nil {
				return stacktrace.Propagate(err, "unable to decrypt '%s' password", name)
			}
			cred.Password = &password
		}
	}
	// update rules and isUsed
	for _, rule := range c.conf.Rules {
		if rule.Dns != nil && rule.Proxy == nil {
			rule.Proxy = &directName
		} else {
			for _, p := range rule.allProxiesName() {
				proxy := c.conf.Proxies[p]
				proxy.isUsed = true
				if proxy.cred != nil && !proxy.cred.isPerUser {
					proxy.cred.isUsed = true
				}
			}
		}
	}
	for _, rule := range c.conf.SocksRules {
		if rule.Dns != nil && rule.Proxy == nil {
			rule.Proxy = &directName
		} else {
			for _, p := range rule.allProxiesName() {
				proxy := c.conf.Proxies[p]
				proxy.isUsed = true
				if proxy.cred != nil && !proxy.cred.isPerUser {
					proxy.cred.isUsed = true
				}
			}
		}
	}
	// download proxy pac
	for _, proxy := range c.conf.Proxies {
		if proxy.isUsed && *proxy.Type == ProxyPac {
			logInfo("[-] Loading proxy pac: %s", *proxy.Url)
			js, ex, err := c.downloadPac(*proxy.Url)
			if err != nil {
				ok := false
				if js, ok = c.pacsCache[*proxy.Url]; ok {
					logInfo("[-] Error: unable to download or use pac, using cached js")
					ex, _ = c.pacToExecutor(js)
				} else {
					logError("[-] Error: %v", err)
				}
			}
			if js == "" {
				noneJs := fmt.Sprintf(`function FindProxyForURL() { return "%s"; }`, c.conf.pacProxy)
				proxy.pacJs = &noneJs
				proxy.pacRuntime = nil
				c.needFastReload = true
				continue
			}
			proxy.pacJs = &js
			proxy.pacRuntime = ex
			c.pacsCache[*proxy.Url] = js
			//
			for _, cred := range c.splitCredentials(proxy.Credentials) {
				c.conf.Credentials[cred].isUsed = true
			}
		}
	}
	return nil
}

func (c *Config) downloadPac(url string) (string, *PacExecutor, error) {
	// download pac
	httpClient := c.newHttpClient()
	get, err := httpClient.Get(url)
	if err != nil {
		return "", nil, errors.New(fmt.Sprintf("unable to download pac: %v", err))
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(get.Body)
	// check status code
	if get.StatusCode != 200 {
		return "", nil, errors.New(fmt.Sprintf("unable to download pac: HTTP %d", get.StatusCode))
	}
	// read all bytes
	jsb, err := io.ReadAll(get.Body)
	if err != nil {
		return "", nil, errors.New(fmt.Sprintf("unable to download pac: %v", err))
	}
	js := string(jsb)
	executor, err := c.pacToExecutor(js)
	if err != nil {
		return "", nil, err
	}
	return js, executor, nil
}

func (c *Config) pacToExecutor(js string) (*PacExecutor, error) {
	// load js as unicode/utf-8
	executor, err := NewPac(js)
	if err != nil {
		// load js as iso-latin-1
		jsb2, err := charmap.ISO8859_1.NewDecoder().Bytes([]byte(js))
		if err == nil {
			js = string(jsb2)
			executor, err = NewPac(js)
			if err != nil {
				return nil, stacktrace.Propagate(err, "unable to create pac runtime")
			}
		}
	}
	return executor, nil
}

func (c *Config) genProxy(name string, hosts string, port int) string {
	list := make([]string, 0)
	for _, host := range strings.Split(hosts, ",") {
		list = append(list, fmt.Sprintf("%s %s:%d", name, host, port))
	}
	return strings.Join(list, ";")
}

func (c *Config) genPac() error {
	builder := strings.Builder{}
	builder.WriteString(`
var FindProxyForURL = function(profiles) {
  return function(url, host) {
    "use strict";
    var index = 0, result = null, direct = null;
    do {
      result = profiles[index++];
      if (typeof result === "function") {
        result = result(url, host);
        if (result === "CONTINUE") { direct = result; result = null; }
      }
    } while (typeof result !== "string" && index < profiles.length);
    if (result != null) return result;
    if (direct != null) return "DIRECT";
    return "PROXY 127.0.0.1:1";
  }
}([`)
	// proxy loop
	fn := false
	startFn := func() {
		builder.WriteString(`
function(url, host) {
  "use strict";
`)
		fn = true
	}
	endFn := func() {
		builder.WriteString(`  return null;
},`)
		fn = false
	}
	for _, rule := range c.conf.Rules {
		switch {
		case rule.Dns != nil:
		case rule.Proxy == nil:
			x := ""
			if rule.regex.exclude {
				x = "!"
			}
			p := "PROXY 127.0.0.1:1"
			if !fn {
				startFn()
			}
			builder.WriteString(fmt.Sprint("  if (", x, "/", rule.regex.regex, `/.test(host)) return "`, p, `";`, "\n"))
		case *c.conf.Proxies[rule.firstProxy()].Type == ProxyPac:
			x := ""
			if !rule.regex.exclude { // inverse exclude as if condition is true then return null
				x = "!"
			}
			proxy := c.conf.Proxies[rule.firstProxy()]
			if fn {
				endFn()
			}
			builder.WriteString(`
function(url, host) {
`)
			builder.WriteString(fmt.Sprint("  if (", x, "/", rule.regex.regex, `/.test(host)) return null;`))
			builder.WriteString(fmt.Sprintf(`
  var f = function() {
/* Begin of PAC */
%s
/* End of PAC */
    return FindProxyForURL;
  }.call(this);
  var r = f(url, host).trim();
  if (r === "DIRECT") return "CONTINUE";
  var firstProxy = r.split(";")[0].trim();
  var split = firstProxy.split(" ");
  var type = split[0];
  var hostPort = "";
  if (split.length > 1) hostPort = split.slice(1).join(" ").trim();
  var hostOnly = hostPort.split(":")[0];
`, *proxy.pacJs))
			for _, confProxy := range c.conf.Proxies {
				//if confProxy.Host != nil {
				//	hp := *confProxy.Host + ":" + strconv.Itoa(confProxy.Port)
				//	p := c.conf.pacProxy
				//	if confProxy.pacProxy != nil {
				//		p = *confProxy.pacProxy
				//	}
				//	builder.WriteString(fmt.Sprint(`  if (hostPort === "`, hp, `") return "`, p, `";`, "\n"))
				//}
				if confProxy.pacRegex != nil {
					p := c.conf.pacProxy
					if confProxy.pacProxy != nil {
						p = *confProxy.pacProxy
					}
					if strings.Contains(confProxy.pacRegex.regex, ":") {
						builder.WriteString(fmt.Sprint("  if (/", confProxy.pacRegex.regex, `/.test(hostPort)) return "`, p, `";`, "\n"))
					} else if confProxy.pacRegex != nil {
						builder.WriteString(fmt.Sprint("  if (/", confProxy.pacRegex.regex, `/.test(hostOnly)) return "`, p, `";`, "\n"))
					}
				}
			}
			builder.WriteString(`  return r;
},`)
		default:
			x := ""
			if rule.regex.exclude {
				x = "!"
			}
			p := ""
			for _, n := range rule.allProxiesName() {
				proxy := c.conf.Proxies[n]
				if proxy.pacProxy != nil {
					p = p + ";" + *proxy.pacProxy
				}
			}
			if p == "" {
				p = c.conf.pacProxy
			} else {
				p = p[1:]
			}
			if !fn {
				startFn()
			}
			builder.WriteString(fmt.Sprint("  if (", x, "/", rule.regex.regex, `/.test(host)) return "`, p, `";`, "\n"))
		}
	}
	// end main function
	if fn {
		endFn()
	}
	builder.WriteString(`
null
]);
`)
	c.pac = strings.ReplaceAll(builder.String(), "\r", "")
	return nil
}

func (c *Config) askCredentials() error {
	logFlush()
	var err error
	for _, cred := range c.conf.Credentials {
		if cred.isUsed && !cred.isPerUser && !cred.isNative {
			message := fmt.Sprintf("Credential [%s] -", *cred.name)
			if cred.isNull {
				message = fmt.Sprintf("Proxy [%s] -", strings.SplitN(*cred.name, "-", 2)[1])
			}
			if cred.Login == nil {
				logPrintf("[-] %s Enter login: ", message)
				var login string
				_, err = fmt.Scanln(&login)
				if err != nil {
					return stacktrace.NewError("Invalid empty login")
				}
				cred.Login = &login
				c.disableAutoUpdate = true
			}
			if cred.Password == nil {
				logPrintf("[-] %s Enter password for user '%s': ", message, *cred.Login)
				pwdBytes, err := gopass.GetPasswdMasked() // looks like password always exists even if error
				if err != nil {
					return stacktrace.NewError("Invalid empty password")
				}
				password := string(pwdBytes)
				cred.Password = &password
				c.disableAutoUpdate = true
			}
		}
	}
	return nil
}

func (c *Config) matchHttp(url string, hostPort string) (*ConfRule, []*ConfProxy) {
	return c.match(url, hostPort, "http:", &c.conf.Rules)
}

func (c *Config) matchSocks(hostPort string) (*ConfRule, []*ConfProxy) {
	return c.match(hostPort, hostPort, "socks:", &c.conf.SocksRules)
}

func (c *Config) match(url string, hostPort string, prefix string, rules *[]*ConfRule) (*ConfRule, []*ConfProxy) {
	if hc, ok := c.getCachedHost(prefix + hostPort); ok {
		return hc.rule, hc.proxy
	}
	hostOnly := strings.Split(hostPort, ":")[0]
	var direct *ConfRule
	for _, rule := range *rules {
		match := false
		if rule.regex.pattern == nil {
			match = true
		} else if !c.conf.experimentalHostsCache && strings.Contains(rule.regex.regex, "/") {
			match = rule.regex.pattern.MatchString(url) != rule.regex.exclude
		} else if strings.Contains(rule.regex.regex, ":") {
			match = rule.regex.pattern.MatchString(hostPort) != rule.regex.exclude
		} else {
			match = rule.regex.pattern.MatchString(hostOnly) != rule.regex.exclude
		}
		if match {
			proxy := c.resolve(url, hostOnly, rule)
			if proxy != nil && *proxy[0] != ConfProxyContinue {
				c.addCachedHost(prefix+hostPort, rule, proxy)
				return rule, proxy
			}
			direct = rule
		}
	}
	// if last successful rule is a pac rule which returned DIRECT, then return a "direct" proxy
	// otherwise, return nil
	if direct != nil {
		rule := direct
		proxy := []*ConfProxy{c.conf.Proxies[ProxyDirect.Name()]}
		c.addCachedHost(prefix+hostPort, rule, proxy)
		return rule, proxy
	}
	c.addCachedHost(prefix+hostPort, nil, nil)
	return nil, nil
}

func (c *Config) addCachedHost(hostPort string, rule *ConfRule, proxy []*ConfProxy) {
	c.hostsCacheMutex.Lock()
	defer c.hostsCacheMutex.Unlock()
	c.hostsCache[hostPort] = &HostCache{rule, proxy}
}

func (c *Config) getCachedHost(hostPort string) (*HostCache, bool) {
	c.hostsCacheMutex.RLock()
	defer c.hostsCacheMutex.RUnlock()
	if hc, ok := c.hostsCache[hostPort]; ok {
		return hc, true
	}
	return nil, false
}

func (c *Config) resolve(url, host string, rule *ConfRule) []*ConfProxy {
	proxy := c.conf.Proxies[rule.firstProxy()]
	if proxy == nil {
		return nil
	}
	if *proxy.Type != ProxyPac {
		return c.allProxies(rule)
	}
	pacResult := c.resolvePac(url, host, proxy)
	switch {
	case pacResult.isDirect:
		// return continue to continue scanning rules
		// if no more rules then this will be transformed into a DIRECT (see match)
		return []*ConfProxy{&ConfProxyContinue}
	case pacResult.isSocks, pacResult.isProxy:
		// lookup hostPort in existing proxies (host/port and pac), if found use it, otherwise create a new one
		var pacProxies []*ConfProxy
		for _, confProxy := range c.conf.Proxies {
			//if confProxy.Host != nil {
			//	if *confProxy.Host+":"+strconv.Itoa(confProxy.Port) == pacResult.hostPort {
			//		return confProxy
			//	}
			//}
			if confProxy.pacRegex != nil {
				if strings.Contains(confProxy.pacRegex.regex, ":") {
					if confProxy.pacRegex.pattern.MatchString(pacResult.hostPort) {
						pacProxies = append(pacProxies, confProxy)
					}
				} else if confProxy.pacRegex != nil {
					if confProxy.pacRegex.pattern.MatchString(pacResult.hostOnly) {
						pacProxies = append(pacProxies, confProxy)
					}
				}
			}
		}
		if pacProxies != nil {
			return pacProxies
		}
		// otherwise create a temporary proxy
		proxyName := pacResult.proxy
		proxyType := ProxyAnonymous
		if pacResult.isSocks {
			proxyType = ProxySocks
		}
		host, p := splitHostPort(pacResult.hostPort, "127.0.0.1", "8080", false)
		port, _ := strconv.Atoi(p)
		return []*ConfProxy{{
			name:      &proxyName,
			Type:      &proxyType,
			typeValue: ProxySocks.Value(),
			Host:      &host,
			Port:      port,
			Verbose:   rule.Verbose,
		}}
	}
	if pacResult.isDirect {
		return []*ConfProxy{&ConfProxyContinue}
	}

	return []*ConfProxy{proxy}
}

func (c *Config) resolvePac(url, host string, proxy *ConfProxy) *PacResult {
	pac := proxy.pacRuntime
	if pac == nil {
		return &PacResult{
			proxy:    ProxyNone.Name(),
			isDirect: false,
			isProxy:  false,
			isSocks:  false,
			hostPort: "",
			hostOnly: "",
		}
	}
	proxies, _ := pac.Run(url, host)
	firstProxy := strings.TrimSpace(strings.Split(strings.TrimSpace(proxies), ";")[0])
	split := strings.SplitN(firstProxy+" ", " ", 2)
	pType := split[0]
	pHostPort := ""
	if len(split) > 1 {
		pHostPort = strings.TrimSpace(split[1])
	}
	pHostOnly := strings.Split(pHostPort, ":")[0]
	return &PacResult{
		proxy:    firstProxy,
		isDirect: pType == "DIRECT",
		isProxy:  pType == "PROXY" || pType == "HTTP" || pType == "HTTPS",
		isSocks:  pType == "SOCKS" || pType == "SOCKS4" || pType == "SOCKS5",
		hostPort: pHostPort,
		hostOnly: pHostOnly,
	}
}

func (c *Config) allProxies(rule *ConfRule) []*ConfProxy {
	allProxies := rule.allProxiesName()
	proxies := make([]*ConfProxy, len(allProxies))
	for i, p := range allProxies {
		proxies[i] = c.conf.Proxies[p]
	}
	return proxies
}

func (c *Config) splitCredentials(creds *string) []string {
	if creds != nil && *creds != "" {
		c := strings.Split(*creds, " ")
		if strings.Contains(*creds, ",") {
			c = strings.Split(*creds, ",")
		}
		return c
	}
	return nil
}

func (c *Config) regex(rule string) (*ConfRegex, error) {
	exclude := false
	regex := rule

	if strings.HasPrefix(regex, "!") {
		regex = regex[1:]
		exclude = true
	}
	if strings.HasPrefix(regex, "re:") {
		regex = regex[3:]
	} else {
		regex = strings.ReplaceAll(regex, ".", `\.`)
		regex = strings.ReplaceAll(regex, "*", ".*")
		regex = strings.ReplaceAll(regex, "?", ".")
		regex = "^" + strings.ReplaceAll(regex, "|", "$|^") + "$"
	}
	pattern, err := regexp.Compile(regex)
	if err != nil {
		return nil, stacktrace.Propagate(err, "unable to compile regex")
	}
	return &ConfRegex{
		pattern: pattern,
		regex:   regex,
		exclude: exclude,
	}, nil
}

func (c *Config) genCerts() error {
	mitm := false
	for _, rule := range c.conf.Rules {
		if rule.Mitm {
			mitm = true
			break
		}
	}
	if !mitm {
		return nil
	}

	// read/create CA
	caCert := AppName + ".ca.crt"
	caKey := AppName + ".ca.key"
	ca, err := NewCertFromFiles(caCert, caKey)
	if err != nil {
		ca, err = NewCert(NewBasicCACertConfig("kpx ca - "+uuid.NewString(), time.Now().UnixMicro()), 2048, nil)
		if err != nil {
			return fmt.Errorf("unable to generate CA certificate: %v", err)
		}
		err = ca.SaveToFiles(caCert, caKey)
		if err != nil {
			return fmt.Errorf("unable to save CA certificate: %v", err)
		}
	}

	cm, err := NewCertsManager(ca, "kpx:", []string{"**"})
	if err != nil {
		return fmt.Errorf("unable to create certificates manager: %v", err)
	}
	c.certsManager = cm
	return nil
}

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

type Conf struct {
	Bind                        string
	Port                        int
	SocksPort                   int `yaml:"socksPort"`
	Verbose                     bool
	Debug                       bool
	Trace                       bool
	Proxies                     map[string]*ConfProxy
	Credentials                 map[string]*ConfCred
	Domains                     map[string]*string
	Rules                       []*ConfRule
	SocksRules                  []*ConfRule `yaml:"socksRules"`
	pacProxy                    string
	Krb5                        string
	ConnectTimeout              int `yaml:"connectTimeout"`
	IdleTimeout                 int `yaml:"idleTimeout"`
	CloseTimeout                int `yaml:"closeTimeout"`
	Check                       *bool
	Update                      bool
	Restart                     bool
	UseEnvProxy                 bool
	Experimental                string   // space/comma separated list of features
	experimentalConnectionPools bool     // add a connection pool for http
	experimentalHostsCache      bool     // add a hosts cache for proxy lookup - fine grained url lookup is then disabled
	ACL                         []string `yaml:"acl"` //comma-separated list of allowed IPs. If empty everybody is allowed
}

type ConfCred struct {
	name      *string
	Login     *string
	Password  *string
	isNull    bool
	isPerUser bool
	isUsed    bool // set if is not nil, not per user and is used by a a rule => proxy
	isNative  bool // set if using native kerberos implementation
}

type ConfProxy struct {
	name        *string
	Type        *ProxyType
	typeValue   int
	Host        *string
	Port        int
	Verbose     *bool
	Ssl         bool
	Spn         *string
	Realm       *string
	Credential  *string
	Credentials *string
	cred        *ConfCred // cannot be nil for kerberos, basic, and eventually for socks
	Pac         *string
	pacRegex    *ConfRegex
	Url         *string
	pacJs       *string
	// proxy       string
	pacProxy   *string
	isUsed     bool
	pacRuntime *PacExecutor
}

type ConfRule struct {
	Host    *string
	Proxy   *string //
	Dns     *string
	Verbose *bool
	Mitm    bool
	regex   *ConfRegex
	//confProxy *ConfProxy // cannot be nil
}

func (r *ConfRule) firstProxy() string {
	return strings.Split(*r.Proxy, ",")[0]
}

func (r *ConfRule) allProxiesName() []string {
	return strings.Split(*r.Proxy, ",")
}

type ConfRegex struct {
	pattern *regexp.Regexp
	regex   string
	exclude bool
}

type PacResult struct {
	proxy    string
	isDirect bool
	isProxy  bool
	isSocks  bool
	hostPort string
	hostOnly string
}

func (c *Config) newHttpClient() *http.Client {
	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	if !c.conf.UseEnvProxy {
		httpTransport.Proxy = nil
	}
	httpClient := &http.Client{Timeout: 30 * time.Second, Transport: httpTransport}
	return httpClient
}
