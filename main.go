package kpx

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"text/template"
	"time"

	"github.com/jcmturner/gokrb5/v8/client"
)

var VersionValue = ""
var VersionTemplate = "{{.AppName}} {{.AppVersion}} - {{.AppUrl}}"

var UsageValue = ""
var UsageTemplate = `
{{.AppName}} is a Kerberos authenticating HTTP/1.1 proxy, that forwards requests to any upstream proxies and servers.
It exposes an anonymous proxy, automatically injecting required credentials when forwarding requests.
It also provides a javascript proxy.pac to be used in browser or system proxy, at 'http://HOST:PORT/proxy.pac'.

Usage: {{.AppName}} [-dtv] [-u <user@domain>] [-l <[ip:]port>] [-c <config>] [-k <key>]
       {{.AppName}} [-dtv] [-u <user@domain>] [-l <[ip:]port>] [--timeout TIMEOUT] <proxy:port>
       {{.AppName}} -e [-k <key>]

Example:
       {{.AppName}} -u user_login@eur -l 8888 proxy:8080

Options:
      -c, --config=<config>      config file, in yaml format (defaults to '{{.AppName}}.yaml' then '{{.AppName}}.json')
      -k, --key=<key>            encryption key location (defaults to '{{.AppName}}.key')
      -l, --listen=<[ip:]port>   listen to this ip port (ip defaults to 127.0.0.1, port defaults to 8080)
      -u, --user=<user@domain>   user for authentication, like login@domain or domain\login
                                 ! domain is case-sensitive in Kerberos, however it is uppercased as all internet usage seems to be uppercase
                                 domain is automatically expanded to {{.AppDefaultDomain}} when set from command line
                                 can also replace user in configuration file, when there is only one user defined
	      --acl=<ips>            list of comma-separated IPs, who is allowed to connect
          --timeout TIMEOUT      automatically stop {{.AppName}} after TIMEOUT seconds, when run without config file, defaults to 3600s = 1h (set to 0 to disable)
      -e, --encrypt              encrypt a password, encryption key location is {{.AppName}}.key  
      -d, --debug                run in debug mode, displaying all headers
      -t, --trace                run in trace mode, displaying everything
      -v, --verbose              run in verbose mode, displaying all requests (automatically set if run without config file)
      -h, --help                 show full help with config file format
      -V, --version              show version

Note1: remote HTTPS proxies has not been tested, as none was available for testing.
Note2: failover proxies can be configured for a single rule "proxy: proxy1,proxy2,...", but only works for non-pac proxies, and assumes all proxies are "almost" of the same type.
Note3: failover hosts can be configured for a single proxy "host: host1,host2,...", but only works for non-pac proxies.
`

var HelpValue = ""

var HelpTemplate = `
CONFIG FILE
===========
A config file can be provided as json or yaml format.
Content should be similar to this:

# listen to this ip, use 0.0.0.0 to listen on all ips
bind: 127.0.0.1
# listen to this port to serve HTTP requests
port: 7777
# listen to this port to serve SOCKS requests
socksPort: 7778
# set verbose to see all requests
verbose: true
# set debug to view all requests and responses headers
debug: true
# set debug to view everything
trace: false
# timeout for connecting
connectTimeout: 10
# timeout for existing connections, waiting for incoming data
idleTimeout: 0
# timeout for closing connections after one side closed it, allowing to flush the remaining buffered data
closeTimeout: 10
# check for updates, defaults to true
check: true
# automatically update, defaults to false
update: false
# exit after update, defaults to false, use only if a restart mechanism is implemented outside
restart: false
# use proxy environment variables for downloading updates and pac files, defaults to false
useEnvProxy: false

# list of proxies
proxies:
# sample of a PAC proxy. 'credentials' is used to list the users we need to get login/password on startup
  pac-mkt:
    type: pac
    url: http://broproxycfg.int.world.company/ProxyPac/proxy.pac
    credentials: user
# another PAC proxy. verbosity can also be set at proxy level
  pac-ret:
    type: pac
    url: http://broproxycfg.int.world.company/ProxyPac/proxy.pac
    credentials: user
	verbose: true
# sample of kerberos proxy. 'pac' is used to get the kerberos realm in PAC proxies at runtime
  mkt:
    type: kerberos
    spn: HTTP
    realm: EUR.MSD.WORLD.COMPANY
    host: proxy-mkt.int.world.company
    port: 8080
    credential: user
    pac: proxy-mkt*
  ret:
    type: kerberos
    spn: HTTP
    realm: EUR.MSD.WORLD.COMPANY
    host: proxy-sgt.si.company
    port: 8080
    credential: user
    pac: proxy-sgt*
# sample of anonymous (no authentication) proxy. 'ssl' for HTTPS proxy
  net:
    type: anonymous
    host: 127.0.0.1
    port: 3128
	ssl: false
# sample of socks proxy
  nets:
    type: socks
    host: localhost
    port: 1080
  dev:
    type: anonymous
    host: localhost
    port: 3129
  devs:
    type: socks
    host: localhost
    port: 1081
    ssl: false
# sample of basic (base64 encoding) proxy. 'credential' is the user to get login/password on startup
  basic:
    type: basic
    host: proxy-mkt.int.world.company
    port: 8080
    credential: user

# list of credentials
credentials:
# sample of credential. if no 'password', it will be asked on startup. the same for login
# password can be provided as clear text, or encrypted using '-e' option
  user:
    login: a443939
    password: encrypted:SECRET_KEY

# list of rules to determine which proxy to use for HTTP proxy
rules:
# sample: direct connection for this host
  - host: "test-proxy-pac1"
    proxy: direct
    dns: 127.0.0.1
# sample: alter ip and or port resolution for this host. syntax is [IP]:[PORT]. no port means use the same port as source
  - host: "test-proxy-pac2"
    dns: 127.0.0.1:7777
  - host: "test-socks-conf"
    proxy: devs
    dns: 127.0.0.1
# sample: multiple hosts, separated by '|'. add '!' at the beginning to inverse rule. verbosity can also be set at rule level
  - host: 192.168.2.6|osmose-homo*
    proxy: devs
  - host: "*.safe.company|*.si.company|*.ressources.company|*.world.company"
    proxy: direct
    verbose: true
# sample: regex can be used for host, add 're:' at the beginning. add '!re:' to inverse rule
  - host: "re:^github\.com$|^gitlab.com$"
    proxy: mkt
    verbose: true
# sample: use mitm to have man-int-the-middle hijacked connections, CA is written in {{.AppName}}.ca.crt 
  - host: "update.microsoft.com"
    proxy: mkt
    verbose: true
    mitm: true
# sample: proxy 'none' goes nowhere, result is always 400 bad request
  - host: "microsoft.com"
    proxy: none
    verbose: true
# sample: use '*' host as a catch all
  - host: "*"
    proxy: pac-mkt
    verbose: true

# list of rules to determine which proxy to use for SOCKS proxy
socksRules:
  # sample: direct connection for this host
  - host: "test-proxy-pac1"
    proxy: direct
    dns: 127.0.0.1
  # sample: use '*' host as a catch all
  - host: "*"
    proxy: net

# list some domain aliases, allowing to use 'EUR' instead of 'EUR.MSD.WORLD.COMPANY'
domains:
  EUR: EUR.MSD.WORLD.COMPANY
  ASI: ASI.MSD.WORLD.COMPANY
  AME: AME.MSD.WORLD.COMPANY

# list of IPs who is allowed to connect. If empty - everybody is allowed
acl:
  - 127.0.0.1
  - 192.168.0.1
`

func Main() {
	var values = map[string]string{
		"AppName":          AppName,
		"AppUrl":           AppUrl,
		"AppDefaultDomain": AppDefaultDomain,
		"AppVersion":       AppVersion,
	}
	VersionValue = templates(VersionTemplate, values)
	UsageValue = templates(UsageTemplate, values)
	HelpValue = templates(HelpTemplate, values)
	client.MyCrossDomainPatch() // Ensure krb5 library is pacthed for Cross-Domain support
	logInit()
	defer logDestroy()
	cmd()
	start()
}

func templates(text string, values map[string]string) string {
	var tpl bytes.Buffer
	_ = template.Must(template.New("").Parse(text)).Execute(&tpl, values)
	return tpl.String()
}

func usage() {
	fmt.Printf("\n%s\n%s\n", VersionValue, UsageValue)
	os.Exit(1)
}

func help() {
	fmt.Printf("%s\n%s\n%s\n", VersionValue, UsageValue, HelpValue)
	os.Exit(0)
}
func version() {
	fmt.Printf("%s\n", VersionValue)
	os.Exit(0)
}

func cmd() {
	flag.Usage = usage
	flag.StringVar(&options.Config, "c", "", "")
	flag.StringVar(&options.Config, "config", "", "")
	flag.StringVar(&options.KeyFile, "k", AppName+".key", "")
	flag.StringVar(&options.KeyFile, "key", AppName+".key", "")
	flag.StringVar(&options.Listen, "l", "", "")
	flag.StringVar(&options.Listen, "listen", "", "")
	flag.StringVar(&options.User, "u", "", "")
	flag.StringVar(&options.User, "user", "", "")
	flag.IntVar(&options.Timeout, "timeout", 3600, "")
	flag.BoolVar(&options.Encrypt, "e", false, "")
	flag.BoolVar(&options.Encrypt, "encrypt", false, "")
	flag.BoolVar(&options.Debug, "d", false, "")
	flag.BoolVar(&options.Debug, "debug", false, "")
	flag.BoolVar(&options.Trace, "t", false, "")
	flag.BoolVar(&options.Trace, "trace", false, "")
	flag.BoolVar(&options.Verbose, "v", false, "")
	flag.BoolVar(&options.Verbose, "verbose", false, "")
	flag.BoolVar(&options.ShowHelp, "h", false, "")
	flag.BoolVar(&options.ShowHelp, "help", false, "")
	flag.BoolVar(&options.ShowVersion, "V", false, "")
	flag.BoolVar(&options.ShowVersion, "version", false, "")
	var acl string
	flag.StringVar(&acl, "acl", "", "")
	options.ACL = strings.Split(acl, ",")
	flag.Parse()
	args := flag.Args()

	switch {
	case options.ShowHelp:
		help()
	case options.ShowVersion:
		version()
	case options.Encrypt:
		encryptPassword()
	case len(args) == 1 && options.Config != "":
		println("invalid arguments")
		usage()
	case len(args) > 1:
		println("invalid arguments")
		usage()
	case len(args) == 1:
		options.Proxy = args[0]
	}

	logPrintf("[-] Proxy %s started\n", VersionValue)

	if options.Proxy == "" {
		if options.Config == "" {
			if _, err := os.Stat(AppName + ".yaml"); err == nil {
				options.Config = AppName + ".yaml"
			} else if _, err := os.Stat(AppName + ".json"); err == nil {
				options.Config = AppName + ".json"
			} else {
				options.Config = AppName + ".yaml"
			}
		}
		options.Timeout = 0
	} else {
		options.Config = ""
		options.Verbose = true
		if options.Listen == "" {
			options.Listen = ":"
		}
		h, p := splitHostPort(options.Listen, "127.0.0.1", "8080", true)
		options.Listen = h + ":" + p
		options.bindHost = h
		options.bindPort, _ = strconv.Atoi(p)
		h, p = splitHostPort(options.Proxy, "127.0.0.1", "8080", true)
		options.Proxy = h + ":" + p
		options.proxyHost = h
		options.proxyPort, _ = strconv.Atoi(p)
		if options.User == "" {
			logPrintf("[-] Credential [user] - Enter login with full domain name: ")
			_, err := fmt.Scanln(&options.User)
			if err != nil || options.User == "" {
				logFatal("[-] Error: invalid empty value for flag -u")
			}
		}
		options.login, options.domain = splitUsername(options.User, "")
		if options.domain == "" {
			logFatal("[-] Error: invalid value %q for flag -u: missing domain", options.User)
		}
		if !strings.Contains(options.domain, ".") {
			options.domain = options.domain + AppDefaultDomain
		}
	}

	options.Verbose = options.Verbose || options.Debug || options.Trace
	options.Debug = options.Debug || options.Trace

	debug = options.Debug
	trace = options.Trace
}

func splitUsername(username, realm string) (string, string) {
	if strings.Contains(username, `\`) {
		p := strings.LastIndex(username, `\`)
		realm = username[:p]
		username = username[p+1:]
	} else if strings.Contains(username, "@") {
		p := strings.LastIndex(username, "@")
		realm = username[p+1:]
		username = username[:p]
	}
	realm = strings.ToUpper(realm)
	return username, realm
}

func splitHostPort(hostPort, defaultHost, defaultPort string, portFirst bool) (string, string) {
	hp := strings.SplitN(hostPort, ":", 2)
	var host, port string
	if len(hp) == 1 {
		if portFirst {
			host = ""
			port = hp[0]
		} else {
			host = hp[0]
			port = ""
		}
	} else if len(hp) == 2 {
		host = hp[0]
		port = hp[1]
	}
	host = strings.TrimSpace(host)
	port = strings.TrimSpace(port)
	if host == "" {
		host = defaultHost
	}
	if port == "" {
		port = defaultPort
	}
	return host, port
}

func start() {
	proxy := Proxy{}
	err := proxy.init()
	if err != nil {
		logFatal("[-] Error: %s", err)
	}
	err = proxy.load()
	if err != nil {
		logFatal("[-] Error: %s", err)
	}
	// reload task
	go proxy.watch1()
	go proxy.watch2()
	// update task
	if !strings.HasPrefix(AppVersion, "dev") {
		go func() {
			time.Sleep(3 * time.Second)
			for {
				update(&proxy)
				time.Sleep(time.Hour)
			}
		}()
	}
	// start proxy
	err = proxy.run()
	if err != nil {
		logFatal("[-] Error: %s", err)
	}
	proxy.stop()
}

func update(proxy *Proxy) {
	// check for updates ?
	config := proxy.getConfig()
	conf := config.conf
	if conf.Check != nil && *conf.Check == false {
		return
	}
	// get update name
	list := map[string]string{
		"windows/amd64": AppName + ".exe",
		"linux/amd64":   AppName,
		"darwin/amd64":  AppName + ".macos",
	}
	nameOsArch := runtime.GOOS + "/" + runtime.GOARCH
	updateName, ok := list[nameOsArch]
	if !ok {
		return
	}
	// download releases list
	url := AppUpdateUrl
	if url == "" {
		return
	}
	logInfo("[-] Checking for updates: %s", url)
	httpClient := config.newHttpClient()
	get, err := httpClient.Get(url)
	if err != nil {
		logError("[-] Update failed: %v", err)
		return
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(get.Body)
	jsb, err := io.ReadAll(get.Body)
	if err != nil {
		logError("[-] Update failed: %v", err)
		return
	}
	js := map[string]any{}
	err = json.Unmarshal(jsb, &js)
	if err != nil {
		logError("[-] Update failed: %v", err)
		return
	}
	// check for new version
	ver := jsString(js, "name")
	if ver == AppVersion || ver == "v"+AppVersion {
		logInfo("[-] No update available")
		return
	}
	// find download url
	assetUrl := ""
	assets := jsSlice(js, "assets")
	for _, a := range assets {
		asset := jsMap(a)
		if asset != nil {
			name := jsString(asset, "name")
			if name != updateName {
				continue
			}
			assetUrl = jsString(asset, "browser_download_url")
			break
		}
	}
	if assetUrl == "" {
		logInfo("[-] No download url available")
		return
	}
	logInfo("[-] New version %s found", ver)
	// automatically update ?
	if !conf.Update {
		logInfo("[-] Skipping update (update=false)")
		return
	}
	// download release
	logInfo("[-] Downloading update: %s", assetUrl)
	exe, err := os.Executable()
	if err != nil {
		logError("[-] Download failed: %v", err)
		return
	}
	stat, err := os.Stat(exe)
	if err != nil {
		logError("[-] Download failed: %v", err)
		return
	}
	_ = os.Remove(exe + ".new")
	file, err := os.Create(exe + ".new")
	if err != nil {
		logError("[-] Download failed: %v", err)
		return
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)
	writer := bufio.NewWriter(file)
	defer func(name string) {
		_ = os.Remove(name)
	}(file.Name())
	get, err = httpClient.Get(assetUrl)
	if err != nil {
		logError("[-] Download failed: %v", err)
		return
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(get.Body)
	_, err = io.Copy(writer, get.Body)
	if err != nil {
		logError("[-] Download failed: %v", err)
		return
	}
	err = writer.Flush()
	if err != nil {
		logError("[-] Download failed: %v", err)
		return
	}
	err = file.Close()
	if err != nil {
		logError("[-] Download failed: %v", err)
		return
	}
	// replace executable
	logInfo("[-] Installing update: %s", exe)
	err = os.Chmod(file.Name(), stat.Mode())
	if err != nil {
		logError("[-] Install failed: %v", err)
		return
	}
	_ = os.Remove(exe + ".old")
	err = syscall.Rename(exe, exe+".old")
	if err != nil {
		logError("[-] Install failed: %v", err)
		return
	}
	err = syscall.Rename(exe+".new", exe)
	if err != nil {
		logError("[-] Install failed: %v", err)
		return
	}
	// restart ?
	if !conf.Restart {
		logInfo("[-] Skipping restart (restart=false)")
		return
	}
	if config.disableAutoUpdate {
		logInfo("[-] Skipping restart (interactive login/password)")
		return
	}

	// exit
	logInfo("[-] Exiting on update (restart=true)")
	logDestroy()
	os.Exit(200)
}

func jsString(v map[string]any, s string) string {
	if a, ok := v[s]; ok {
		if b, ok := a.(string); ok {
			return b
		}
	}
	return ""
}

func jsSlice(v map[string]any, s string) []any {
	if a, ok := v[s]; ok {
		if b, ok := a.([]any); ok {
			return b
		}
	}
	return nil
}

func jsMap(v any) map[string]any {
	if a, ok := v.(map[string]any); ok {
		return a
	}
	return nil
}
