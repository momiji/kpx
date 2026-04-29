package kpx

import (
	"container/list"
	"fmt"
	"math"
	"net"
	"os"
	"os/signal"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/momiji/kpx/auth"
	"github.com/momiji/kpx/log"
	"github.com/momiji/kpx/transport"
	"github.com/momiji/kpx/ui"
	"github.com/momiji/kpx/utils"

	"github.com/txthinking/socks5"

	"github.com/fsnotify/fsnotify"
	"github.com/palantir/stacktrace"
)

type Proxy struct {
	config                      atomic.Pointer[Config]  // atomic
	forceStop                   bool                    // not atomic - used only for get/set, no conditional update
	newRequestId                atomic.Int32            // atomic - used in each process
	requestsCount               atomic.Int32            // atomic - used in each connection
	kerberos                    *auth.KerberosStore     // not atomic - used only for get/set, no conditional update - initialized once
	lastModTime                 time.Time               // not atomic - used only for get/set in one coroutine
	lastLoadTime                time.Time               // not atomic - used only for get/set in one coroutine
	loadCounter                 atomic.Int32            // atomic - used in each process to test if config has been updated
	reloadEvent                 *utils.ManualResetEvent //
	fixWatchEvent               *utils.ManualResetEvent //
	connPool                    map[string]*list.List   // must be synced - used in each process
	poolMutex                   sync.Mutex              // atomic - used in each process
	experimentalConnectionPools bool
	consoleUI                   bool

	// krbClients    map[string]*KerberosClient //
	// configPtr     *unsafe.Pointer
}

func (p *Proxy) getConfig() *Config {
	return p.config.Load()
}

func (p *Proxy) setConfig(config *Config) {
	p.config.Store(config)
	p.loadCounter.Add(1)
	trace = config.conf.Trace
	debug = config.conf.Debug
	switch {
	case trace:
		_logger.SetLogLevel(log.LogLevelTrace)
	case debug:
		_logger.SetLogLevel(log.LogLevelDebug)
	default:
		_logger.SetLogLevel(log.LogLevelInfo)
	}

	p.experimentalConnectionPools = config.conf.experimentalConnectionPools
	//
	features := ""
	if config.conf.experimentalConnectionPools {
		features += "," + EXPERIMENTAL_CONNETION_POOLS
	}
	if config.conf.experimentalHostsCache {
		features += "," + EXPERIMENTAL_HOSTS_CACHE
	}
	if features != "" {
		_logger.Infof("[-] Experimental features: " + features[1:])
	}
}

func (p *Proxy) init() error {
	p.forceStop = false
	// p.krbClients = make(map[string]*KerberosClient)
	// p.configPtr = (*unsafe.Pointer)(unsafe.Pointer(&p.unsafeConfig))
	p.reloadEvent = utils.NewManualResetEvent(false)
	p.fixWatchEvent = utils.NewManualResetEvent(false)
	p.connPool = map[string]*list.List{}
	return nil
}

// Initial loading
func (p *Proxy) load() error {
	// load config
	if options.Config != "" {
		file, err := os.Open(options.Config)
		if err != nil {
			return stacktrace.Propagate(err, "unable to open file")
		}
		defer func(file *os.File) {
			_ = file.Close()
		}(file)
		stat, err := file.Stat()
		if err != nil {
			return stacktrace.Propagate(err, "unable to stat file")
		}
		p.lastModTime = stat.ModTime()
		p.lastLoadTime = time.Now()
	}
	config, err := NewConfig(options.Config)
	if err != nil {
		return stacktrace.Propagate(err, "unable to create config")
	}
	p.setConfig(config)
	// ask missing credentials
	err = config.askCredentials()
	if err != nil {
		return stacktrace.Propagate(err, "unable to get credentials")
	}
	// initialize kerberos
	krbConfig := &auth.KerberosConfig{
		KrbString:       config.conf.Krb5,
		DefaultDomain:   AppDefaultDomain,
		DomainMapper:    config.conf.Domains,
		KdcConnTimeout:  time.Duration(config.conf.ConnectTimeout) * time.Second,
		KdcCacheTimeout: KDC_TEST_TIMEOUT * time.Second,
	}
	k, err := auth.NewKerberosStore(krbConfig, _logger)
	if err != nil {
		return stacktrace.Propagate(err, "unable to create kerberos store")
	}
	p.kerberos = k
	// initialize kerberos clients
	err = p.loadKerberos(config)
	if err != nil {
		return stacktrace.Propagate(err, "unable to create kerberos clients")
	}
	return nil
}

func (p *Proxy) loadKerberos(config *Config) error {
	// initialize kerberos clients based on user/realm
	for _, proxy := range config.conf.Proxies {
		if *proxy.Type == ProxyKerberos && proxy.cred != nil && proxy.cred.isUsed {
			if proxy.cred.isNative {
				// try to log in with kerberos
				err := NativeKerberos.SafeTryLogin()
				if err != nil {
					return stacktrace.Propagate(err, "unable to login to native os kerberos")
				}
			} else {
				// try to log in with username/password
				_, err := p.kerberos.SafeTryLogin(*proxy.cred.Login, *proxy.Realm, *proxy.cred.Password, false)
				if err != nil {
					return stacktrace.Propagate(err, "unable to login to kerberos")
				}
			}
		}
	}
	return nil
}

func (p *Proxy) watch1() {
	if trace {
		_logger.Infof("start configuration reload task")
	}
	for {
		select {
		case <-p.reloadEvent.Channel():
		case <-time.After(RELOAD_TEST_TIMEOUT * time.Second):
		}
		p.reloadEvent.Reset()
		if trace {
			_logger.Infof("reload configuration")
		}
		p.reload()
		p.fixWatchEvent.Signal()
	}
}

func (p *Proxy) watch2() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		if trace {
			_logger.Errorf("watcher error: %v", err)
		}
		return
	}
	if trace {
		_logger.Infof("start configuration watcher task")
	}
	timer := time.AfterFunc(math.MaxInt64, func() { p.reloadEvent.Signal() })
	timer.Stop()
	watchPath := path.Dir(options.Config)
	_ = watcher.Add(watchPath)
	for {
		select {
		case <-p.fixWatchEvent.Channel():
			// update watcher's list
			p.fixWatchEvent.Reset()
			wl := watcher.WatchList()
			if len(wl) != 1 || wl[0] != watchPath {
				if trace {
					_logger.Infof("reconfigure watcher")
				}
				_ = watcher.Add(watchPath)
			}
		case e, ok := <-watcher.Errors:
			// watcher error
			if trace {
				_logger.Infof("watcher error: ok=%v %v", ok, e)
			}
		case e, ok := <-watcher.Events:
			// watcher event
			if trace {
				_logger.Infof("watcher event: ok=%v %v", ok, e)
			}
			if !ok {
				continue
			}
			if path.Base(e.Name) == path.Base(options.Config) && (e.Has(fsnotify.Create) || e.Has(fsnotify.Write)) {
				timer.Reset(100 * time.Millisecond)
			}
		}
	}
}

func (p *Proxy) reload() {
	stat, err := os.Stat(options.Config)
	if err != nil {
		return
	}
	oldConfig := p.getConfig()
	if stat.ModTime() == p.lastModTime && time.Now().Before(p.lastLoadTime.Add(RELOAD_FORCE_TIMEOUT*time.Second)) && !oldConfig.needFastReload {
		return
	}
	// test if we need to reload
	newConfig, err := NewConfig(options.Config)
	p.lastModTime = stat.ModTime()
	p.lastLoadTime = time.Now()
	if err != nil {
		_logger.Infof("[-] Error while reloading configuration: %s", err)
		return
	}
	// test if we can hot-reload - no need for more credentials
	for _, cred := range newConfig.conf.Credentials {
		// start by copying old credentials
		oldCred := oldConfig.conf.Credentials[*cred.name]
		if oldCred != nil {
			if cred.Login == nil {
				cred.Login = oldCred.Login
			}
			if cred.Password == nil {
				cred.Password = oldCred.Password
			}
		}
		// then verify if it used it must have a login/password
		if cred.isUsed && !cred.isNative {
			if cred.Login == nil || cred.Password == nil {
				_logger.Infof("[-] Could not Hot-reload the configuration as it requires new credentials")
				return
			}
		}
	}
	_logger.Infof("[-] Hot-reload of the configuration succeeded")
	// replace current config with the new one
	p.setConfig(newConfig)
}

func (p *Proxy) run() error {
	// get config that won't be hot reloaded as ports cannot be changed afterwards
	config := p.getConfig()

	// start automatic exit
	if options.Timeout > 0 {
		go func() {
			<-time.After(time.Duration(options.Timeout) * time.Second)
			p.exit(0)
		}()
		_logger.Infof("[-] Proxy will exit automatically in %v seconds", options.Timeout)
	}

	// start http server
	if config.conf.Port != 0 {
		ln, err := net.Listen("tcp4", fmt.Sprint(config.conf.Bind, ":", config.conf.Port))
		if err != nil {
			return stacktrace.Propagate(err, "unable to listen on %s:%d", config.conf.Bind, config.conf.Port)
		}

		hostPort := ln.Addr().String()
		_logger.Infof("[-] Use %s as your http proxy or http://%s/proxy.pac as your proxy PAC url", hostPort, hostPort)

		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					continue
				}
				remoteIp := strings.Split(conn.RemoteAddr().String(), ":")[0]
				if !p.isAllowed(remoteIp, p.getConfig().conf.ACL) {
					_logger.Infof("[-] Connection from %s is not allowed by ACL", remoteIp)
					_ = conn.Close() // force closing client, ignore any error
					continue
				}
				transport.ConfigureConn(conn)
				if p.stopped() {
					_ = conn.Close() // force closing client, ignore any error
					break
				}
				if trace {
					_logger.Infof("new connection")
				}
				go func() {
					c := p.requestsCount.Add(1)
					if trace {
						_logger.Infof("connections count=%d", c)
					}
					NewProcess(p, conn).processHttp()
					c = p.requestsCount.Add(-1)
					if trace {
						_logger.Infof("connections count=%d", c)
					}
				}()
			}
		}()
	}

	// start socks5 server
	errChan := make(chan error)
	if config.conf.SocksPort != 0 {
		socks, err := socks5.NewClassicServer(fmt.Sprintf("%s:%d", config.conf.Bind, config.conf.SocksPort), config.conf.Bind, "", "", 0, 60)
		if err != nil {
			return stacktrace.Propagate(err, "unable to create socks server on %s:%d", config.conf.Bind, config.conf.SocksPort)
		}
		_logger.Infof("[-] Use %s as your socks5 proxy and configure it to use remote dns - curl syntax is 'curl -x socks5h://%s' or 'curl --socks5-hostname %s'", socks.Addr, socks.Addr, socks.Addr)
		go func() {
			err = socks.ListenAndServe(p)
			if err != nil {
				errChan <- stacktrace.Propagate(err, "unable to listen on %s:%d", config.conf.Bind, config.conf.SocksPort)
			}
		}()
	}

	// start console ui and data cleanup
	if p.consoleUI {
		_logger.Infof("[-] Starting console UI")
		go func() {
			time.Sleep(1 * time.Second)
			ui.SwitchUI(false)
		}()
	}
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		for {
			select {
			case <-ticker.C:
				ui.TrafficData.RemoveDead()
			}
		}
	}()

	// wait forever, only exit() can stop or a previous return with an error
	select {
	case err := <-errChan:
		return err
	}
}

func (p *Proxy) TCPHandle(server *socks5.Server, conn *net.TCPConn, request *socks5.Request) error {
	if request.Cmd != socks5.CmdConnect {
		_logger.Infof("[-] TCP socks proxy is not implemented for command %b", request.Cmd)
		return nil
	}
	// return any address, not important as we are using connect?
	a, addr, port, err := socks5.ParseAddress("127.0.0.1:12345")
	if err != nil {
		conn.Close()
		return err
	}
	if a == socks5.ATYPDomain {
		addr = addr[1:]
	}
	reply := socks5.NewReply(socks5.RepSuccess, a, addr, port)
	if _, err := reply.WriteTo(conn); err != nil {
		conn.Close()
		return err
	}

	NewProcess(p, conn).processSocks(request)
	return nil
}

func (p *Proxy) UDPHandle(server *socks5.Server, addr *net.UDPAddr, datagram *socks5.Datagram) error {
	_logger.Infof("[-] UDP socks proxy is not implemented")
	return nil
}

func (p *Proxy) stop() {
	p.forceStop = true
	p.exit(1)
}

func (p *Proxy) stopped() bool {
	return p.forceStop
}

// generate a new kerberos ticket, using a new client if not yet cached per realm/username/password
func (p *Proxy) generateKerberosNegotiate(username string, realm string, password string, protocol string, host string) (*string, error) {
	if p.stopped() {
		return nil, nil
	}
	token, err := p.kerberos.SafeGetToken(username, realm, password, protocol, host)
	if err != nil {
		return nil, stacktrace.Propagate(err, "unable to get kerberos token")
	}
	auth := "Negotiate " + *token
	return &auth, nil
}

func (p *Proxy) generateKerberosNative(protocol string, host string) (*string, error) {
	if p.stopped() {
		return nil, nil
	}
	token, err := NativeKerberos.SafeGetToken(protocol, host)
	if err != nil {
		return nil, stacktrace.Propagate(err, "unable to get kerberos token")
	}
	auth := "Negotiate " + *token
	return &auth, nil
}

// check if ip is in the list of allowed ips or cidrs
func (p *Proxy) isAllowed(ip string, acl []string) bool {
	for _, a := range acl {
		if strings.Contains(a, "/") {
			_, cidr, _ := net.ParseCIDR(a)
			if cidr != nil && cidr.Contains(net.ParseIP(ip)) {
				return true
			}
		} else if a == ip {
			return true
		}
	}
	return acl == nil || len(acl) == 0
}

func (p *Proxy) exit(code int) {
	if p.consoleUI {
		// force stop UI
		ui.StopUI()
		<-ui.StoppedUI
	}
	// logDestroy()
	_logger.Destroy()
	os.Exit(code)
}

func (p *Proxy) ui() {
	// exit signal handler to close ui correctly
	exitSignal := make(chan os.Signal, 1)
	signal.Notify(exitSignal, syscall.SIGINT, syscall.SIGTERM)
	// replace logger writer with suspendable ui writer
	// logWriter(ui.WriterUI(os.Stdout))
	_logger.SetMode(log.LogModeNone)
	// start ui
	go ui.RunUI(true)
	// wait for exit signal
loop:
	for {
		select {
		case <-exitSignal:
			ui.StopUI()
		case <-ui.StoppedUI:
			break loop
		}
	}
	p.exit(0)
}
