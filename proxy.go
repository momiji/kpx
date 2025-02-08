package kpx

import (
	"container/list"
	"fmt"
	"math"
	"net"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/txthinking/socks5"

	"github.com/fsnotify/fsnotify"
	"github.com/palantir/stacktrace"
	"golang.org/x/exp/slices"
)

type Proxy struct {
	config                      atomic.Pointer[Config] // atomic
	forceStop                   bool                   // not atomic - used only for get/set, no conditional update
	newRequestId                atomic.Int32           // atomic - used in each process
	requestsCount               atomic.Int32           // atomic - used in each connection
	kerberos                    *KerberosStore         // not atomic - used only for get/set, no conditional update - initialized once
	lastModTime                 time.Time              // not atomic - used only for get/set in one coroutine
	lastLoadTime                time.Time              // not atomic - used only for get/set in one coroutine
	loadCounter                 atomic.Int32           // atomic - used in each process to test if config has been updated
	reloadEvent                 *ManualResetEvent      //
	fixWatchEvent               *ManualResetEvent      //
	connPool                    map[string]*list.List  // must be synced - used in each process
	poolMutex                   sync.Mutex             // atomic - used in each process
	experimentalConnectionPools bool

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
		logInfo("[-] Experimental features: " + features[1:])
	}
}

func (p *Proxy) init() error {
	p.forceStop = false
	// p.krbClients = make(map[string]*KerberosClient)
	// p.configPtr = (*unsafe.Pointer)(unsafe.Pointer(&p.unsafeConfig))
	p.reloadEvent = NewManualResetEvent(false)
	p.fixWatchEvent = NewManualResetEvent(false)
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
	k, err := NewKerberosStore(config)
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
				_, err := p.kerberos.safeTryLogin(*proxy.cred.Login, *proxy.Realm, *proxy.cred.Password, false)
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
		logInfo("start configuration reload task")
	}
	for {
		select {
		case <-p.reloadEvent.Channel():
		case <-time.After(RELOAD_TEST_TIMEOUT * time.Second):
		}
		p.reloadEvent.Reset()
		if trace {
			logInfo("reload configuration")
		}
		p.reload()
		p.fixWatchEvent.Signal()
	}
}

func (p *Proxy) watch2() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		if trace {
			logError("watcher error: %v", err)
		}
		return
	}
	if trace {
		logInfo("start configuration watcher task")
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
					logInfo("reconfigure watcher")
				}
				_ = watcher.Add(watchPath)
			}
		case e, ok := <-watcher.Errors:
			// watcher error
			if trace {
				logInfo("watcher error: ok=%v %v", ok, e)
			}
		case e, ok := <-watcher.Events:
			// watcher event
			if trace {
				logInfo("watcher event: ok=%v %v", ok, e)
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
		logInfo("[-] Error while reloading configuration: %s", err)
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
				logInfo("[-] Could not Hot-reload the configuration as it requires new credentials")
				return
			}
		}
	}
	logInfo("[-] Hot-reload of the configuration succeeded")
	// replace current config with the new one
	p.setConfig(newConfig)
}

func (p *Proxy) run() error {
	config := p.getConfig()

	// start automatic exit
	if options.Timeout > 0 {
		go func() {
			<-time.After(time.Duration(options.Timeout) * time.Second)
			logDestroy()
			os.Exit(0)
		}()
		logInfo("[-] Proxy will exit automatically in %v seconds", options.Timeout)
	}

	// start automatic pool vacuum
	go func() {
		for !p.stopped() {
			<-time.After(time.Duration(POOL_CLOSE_TIMEOUT) * time.Second)
			p.vacuumPool()
		}
	}()

	// start http server
	if config.conf.Port != 0 {
		ln, err := net.Listen("tcp4", fmt.Sprint(config.conf.Bind, ":", config.conf.Port))
		if err != nil {
			return stacktrace.Propagate(err, "unable to listen on %s:%d", config.conf.Bind, config.conf.Port)
		}

		hostPort := ln.Addr().String()
		logInfo("[-] Use %s as your http proxy or http://%s/proxy.pac as your proxy PAC url", hostPort, hostPort)

		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					continue
				}
				if config.conf.ACL != nil {
					if !slices.Contains(config.conf.ACL, strings.Split(conn.RemoteAddr().String(), ":")[0]) {
						conn.Close()
						continue
					}
				}
				ConfigureConn(conn)
				if p.stopped() {
					_ = conn.Close() // force closing client, ignore any error
					break
				}
				if trace {
					logInfo("new connection")
				}
				go func() {
					c := p.requestsCount.Add(1)
					if trace {
						logInfo("connections count=%d", c)
					}
					NewProcess(p, conn).processHttp()
					c = p.requestsCount.Add(-1)
					if trace {
						logInfo("connections count=%d", c)
					}
				}()
			}
		}()
	}

	// start socks5 server
	if config.conf.SocksPort != 0 {
		socks, err := socks5.NewClassicServer(fmt.Sprintf("%s:%d", config.conf.Bind, config.conf.SocksPort), config.conf.Bind, "", "", 0, 60)
		if err != nil {
			return stacktrace.Propagate(err, "unable to create socks server on %s:%d", config.conf.Bind, config.conf.SocksPort)
		}
		logInfo("[-] Use %s as your socks5 proxy and configure it to use remote dns - curl syntax is 'curl -x socks5h://%s' or 'curl --socks5-hostname %s'", socks.Addr, socks.Addr, socks.Addr)
		err = socks.ListenAndServe(p)
		if err != nil {
			return stacktrace.Propagate(err, "unable to listen on %s:%d", config.conf.Bind, config.conf.SocksPort)
		}
	}

	// wait forever, only exit() can stop or a previous return with an error
	select {}
}

func (p *Proxy) TCPHandle(server *socks5.Server, conn *net.TCPConn, request *socks5.Request) error {
	if request.Cmd != socks5.CmdConnect {
		logInfo("[-] TCP socks proxy is not implemented for command %b", request.Cmd)
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
	logInfo("[-] UDP socks proxy is not implemented")
	return nil
}

func (p *Proxy) stop() {
	p.forceStop = true
	logDestroy()
	os.Exit(1)
}

func (p *Proxy) stopped() bool {
	return p.forceStop
}

// generate a new kerberos ticket, using a new client if not yet cached per realm/username/password
func (p *Proxy) generateKerberosNegotiate(username string, realm string, password string, protocol string, host string) (*string, error) {
	if p.stopped() {
		return nil, nil
	}
	token, err := p.kerberos.safeGetToken(username, realm, password, protocol, host)
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

type PooledConnection struct {
	conn    *CloseAwareConn
	timeout time.Time
	reqId   int32
}

type PooledConnectionInfo struct {
	key   string
	conn  *CloseAwareConn
	reqId int32
}

func (p *Proxy) newPooledConn(dialer *net.Dialer, network string, proxy string, host string, context string, reqId int32) (bool, *PooledConnectionInfo, error) {
	key := network + "/" + proxy + "/" + context + "/" + host
	if p.experimentalConnectionPools {
		p.poolMutex.Lock()
		defer p.poolMutex.Unlock()
		var items *list.List
		if l, ok := p.connPool[key]; ok {
			items = l
		} else {
			l = list.New()
			p.connPool[key] = l
			items = l
		}
		for {
			item := items.Front()
			if item == nil {
				break
			}
			items.Remove(item)
			pc := item.Value.(*PooledConnection)
			if pc.timeout.After(time.Now()) {
				if trace {
					logInfo("(%d) reusing connection %d from pool", reqId, pc.reqId)
				}
				_ = pc.conn.SetDeadline(time.Time{})
				pc.conn.Reset(reqId)
				return true, &PooledConnectionInfo{key, pc.conn, pc.reqId}, nil
			} else {
				_ = pc.conn.Close()
			}
			if trace {
				logInfo("(%d) removed old connection %d from pool", reqId, pc.reqId)
			}
		}
	}
	// create a new connection
	c, err := NewCloseAwareConn(dialer, network, proxy, reqId)
	return false, &PooledConnectionInfo{key, c, reqId}, err
}

func (p *Proxy) pushConnToPool(info *PooledConnectionInfo, reqId int32) {
	if p.experimentalConnectionPools {
		if trace {
			logInfo("(%d) pushing connection %d to pool for later reuse", reqId, info.reqId)
		}
		p.poolMutex.Lock()
		defer p.poolMutex.Unlock()
		poolTimeout := time.Now().Add(POOL_CLOSE_TIMEOUT * time.Second)
		closeTimeout := poolTimeout.Add(POOL_CLOSE_TIMEOUT_ADD * time.Second)
		if err := info.conn.SetDeadline(closeTimeout); err == nil {
			var items *list.List
			if l, ok := p.connPool[info.key]; ok {
				items = l
			} else {
				l = list.New()
				p.connPool[info.key] = l
				items = l
			}
			items.PushBack(&PooledConnection{conn: info.conn, timeout: poolTimeout, reqId: info.reqId})
		}
	}
}

func (p *Proxy) vacuumPool() {
	if trace {
		logInfo("deleting connections from pool")
	}
	p.poolMutex.Lock()
	defer p.poolMutex.Unlock()
	now := time.Now()
	total := 0
	count := 0
	for key, items := range p.connPool {
		var next *list.Element
		for e := items.Front(); e != nil; e = next {
			total++
			next = e.Next()
			pc := e.Value.(*PooledConnection)
			if pc.timeout.After(now) {
				count++
				_ = pc.conn.Close()
				items.Remove(e)
			}
		}
		if items.Len() == 0 {
			delete(p.connPool, key)
		}
	}
	if trace {
		logInfo("%d connections removed from pool, %d remaining", count, total-count)
	}
}
