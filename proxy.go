package kpx

import (
	"container/list"
	"fmt"
	"github.com/fsnotify/fsnotify"
	"github.com/palantir/stacktrace"
	"math"
	"net"
	"os"
	"path"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

type Proxy struct {
	unsafeConfig  *Config
	configPtr     *unsafe.Pointer
	forceStop     *AtomicBool
	newRequestId  *AtomicInt
	requestsCount *AtomicInt
	kerberos      *KerberosStore
	krbClients    map[string]*KerberosClient
	lastLoad      time.Time
	loadCounter   *AtomicInt
	reloadEvent   *ManualResetEvent
	fixWatchEvent *ManualResetEvent
	connPool      map[string]*list.List
	poolMutex     sync.Mutex
}

func (p *Proxy) safeGetConfig() *Config {
	return (*Config)(atomic.LoadPointer(p.configPtr))

}
func (p *Proxy) safeSetConfig(config *Config) {
	atomic.StorePointer(p.configPtr, unsafe.Pointer(config))
	p.loadCounter.IncrementAndGet(1)
	trace = config.conf.Trace
	debug = config.conf.Debug
}

func (p *Proxy) init() error {
	p.forceStop = NewAtomicBool(false)
	p.newRequestId = NewAtomicInt(0)
	p.requestsCount = NewAtomicInt(0)
	p.krbClients = make(map[string]*KerberosClient)
	p.configPtr = (*unsafe.Pointer)(unsafe.Pointer(&p.unsafeConfig))
	p.loadCounter = NewAtomicInt(0)
	p.reloadEvent = NewManualResetEvent(false)
	p.fixWatchEvent = NewManualResetEvent(false)
	p.connPool = map[string]*list.List{}
	return nil
}

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
		p.lastLoad = stat.ModTime()
	}
	config, err := NewConfig(options.Config)
	if err != nil {
		return stacktrace.Propagate(err, "unable to create config")
	}
	p.safeSetConfig(config)
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
			// try to login
			_, err := p.kerberos.safeTryLogin(*proxy.cred.Login, *proxy.Realm, *proxy.cred.Password, false)
			if err != nil {
				return stacktrace.Propagate(err, "unable to login to kerberos")
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
		case <-time.After(10 * time.Second):
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
	if stat.ModTime() == p.lastLoad {
		return
	}
	// test if we need to reload
	newConfig, err := NewConfig(options.Config)
	p.lastLoad = stat.ModTime()
	if err != nil {
		logInfo("[-] Error while reloading configuration: %s", err)
		return
	}
	oldConfig := p.safeGetConfig()
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
		if cred.isUsed {
			if cred.Login == nil || cred.Password == nil {
				logInfo("[-] Could not Hot-reload the configuration as it requires new credentials")
				return
			}
		}
	}
	logInfo("[-] Hot-reload of the configuration succeeded")
	// replace current config with the new one
	p.safeSetConfig(newConfig)
}

func (p *Proxy) run() error {
	config := p.safeGetConfig()
	ln, err := net.Listen("tcp4", fmt.Sprint(config.conf.Bind, ":", config.conf.Port))
	if err != nil {
		return stacktrace.Propagate(err, "unable to listen to %s:%d", config.conf.Bind, config.conf.Port)
	}

	hostPort := ln.Addr().String()
	logInfo("[-] Use http://%s as your proxy url or http://%s/proxy.pac as your pac url", hostPort, hostPort)
	if options.Timeout > 0 {
		go func() {
			<-time.After(time.Duration(options.Timeout) * time.Second)
			os.Exit(0)
		}()
		logInfo("[-] Proxy will exit automatically in %v seconds", options.Timeout)
	}
	/*go func() {
		for {
			logInfo("[-] Status (goroutines,requests): %d, %d", runtime.NumGoroutine(), p.requestsCount.Get())
			time.Sleep(60 * time.Second)
		}
	}()*/

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		if p.forceStop.IsSet() {
			_ = conn.Close() // force closing client, ignore any error
			break
		}
		if trace {
			logInfo("new connection")
		}
		go func() {
			c := p.requestsCount.IncrementAndGet(1)
			if trace {
				logInfo("connections count=%d", c)
			}
			NewProcess(p, conn).process()
			c = p.requestsCount.DecrementAndGet(1)
			if trace {
				logInfo("connections count=%d", c)
			}
		}()
	}

	return nil
}

func (p *Proxy) stop() {
	p.forceStop.Set()
	logDestroy()
	os.Exit(1)
}

func (p *Proxy) stopped() bool {
	return p.forceStop.IsSet()
}

// generate a new kerberos ticket, using a new client if not yet cached per realm/username/password
func (p *Proxy) generateKerberosNegotiate(username string, realm string, password string, host string) (*string, error) {
	if p.stopped() {
		return nil, nil
	}
	token, err := p.kerberos.safeGetToken(username, realm, password, host)
	if token == nil {
		return nil, stacktrace.Propagate(err, "unable to get kerberos token")
	}
	auth := "Negotiate " + *token
	return &auth, nil
}

type PooledConnection struct {
	conn    net.Conn
	timeout time.Time
	reqId   int32
}

type PooledConnectionInfo struct {
	key   string
	conn  net.Conn
	reqId int32
}

func (p *Proxy) newPooledConn(dialer *net.Dialer, network string, proxy string, host string, context string, reqId int32) (bool, *PooledConnectionInfo, error) {
	key := network + "/" + proxy + "/" + context + "/" + host
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
			pc.conn.SetDeadline(time.Time{})
			return true, &PooledConnectionInfo{key, pc.conn, pc.reqId}, nil
		}
		if trace {
			logInfo("(%d) removed old connection %d from pool", reqId, pc.reqId)
		}
	}
	// create a new connection
	c, err := dialer.Dial(network, proxy)
	return false, &PooledConnectionInfo{key, c, reqId}, err
}

func (p *Proxy) pushConnToPool(info *PooledConnectionInfo, reqId int32) {
	if trace {
		logInfo("(%d) pushing connection %d to pool for later reuse", reqId, info.reqId)
	}
	p.poolMutex.Lock()
	defer p.poolMutex.Unlock()
	poolTimeout := time.Now().Add(POOL_CLOSE_TIMEOUT * time.Second)
	closeTimeout := poolTimeout.Add(POOL_CLOSE_TIMEOUT_ADD * time.Second)
	if err := info.conn.SetDeadline(closeTimeout); err == nil {
		p.connPool[info.key].PushBack(&PooledConnection{conn: info.conn, timeout: poolTimeout, reqId: info.reqId})
	}
}
