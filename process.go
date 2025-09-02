package kpx

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/momiji/kpx/ui"
	"github.com/txthinking/socks5"

	"github.com/palantir/stacktrace"
	netproxy "golang.org/x/net/proxy"
)

type Process struct {
	config      *Config //copy config here because it is multithreaded
	proxy       *Proxy
	conn        *TimedConn
	reqId       int32
	verbose     bool
	logName     string
	logPrefix   string
	logLine     string
	logTraffic  string
	logHostPort string
	loadCounter int32
	ti          *traceInfo
	traffic     *ui.TrafficRow
	trafficConn *TrafficConn
}

func NewProcess(proxy *Proxy, conn net.Conn) *Process {
	reqId := proxy.newRequestId.Add(1)
	ti := newTraceInfo(reqId, "process")
	if trace {
		logTrace(ti, "create process")
	}
	trafficConn := NewTrafficConn(conn)
	return &Process{
		config:      proxy.getConfig(),
		proxy:       proxy,
		conn:        NewTimedConn(trafficConn, newTraceInfo(reqId, "client")),
		trafficConn: trafficConn,
		reqId:       reqId,
		loadCounter: proxy.loadCounter.Load(),
		ti:          ti,
	}
}

func (p *Process) processHttp() {
	// automatically close connection on exit
	defer func() { _ = p.conn.Close() }()
	// loop until proxyChannel is empty, meaning connection should close
	var clientChannel = &ProxyRequest{
		conn: p.conn,
	}
	// loop
	var proxyChannel *ProxyRequest
	for !p.proxy.stopped() {
		// we don't reuse the proxyChannel as the target can change,
		// however we use a pool to reuse connection once target is identified
		proxyChannel = p.processChannel(clientChannel, nil)
		if proxyChannel == nil {
			break
		}
	}
}

func (p *Process) processChannel(clientChannel, proxyChannel *ProxyRequest) *ProxyRequest {
	if trace {
		logTrace(p.ti, "start process")
	}
	p.logLine = ""
	p.logPrefix = ""
	clientChannel.prefix = ""

	// set timeout for reading headers
	clientChannel.conn.setTimeout(p.config.conf.ConnectTimeout)

	// read request headers - set timeout to prevent waiting forever incoming http headers
	err := clientChannel.readRequestHeaders()
	if err != nil {
		if err == io.EOF {
			return p.closeChannels(clientChannel, proxyChannel)
		}
		_ = clientChannel.badRequest()
		return p.closeChannels(clientChannel, proxyChannel)
	}

	// is url for local web server?
	if strings.HasPrefix(clientChannel.header.url, "/") {
		_ = p.webServer(clientChannel)
		return p.closeChannels(clientChannel, proxyChannel)
	}

	// prevent timeout on connections
	clientChannel.conn.setTimeout(0)

	// if url is local server, serve as http server
	// find proxy to use from host:port
	if trace {
		logTrace(p.ti, "proxy match")
	}
	rule, proxies := p.config.matchHttp(clientChannel.header.url, clientChannel.header.hostPort)
	firstProxy, firstHostPort := p.findFirstProxy(rule, proxies)
	if trace {
		if firstProxy != nil {
			logTrace(p.ti, "proxy matched '%s'", *firstProxy.name)
		} else {
			logTrace(p.ti, "no proxy matched")
		}
	}

	// print log in verbose mode
	p.computeLog(clientChannel, rule, firstProxy, firstHostPort)
	if p.verbose {
		logInfo("%s", p.logLine)
	}
	if debug {
		prefix := fmt.Sprintf("%s C<", p.logPrefix)
		for _, header := range clientChannel.header.headers {
			logHeader("%s %s", prefix, header)
		}
	}

	// traffic data
	p.traffic = ui.NewTrafficRow(p.reqId, p.logTraffic)
	ui.TrafficData.Add(p.traffic)
	p.trafficConn.row = p.traffic

	// if no proxy, just throw away the request
	if rule == nil || firstProxy == nil || *firstProxy.Type == ProxyNone {
		_ = clientChannel.badRequest()
		return p.closeChannels(clientChannel, proxyChannel)
	}

	// authorization is now computed lazily, as we don't know yet if we need a new authorization header.
	// if we're reusing an existing connection, authorization is not necessary
	var authorization *string
	var authorizationFunc func() (*string, error)
	var authorizationContext string

	// check if authentication is required as defined in the configuration.
	// authentication is computed on each request, regardless connection will be reused or not.
	authentication := (*firstProxy.Type == ProxyKerberos || *firstProxy.Type == ProxyBasic || *firstProxy.Type == ProxySocks) && firstProxy.cred != nil
	//if proxyChannel != nil {
	//    authentication = false
	//}

	// if proxy requires per-user authentication
	// - step 1: respond with Proxy-Authenticate header to require username/password
	// - step 2: receive Proxy-Authorization header, and convert it to kerberos/basic ticket
	// for kerberos, only do this when there is no connection to proxy yet
	// for basic, do this all the time, as basic info is always present
	if authentication && firstProxy.cred.isPerUser {
		if trace {
			logTrace(p.ti, "per-user authentication")
		}
		proxyAuthorization := clientChannel.findHeader("proxy-authorization")
		if proxyAuthorization != nil {
			var authenticated bool
			authenticated, authorizationContext, authorizationFunc = p.computeAuthPerUser(firstProxy, proxyAuthorization)
			if !authenticated {
				// authentication failed
				_ = clientChannel.requireAuth(*firstProxy.name)
				return p.closeChannels(clientChannel, proxyChannel)
			}
		} else {
			_ = clientChannel.requireAuth(*firstProxy.name)
			return p.closeChannels(clientChannel, proxyChannel)
		}
	}

	// if proxy is not per-user
	// for kerberos, only do this when there is no connection to proxy yet
	// for basic, do this all the time, as basic info is always present
	if authentication && !firstProxy.cred.isPerUser {
		if trace {
			logTrace(p.ti, "authentication")
		}
		var authenticated bool
		authenticated, authorizationContext, authorizationFunc = p.computeAuthPerConf(firstProxy)
		if !authenticated {
			// authentication failed
			_ = clientChannel.requireAuth(*firstProxy.name)
			return p.closeChannels(clientChannel, proxyChannel)
		}
	}

	// create proxyChannel
	// simulateConnect: for peers that do not talk HTTP like DIRECT or SOCKS
	simulateConnect := false
	// allow 3 retries, creating a new remote connection each time
	retryable := 3
	// man-in-the-middle - it seems to work for all proxy configuration
	mitmProxy := true
	mitmClient := true
	// if connection from pool
	var pooledConnInfo *PooledConnectionInfo
	// try up to retryable connections
	for {
		pooledConnInfo = nil
		if trace {
			logTrace(p.ti, "start connection (retryable=%d)", retryable)
		}
		if proxyChannel == nil {
			if trace {
				logTrace(p.ti, "create proxy channel")
			}
			var conn net.Conn
			dialer := new(net.Dialer)
			dialer.Timeout = time.Duration(p.config.conf.ConnectTimeout) * time.Second
			switch *firstProxy.Type {
			case ProxyKerberos, ProxyBasic, ProxyAnonymous:
				if firstProxy.Ssl {
					tlsConfig := tls.Config{}
					conn, err = tls.DialWithDialer(dialer, "tcp4", firstHostPort, &tlsConfig)
				} else if clientChannel.header.isConnect || clientChannel.header.directToConnect {
					conn, err = dialer.Dial("tcp4", firstHostPort)
				} else {
					// may reuse a http connection from pool
					var reused bool
					reused, pooledConnInfo, err = p.proxy.newPooledConn(dialer, "tcp4", firstHostPort, clientChannel.header.host, authorizationContext, p.reqId)
					conn = pooledConnInfo.conn
					if reused && *firstProxy.Type == ProxyKerberos {
						// reused connection is already authenticated
						authentication = false
					}
				}
			case ProxySocks:
				simulateConnect = clientChannel.header.isConnect
				var authz *netproxy.Auth
				if authentication {
					authorization, _ = authorizationFunc()
				}
				if authorization != nil {
					userDetails := strings.SplitN(*authorization, ":", 2)
					authz = &netproxy.Auth{
						User:     userDetails[0],
						Password: userDetails[1],
					}
				}
				var socks netproxy.Dialer
				socks, err = netproxy.SOCKS5("tcp4", firstHostPort, authz, dialer)
				if err == nil {
					hostPort := clientChannel.header.hostPort
					h, p := splitHostPort(hostPort, "", "", false)
					if rule.Dns != nil {
						h2, p2 := splitHostPort(*rule.Dns, h, p, false)
						hostPort = h2 + ":" + p2
					}
					conn, err = socks.Dial("tcp4", hostPort)
				}
			case ProxyDirect:
				simulateConnect = clientChannel.header.isConnect
				hostPort := clientChannel.header.hostPort
				host, port := splitHostPort(hostPort, "", "", false)
				if rule.Dns != nil {
					h2, p2 := splitHostPort(*rule.Dns, host, port, false)
					hostPort = h2 + ":" + p2
				}
				if firstProxy.Ssl {
					tlsConfig := tls.Config{}
					conn, err = tls.DialWithDialer(dialer, "tcp4", hostPort, &tlsConfig)
				} else if clientChannel.header.isConnect || clientChannel.header.directToConnect {
					conn, err = dialer.Dial("tcp4", hostPort)
				} else {
					// may reuse a http connection from pool
					_, pooledConnInfo, err = p.proxy.newPooledConn(dialer, "tcp4", hostPort, clientChannel.header.host, authorizationContext, p.reqId)
					conn = pooledConnInfo.conn
				}
			}
			// if err == nil and pi>0 or pj>0, update last usage
			if err != nil {
				logError("%s => dial: %#s", p.logLine, err)
				return p.closeChannels(clientChannel, proxyChannel)
			}
			// if conn is nil - proxyType=PAC and PAC not downloaded, so it did not resolve to an other proxy
			if conn == nil {
				logInfo("%s => dial: no connection available", p.logLine)
				return p.closeChannels(clientChannel, proxyChannel)
			}
			ConfigureConn(conn)
			proxyChannel = &ProxyRequest{
				conn: NewTimedConn(conn, newTraceInfo(p.reqId, "proxy")),
			}
		}

		// get authorization header
		if authentication && authorization == nil {
			authorization, err = authorizationFunc()
			if err != nil {
				logInfo("[-] Shutting down to prevent locking user account with repeated invalid password...")
				p.proxy.stop()
				return nil
			}
			if authorization == nil {
				authorization = &noAuth
			}
		}

		// forward request to proxy
		if !simulateConnect {
			if trace {
				logTrace(p.ti, "forward request")
			}
			clientChannel.conn.setTimeout(-p.config.conf.IdleTimeout)
			proxyChannel.conn.setTimeout(-p.config.conf.IdleTimeout)
			if !clientChannel.header.directToConnect {
				err = p.forwardRequest(clientChannel, proxyChannel, *firstProxy.Type, authorization)
				if err != nil {
					logError("%s => forward: %#s", p.logLine, err)
					return p.closeChannels(clientChannel, proxyChannel)
				}
			} else {
				err = p.forwardConnect(clientChannel, proxyChannel, *firstProxy.Type, authorization)
				if err != nil {
					logError("%s => forward: %#s", p.logLine, err)
					return p.closeChannels(clientChannel, proxyChannel)
				}
				if debug {
					proxyChannel.prefix = fmt.Sprintf("%s P<", p.logPrefix)
				}
				proxyChannel.conn.setTimeout(p.config.conf.IdleTimeout)
				err = proxyChannel.readResponseHeaders()
				if err != nil {
					logError("%s => forward: %#s", p.logLine, err)
					return p.closeChannels(clientChannel, proxyChannel)
				}
				if strings.ToLower(proxyChannel.header.reason) != "connection established" {
					err = errors.New("connection not established")
					logError("%s => forward: %#s", p.logLine, err)
					return p.closeChannels(clientChannel, proxyChannel)
				}
				if debug {
					proxyChannel.prefix = fmt.Sprintf("%s P>", p.logPrefix)
				}
				proxyChannel.conn = NewTimedConn(tls.Client(proxyChannel.conn.conn, &tls.Config{ServerName: clientChannel.header.host}), newTraceInfo(p.reqId, "proxy"))
				err = p.forwardRequest(clientChannel, proxyChannel, *firstProxy.Type, authorization)
				if err != nil {
					logError("%s => forward: %#s", p.logLine, err)
					return p.closeChannels(clientChannel, proxyChannel)
				}
			}
		}

		// read response headers
		if trace {
			logTrace(p.ti, "read response")
		}
		if debug {
			proxyChannel.prefix = fmt.Sprintf("%s P<", p.logPrefix)
		}
		if simulateConnect {
			// inject headers manually as if proxyChannel has been called
			_ = proxyChannel.injectResponseHeaders([]string{"HTTP/1.0 200 Connection established"})
		} else {
			proxyChannel.conn.setTimeout(p.config.conf.IdleTimeout)
			err := proxyChannel.readResponseHeaders()
			if err != nil {
				retryable--
				if err == io.EOF && retryable > 0 {
					logError("%s => %#s", p.logLine, stacktrace.NewError("Remote connection closed, retrying"))
					p.closeChannel(proxyChannel)
					proxyChannel = nil
					continue
				} else if err == io.EOF {
					logError("%s => %#s", p.logLine, stacktrace.NewError("Remote connection closed"))
				} else {
					logError("%s => response: %#s", p.logLine, err)
				}
				_ = clientChannel.badRequest()
				return p.closeChannels(clientChannel, proxyChannel)
			}
		}
		break
	}

	// downgrade version if proxy is lower than client
	if proxyChannel.header.version.Order() < clientChannel.header.version.Order() {
		clientChannel.header.version = proxyChannel.header.version
	}
	clientChannel.header.keepAlive = clientChannel.header.keepAlive && proxyChannel.header.keepAlive

	// forward response to client
	if trace {
		logTrace(p.ti, "forward response")
	}
	clientChannel.conn.setTimeout(-p.config.conf.IdleTimeout)
	proxyChannel.conn.setTimeout(-p.config.conf.IdleTimeout)
	err = p.forwardResponse(proxyChannel, clientChannel, authentication)
	if err != nil {
		//logError("%s => %v", p.logLine, err)
		return p.closeChannels(clientChannel, proxyChannel)
	}

	// man-in-the-middle: decode https flows
	if clientChannel.header.isConnect && rule.Mitm && (mitmProxy || mitmClient) {
		if trace {
			logTrace(p.ti, "mitm hijacking")
		}
		// convert client connexion to a tls server
		if mitmClient {
			host := clientChannel.header.host
			srvConfig := tls.Config{
				GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
					name := info.ServerName
					if name == "" {
						name = host
					}
					return p.config.certsManager.GetCertificate(name)
				},
			}
			clientChannel.conn.conn = tls.Server(clientChannel.conn.conn, &srvConfig)
		}
		// convert proxy connexion to a tls client
		if mitmProxy {
			cliConfig := tls.Config{InsecureSkipVerify: true}
			proxyChannel.conn.conn = tls.Client(proxyChannel.conn.conn, &cliConfig)
		}
		// automatically close connection after long inactivity
		clientChannel.conn.setTimeout(-p.config.conf.IdleTimeout)
		proxyChannel.conn.setTimeout(-p.config.conf.IdleTimeout)
		// infinite double pipe sync
		for {
			p.logLine = ""
			p.logPrefix = ""
			clientChannel.prefix = ""
			err = clientChannel.readRequestHeaders()
			if err == io.EOF {
				break
			}
			if err != nil {
				_ = clientChannel.badRequest()
				break
			}
			p.computeLog(clientChannel, rule, firstProxy, firstHostPort)
			if p.verbose {
				logInfo("%s", p.logLine)
			}
			if debug {
				prefix := fmt.Sprintf("%s C<", p.logPrefix)
				for _, header := range clientChannel.header.headers {
					logHeader("%s %s", prefix, header)
				}
			}
			err = p.forwardRequest(clientChannel, proxyChannel, *firstProxy.Type, nil)
			if err != nil {
				break
			}
			if debug {
				proxyChannel.prefix = fmt.Sprintf("%s P<", p.logPrefix)
			}
			err = proxyChannel.readResponseHeaders()
			if err != nil {
				break
			}
			err = p.forwardResponse(proxyChannel, clientChannel, false)
			if err != nil {
				break
			}
		}
		return p.closeChannels(clientChannel, proxyChannel)
	}
	// treat CONNECT as a forever duplex pipe
	if clientChannel.header.isConnect || proxyChannel.header.status == 100 {
		if trace {
			logTrace(p.ti, "duplex pipe forever")
		}
		// automatically close connection after long inactivity
		clientChannel.conn.setTimeout(-p.config.conf.IdleTimeout)
		proxyChannel.conn.setTimeout(-p.config.conf.IdleTimeout)
		// create a wait group to wait for both to finish
		var finished sync.WaitGroup
		finished.Add(2)
		// double pipe async copy
		go p.pipe(clientChannel, proxyChannel, &finished)
		go p.pipe(proxyChannel, clientChannel, &finished)
		// wait for both copy to finish
		finished.Wait()
		return p.closeChannels(clientChannel, proxyChannel)
	}
	// if KeepAlive, allow to reuse connection
	if clientChannel.header.keepAlive {
		// reuse connection only if config has not changed
		if p.loadCounter == p.proxy.loadCounter.Load() {
			// reuse proxy channel for next request
			if pooledConnInfo != nil {
				p.proxy.pushConnToPool(pooledConnInfo, p.reqId)
			}
			return proxyChannel
		}
		return p.closeChannels(clientChannel, proxyChannel)
	}
	// else, return
	{
		return p.closeChannels(clientChannel, proxyChannel)
	}
}

func (p *Process) computeLog(channel *ProxyRequest, rule *ConfRule, proxy *ConfProxy, hostPort string) {
	if p.logLine != "" {
		return
	}
	// compute verbosity = (rule.Verbose overrides proxy.Verbose overrides conf.Verbose) || debug
	verbose := p.config.conf.Verbose
	if rule != nil /*&& rule.confProxy != nil*/ && proxy.Verbose != nil {
		verbose = *proxy.Verbose
	}
	if rule != nil && rule.Verbose != nil {
		verbose = *rule.Verbose
	}
	verbose = verbose || debug || trace
	p.verbose = verbose
	// compute proxy display name
	name := ProxyNone.Name()
	if rule != nil /*&& rule.confProxy != nil*/ {
		name = p.proxyShortName(*rule.Proxy)
		if name != *proxy.name {
			name = name + ">" + *proxy.name
		}
	}
	// compute log line
	p.logName = name
	p.logPrefix = fmt.Sprintf("(%d) [%s]", p.reqId, name)
	p.logLine = fmt.Sprintf("%s %s %s HTTP/%s", p.logPrefix, channel.header.method, channel.header.originalUrl, channel.header.version)
	p.logTraffic = fmt.Sprintf("%s %s %s HTTP/%s", name, channel.header.method, channel.header.originalUrl, channel.header.version)
	if channel.header.hostEmpty {
		p.logLine = fmt.Sprintf("%s (%s)", p.logLine, channel.header.host)
	}
	p.logHostPort = hostPort
}

func (p *Process) proxyShortName(s string) string {
	if strings.Contains(s, ",") {
		return strings.Split(s, ",")[0] + "+"
	}
	return s
}

func (p *Process) webServer(channel *ProxyRequest) error {
	var err error
	line := channel.header.method + " " + channel.header.url
	if !strings.HasPrefix(strings.ToLower(line), "get /proxy.pac") {
		return channel.notFound()
	}

	err = channel.writeStatusLine(Http10, 200, "OK")
	if err != nil {
		return err // no wrap
	}
	err = channel.writeDateHeader()
	if err != nil {
		return err // no wrap
	}
	return channel.writeContent(p.config.pac, false, CT_PLAIN_UTF8)
}

func (p *Process) closeChannels(clientChannel, proxyChannel *ProxyRequest) *ProxyRequest {
	if trace {
		logTrace(p.ti, "close channels")
	}
	p.closeChannel(clientChannel)
	p.closeChannel(proxyChannel)
	if p.traffic != nil {
		ui.TrafficData.Remove(p.traffic)
	}
	return nil
}

func (p *Process) closeChannel(channel *ProxyRequest) {
	if channel == nil {
		return
	}
	_ = channel.conn.Close()
}

func (p *Process) forwardRequest(clientChannel *ProxyRequest, proxyChannel *ProxyRequest, proxyType ProxyType, auth *string) error {
	var err error
	if debug {
		proxyChannel.prefix = fmt.Sprintf("%s P>", p.logPrefix)
	}
	// https://www.w3.org/Protocols/rfc2616/rfc2616-sec5.html 5.1.2 => request line must use absoluteUri <=> target is a proxy
	if proxyType == ProxyDirect || proxyType == ProxySocks {
		err = proxyChannel.writeRequestLine(clientChannel.header.method, clientChannel.header.relativeUrl, clientChannel.header.version)
		if err != nil {
			return err // no wrap
		}
	} else {
		err = proxyChannel.writeRequestLine(clientChannel.header.method, clientChannel.header.lineUrl, clientChannel.header.version)
		if err != nil {
			return err // no wrap
		}
	}
	expectContinue := true
	for _, header := range clientChannel.header.headers[1:] {
		lower := strings.ToLower(header)
		switch {
		case strings.HasPrefix(lower, "proxy-connection:") || strings.HasPrefix(lower, "connection:"):
			continue
		case strings.HasPrefix(lower, "proxy-authorization:"):
			continue
		case strings.HasPrefix(lower, "expect") && strings.Contains(lower, "100-continue") && strings.ToUpper(clientChannel.header.method) == "PUT":
			expectContinue = true
		}
		err = proxyChannel.writeHeaderLine(header)
		if err != nil {
			return err // no wrap
		}
	}
	if auth != nil {
		err = proxyChannel.writeHeader("Proxy-Authorization", *auth)
		if err != nil {
			return err // no wrap
		}
	}
	err = proxyChannel.writeKeepAlive(clientChannel.header.keepAlive, proxyType != ProxyDirect && proxyType != ProxySocks)
	if err != nil {
		return err // no wrap
	}
	err = proxyChannel.closeHeader()
	if err != nil {
		return err // no wrap
	}
	// special PUT with Expect: 100-continue
	if expectContinue {
		return nil
	}
	return p.forwardStream(clientChannel, proxyChannel)
}

func (p *Process) forwardConnect(clientChannel *ProxyRequest, proxyChannel *ProxyRequest, _ ProxyType, auth *string) error {
	var err error
	if debug {
		proxyChannel.prefix = fmt.Sprintf("%s P>", p.logPrefix)
	}
	// https://www.w3.org/Protocols/rfc2616/rfc2616-sec5.html 5.1.2 => request line must use absoluteUri <=> target is a proxy
	err = proxyChannel.writeRequestLine("CONNECT", clientChannel.header.hostPort, clientChannel.header.version)
	if err != nil {
		return err // no wrap
	}
	err = proxyChannel.writeHeader("Host", clientChannel.header.hostPort)
	if err != nil {
		return err // no wrap
	}
	for _, header := range clientChannel.header.headers[1:] {
		lower := strings.ToLower(header)
		if strings.HasPrefix(lower, "user-agent:") {
			err = proxyChannel.writeHeaderLine(header)
			if err != nil {
				return err // no wrap
			}
		}
	}
	err = proxyChannel.writeKeepAlive(clientChannel.header.keepAlive, true)
	if err != nil {
		return err // no wrap
	}
	if auth != nil {
		err = proxyChannel.writeHeader("Proxy-Authorization", *auth)
		if err != nil {
			return err // no wrap
		}
	}
	err = proxyChannel.closeHeader()
	if err != nil {
		return err // no wrap
	}
	return p.forwardStream(clientChannel, proxyChannel)
}

func (p *Process) forwardResponse(proxyChannel *ProxyRequest, clientChannel *ProxyRequest, authentication bool) error {
	var err error
	if debug {
		clientChannel.prefix = fmt.Sprintf("%s C>", p.logPrefix)
	}
	for _, header := range proxyChannel.header.headers {
		lower := strings.ToLower(header)
		switch {
		case strings.HasPrefix(lower, "connection:"):
			continue
		case strings.HasPrefix(lower, "proxy-connection:"):
			continue
		case strings.HasPrefix(lower, "proxy-authenticate:") && authentication:
			continue
		case strings.HasPrefix(lower, "kpx-") && debug:
			continue
		}
		err = clientChannel.writeHeaderLine(header)
		if err != nil {
			return err // no wrap
		}
	}
	if debug {
		_ = clientChannel.writeHeader("kpx-proxy", p.logName)
		_ = clientChannel.writeHeader("kpx-host", p.logHostPort)
	}
	if !clientChannel.header.isConnect {
		err = clientChannel.writeKeepAlive(clientChannel.header.keepAlive, clientChannel.header.isProxyConnection)
		if err != nil {
			return err // no wrap
		}
	}
	err = clientChannel.closeHeader()
	if err != nil {
		return err // no wrap
	}
	// special response if HEAD
	if strings.ToUpper(clientChannel.header.method) == "HEAD" {
		return nil
	}
	return p.forwardStream(proxyChannel, clientChannel)
}

func (p *Process) forwardStream(source *ProxyRequest, target *ProxyRequest) error {
	dataReader := strings.NewReader(string(source.header.data))
	sourceReader := io.MultiReader(dataReader, source.conn)
	var reader io.Reader
	if source.header.contentLength == -1 {
		// Use our own implementation of NewChunkedReader instead of original http.NewChunkedReader
		// to also copy the chunked lines
		reader = NewChunkedReader(sourceReader)
	} else {
		reader = io.LimitReader(sourceReader, source.header.contentLength)
	}
	writer := target.conn
	_, err := io.Copy(writer, reader)
	// fast close connection after short inactivity, unless receiving new data
	source.conn.setTimeout(-p.config.conf.CloseTimeout)
	target.conn.setTimeout(-p.config.conf.CloseTimeout)
	return err // no wrap
}

func (p *Process) pipe(source *ProxyRequest, target *ProxyRequest, wait *sync.WaitGroup) {
	// io.Copy will use splice/sendfile (zerocopy) only if src/dst are of type *net.TCPConn
	_, _ = io.Copy(target.conn.conn, source.conn.conn)
	// fast close connection after short inactivity, unless receiving new data
	//source.conn.setTimeout(-p.config.conf.CloseTimeout)
	//target.conn.setTimeout(-p.config.conf.CloseTimeout)
	// in a forever pipe, just close connections after copy is finished
	p.closeChannel(source)
	p.closeChannel(target)
	wait.Done()
}

func (p *Process) hash(format string, a ...any) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf(format, a...))))
}

func (p *Process) findFirstProxy(rule *ConfRule, proxies []*ConfProxy) (*ConfProxy, string) {
	var firstProxy *ConfProxy
	var firstHostPort string
	sortedProxies := append(proxies[:0], proxies...)
	if sortedProxies != nil {
		// sort proxies
		if len(sortedProxies) > 1 {
			p.config.lastMMutex.RLock()
			sort.SliceStable(sortedProxies, func(i int, j int) bool {
				l1 := p.config.lastProxies[*sortedProxies[i].name]
				l2 := p.config.lastProxies[*sortedProxies[j].name]
				return l1.After(l2)
			})
			p.config.lastMMutex.RUnlock()
		}
		// find first working proxy
	proxyLoop:
		for pi, proxy := range sortedProxies {
			if *proxy.Type == ProxyDirect || *proxy.Type == ProxyNone {
				firstProxy = proxy
				break
			}
			// get hosts and port
			hosts := []string{""}
			if proxy.Host != nil {
				hosts = strings.Split(*proxy.Host, ",")
			}
			port := proxy.Port
			// sort hosts
			if len(hosts) > 1 {
				p.config.lastMMutex.RLock()
				sort.SliceStable(hosts, func(i int, j int) bool {
					l1 := p.config.lastProxies[*proxy.name+"."+hosts[i]]
					l2 := p.config.lastProxies[*proxy.name+"."+hosts[j]]
					return l1.After(l2)
				})
				p.config.lastMMutex.RUnlock()
			}
			// loop on hosts
			for hi, host := range hosts {
				hostPort := fmt.Sprintf("%s:%d", host, port)
				// set default proxy
				if firstProxy == nil {
					firstProxy = proxy
					firstHostPort = hostPort
				}
				// try to connect to host
				dialer := new(net.Dialer)
				dialer.Timeout = time.Duration(p.config.conf.ConnectTimeout) * time.Second
				checkConn, err := dialer.Dial("tcp4", hostPort)
				if err != nil {
					// on failure, try next host
					if debug {
						logInfo("[%s] Host %s: %v", *proxy.name, hostPort, err)
					}
					continue
				}
				ConfigureConn(checkConn)
				_ = checkConn.Close()
				// update last proxy and host usage
				p.config.lastMMutex.RLock()
				pl := p.config.lastProxies[*proxy.name]
				hl := p.config.lastProxies[*proxy.name+"."+host]
				p.config.lastMMutex.RUnlock()
				// update last proxy usage, this is very rare
				if pi > 0 || pl.IsZero() || hi > 0 || hl.IsZero() {
					p.config.lastMMutex.Lock()
					pl = p.config.lastProxies[*proxy.name]
					hl = p.config.lastProxies[*proxy.name+"."+host]
					if pi > 0 || pl.IsZero() || hi > 0 || hl.IsZero() {
						p.config.lastProxies[*proxy.name] = time.Now()
						p.config.lastProxies[*proxy.name+"."+host] = time.Now()
					}
					p.config.lastMMutex.Unlock()
				}
				if debug {
					if pi > 0 || (pl.IsZero() && len(sortedProxies) > 1) {
						if debug {
							logInfo("[%s] Now using proxy %s", p.proxyShortName(*rule.Proxy), *proxy.name)
						}
					}
					if hi > 0 || (hl.IsZero() && len(hosts) > 1) {
						if debug {
							logInfo("[%s] Now using host %s", *proxy.name, host)
						}
					}
				}
				// set firstProxy
				firstProxy = proxy
				firstHostPort = hostPort
				break proxyLoop
			}
		}
	}
	return firstProxy, firstHostPort
}

func (p *Process) computeAuthPerUser(firstProxy *ConfProxy, proxyAuthorization *string) (bool, string, func() (*string, error)) {
	var authenticated bool
	var authorizationContext string
	var authorizationFunc func() (*string, error)
	basic := strings.SplitN(*proxyAuthorization, " ", 2)
	if len(basic) == 2 {
		credentials, err := base64.StdEncoding.DecodeString(basic[1])
		if err == nil {
			userDetails := strings.SplitN(string(credentials), ":", 2)
			if len(userDetails) == 2 {
				switch {
				case *firstProxy.Type == ProxyKerberos:
					// note that it is not needed to check isNative as there is no cred for per-user auth
					authorizationContext = p.hash("krb:%s/%s/%s/%s", userDetails[0], *firstProxy.Realm, userDetails[1], *firstProxy.Host)
					authorizationFunc = func(username string, realm string, password string, protocol string, host string) func() (*string, error) {
						return func() (*string, error) {
							// hide error, as this is not an unrecoverable error
							auth, err := p.proxy.generateKerberosNegotiate(username, realm, password, protocol, host)
							if err != nil {
								logError("%s Failed to generate authenticate token: %v", p.logPrefix, err)
							}
							return auth, nil
						}
					}(userDetails[0], *firstProxy.Realm, userDetails[1], *firstProxy.Spn, *firstProxy.Host)
					authenticated = true
				case *firstProxy.Type == ProxyBasic:
					authorizationContext = p.hash("basic:%s", *proxyAuthorization)
					authorizationFunc = func(auth *string) func() (*string, error) {
						return func() (*string, error) {
							return auth, nil
						}
					}(proxyAuthorization)
					authenticated = true
				case *firstProxy.Type == ProxySocks:
					credentialString := string(credentials)
					authorizationContext = p.hash("socks:%s", credentialString)
					authorizationFunc = func(auth *string) func() (*string, error) {
						return func() (*string, error) {
							return auth, nil
						}
					}(&credentialString)
					authenticated = true
				}
			}
		}
	}
	return authenticated, authorizationContext, authorizationFunc
}

func (p *Process) computeAuthPerConf(firstProxy *ConfProxy) (bool, string, func() (*string, error)) {
	var authenticated bool
	var authorizationContext string
	var authorizationFunc func() (*string, error)
	switch {
	case *firstProxy.Type == ProxyKerberos && !firstProxy.cred.isNative:
		authorizationContext = p.hash("krb:%s/%s/%s/%s", *firstProxy.cred.Login, *firstProxy.Realm, *firstProxy.cred.Password, *firstProxy.Host)
		authorizationFunc = func(username string, realm string, password string, protocol string, host string) func() (*string, error) {
			return func() (*string, error) {
				// don't hide error, this is an unrecoverable error
				auth, err := p.proxy.generateKerberosNegotiate(username, realm, password, protocol, host)
				if err != nil {
					logError("%s Failed to generate authenticate token: %v", p.logPrefix, err)
					return nil, err
				}
				return auth, nil
			}
		}(*firstProxy.cred.Login, *firstProxy.Realm, *firstProxy.cred.Password, *firstProxy.Spn, *firstProxy.Host)
		authenticated = true
	case *firstProxy.Type == ProxyKerberos && firstProxy.cred.isNative:
		authorizationContext = p.hash("native:%s", *firstProxy.Host)
		authorizationFunc = func(protocol string, host string) func() (*string, error) {
			return func() (*string, error) {
				// don't hide error, this is an unrecoverable error
				auth, err := p.proxy.generateKerberosNative(protocol, host)
				if err != nil {
					logError("%s Failed to generate authenticate token: %v", p.logPrefix, err)
					return nil, err
				}
				return auth, nil
			}
		}(*firstProxy.Spn, *firstProxy.Host)
		authenticated = true
	case *firstProxy.Type == ProxyBasic:
		basic := fmt.Sprintf("%s:%s", *firstProxy.cred.Login, *firstProxy.cred.Password)
		basic = "Basic " + base64.StdEncoding.EncodeToString([]byte(basic))
		authorizationContext = p.hash("basic:%s", basic)
		authorizationFunc = func(auth *string) func() (*string, error) {
			return func() (*string, error) {
				return auth, nil
			}
		}(&basic)
		authenticated = true
	case *firstProxy.Type == ProxySocks:
		credentialString := fmt.Sprintf("%s:%s", *firstProxy.cred.Login, *firstProxy.cred.Password)
		authorizationContext = p.hash("socks:%s", credentialString)
		authorizationFunc = func(auth *string) func() (*string, error) {
			return func() (*string, error) {
				return auth, nil
			}
		}(&credentialString)
		authenticated = true
	}
	return authenticated, authorizationContext, authorizationFunc
}

func (p *Process) processSocks(request *socks5.Request) {
	var err error

	if trace {
		logTrace(p.ti, "start process")
	}

	// find matching rule and proxy
	requestHostPort := request.Address()
	rule, proxies := p.config.matchSocks(requestHostPort)
	firstProxy, firstHostPort := p.findFirstProxy(rule, proxies)
	proxyName := "none"
	if firstProxy != nil {
		proxyName = *firstProxy.name
	}
	if firstHostPort == "" {
		firstHostPort = requestHostPort
	}

	if trace {
		if firstProxy != nil {
			logTrace(p.ti, "proxy matched '%s'", proxyName)
		} else {
			logTrace(p.ti, "no proxy matched")
		}
	}

	// verbosity
	verbose := p.config.conf.Verbose
	if rule != nil && firstProxy.Verbose != nil {
		verbose = *firstProxy.Verbose
	}
	if rule != nil && rule.Verbose != nil {
		verbose = *rule.Verbose
	}
	verbose = verbose || debug || trace
	p.verbose = verbose

	// verbose log
	if p.verbose {
		logInfo("[%s] socks %s => %s", proxyName, requestHostPort, firstHostPort)
	}

	// if no proxy, just throw away the request
	if rule == nil || firstProxy == nil || *firstProxy.Type == ProxyNone {
		return
	}

	// check if authentication is required as defined in the configuration.
	authentication := *firstProxy.Type == ProxySocks && firstProxy.cred != nil

	//
	var authorization *string
	var authorizationFunc func() (*string, error)

	if authentication {
		if trace {
			logTrace(p.ti, "authentication")
		}
		var authenticated bool
		authenticated, _, authorizationFunc = p.computeAuthPerConf(firstProxy)
		if !authenticated {
			// authentication failed
			return
		}
	}

	// allow 3 retries, creating a new remote connection each time
	retryable := 3
	clientChannel := &ProxyRequest{
		conn: p.conn,
	}
	var proxyChannel *ProxyRequest
	// if connection from pool
	// try up to retryable connections
	for {
		if trace {
			logTrace(p.ti, "start connection (retryable=%d)", retryable)
		}
		var conn net.Conn
		dialer := new(net.Dialer)
		dialer.Timeout = time.Duration(p.config.conf.ConnectTimeout) * time.Second
		switch *firstProxy.Type {
		case ProxySocks:
			var authz *netproxy.Auth
			if authentication {
				authorization, _ = authorizationFunc()
			}
			if authorization != nil {
				userDetails := strings.SplitN(*authorization, ":", 2)
				authz = &netproxy.Auth{
					User:     userDetails[0],
					Password: userDetails[1],
				}
			}
			var socks netproxy.Dialer
			socks, err = netproxy.SOCKS5("tcp4", firstHostPort, authz, dialer)
			if err == nil {
				hostPort := requestHostPort
				h, p := splitHostPort(hostPort, "", "", false)
				if rule.Dns != nil {
					h2, p2 := splitHostPort(*rule.Dns, h, p, false)
					hostPort = h2 + ":" + p2
				}
				conn, err = socks.Dial("tcp4", hostPort)
			}
		case ProxyDirect:
			hostPort := requestHostPort
			host, port := splitHostPort(hostPort, "", "", false)
			if rule.Dns != nil {
				h2, p2 := splitHostPort(*rule.Dns, host, port, false)
				hostPort = h2 + ":" + p2
			}
			if firstProxy.Ssl {
				tlsConfig := tls.Config{}
				conn, err = tls.DialWithDialer(dialer, "tcp4", hostPort, &tlsConfig)
			} else {
				conn, err = dialer.Dial("tcp4", hostPort)
			}
		}
		// if err == nil and pi>0 or pj>0, update last usage
		if err != nil {
			logError("[%s] socks %s => %s: dial %#s", proxyName, requestHostPort, firstHostPort, err)
			retryable--
			if retryable > 0 {
				continue
			}
			return
		}
		//
		ConfigureConn(conn)
		proxyChannel = &ProxyRequest{
			conn: NewTimedConn(conn, newTraceInfo(p.reqId, "proxy")),
		}
		break
	}
	//
	// create a wait group to wait for both to finish
	var finished sync.WaitGroup
	finished.Add(2)
	// double pipe async copy
	go p.pipe(clientChannel, proxyChannel, &finished)
	go p.pipe(proxyChannel, clientChannel, &finished)
	// wait for both copy to finish
	finished.Wait()
	return
}
