package kpx

import (
	"fmt"
	"github.com/palantir/stacktrace"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const CT_PLAIN_UTF8 = "text/plain; charset=UTF-8"

//const CT_PROXY_AUTOCONFIG = "application/x-ns-proxy-autoconfig"

type ProxyRequest struct {
	// input / output streams
	conn *TimedConn
	// headers stream, with already read data
	header *RequestHeader
	// verbose
	prefix string
}

type RequestHeader struct {
	headers   []string
	data      []byte
	startData int
	// request line
	method          string
	relativeUrl     string      // relative url without proto://host(:port), starts with /
	url             string      // request url, with additional proto://host(:port) - may be altered for altered url
	originalUrl     string      // request url, with additional proto://host(:port) - not altered
	lineUrl         string      // url as passed in first header line - may be altered for altered url
	version         HttpVersion // http version
	isConnect       bool        // request line is CONNECT
	isSsl           bool        // request url is https, but not not implies CONNECT is used
	host            string      // host, without port number
	port            int         // port number
	hostPort        string      // host with port number
	hostEmpty       bool        // host from line is empty
	directToConnect bool        // direct ue of proxy requires upgrade to CONNECT
	// response line
	status int
	reason string
	// headers
	keepAlive         bool
	contentLength     int64
	isProxyConnection bool
}

type HttpVersion string

const (
	Http10 HttpVersion = "1.0"
	Http11 HttpVersion = "1.1"
	Http2  HttpVersion = "2"
)

var HttpVersions = [...]HttpVersion{Http10, Http11, Http2}

func GetHttpVersion(version string) HttpVersion {
	a := strings.Split(version, "/")
	if len(a) == 0 {
		return Http10
	}
	v := a[len(a)-1]
	for _, hv := range HttpVersions {
		if v == hv.Version() {
			return hv
		}
	}
	return Http10
}

func (hv HttpVersion) Version() string {
	return string(hv)
}

func (hv HttpVersion) Order() int {
	for i, v := range HttpVersions {
		if v == hv {
			return i
		}
	}
	return -1
}

func (r *ProxyRequest) injectHeaders(headers []string) (*RequestHeader, error) {
	if r.prefix != "" {
		for _, header := range headers {
			logHeader("%s %s", r.prefix, header)
		}
	}
	h := make([]string, len(headers))
	copy(h, headers)
	d := make([]byte, 0)
	rh := RequestHeader{headers: h, data: d}
	r.header = &rh
	return r.header, nil
}

func (r *ProxyRequest) ReadFull(buffer []byte) (int, error) {
	var err error
	length := 0
	read := 0
	pos := 0
	found := 0
	b := buffer
	for {
		read, err = r.conn.Read(b)
		length += read
		if err != nil {
			return length, err // no wrap
		}
		// looking for \r\n\r\n (4 chars) at the end of http headers
		for i := pos; i < length; i++ {
			if buffer[i] == 13 || buffer[i] == 10 {
				found++
				if found == 4 {
					return length, nil
				}
			} else {
				found = 0
			}
		}
		pos = length
		b = buffer[length:]
	}
}

func (r *ProxyRequest) readHeaders() (*RequestHeader, error) {
	// init header
	h := RequestHeader{}
	// read header bytes
	startData := 0
	startLine := 0
	buffer := make([]byte, HEADER_MAX_SIZE)
	headers := make([]string, 0, 32)
	// read headers
	readLen, err := r.ReadFull(buffer)
	if err != nil {
		if readLen == 0 || err == io.EOF {
			return nil, io.EOF
		}
		return nil, stacktrace.Propagate(err, "Could not read headers")
	}
	if readLen == 0 {
		return nil, stacktrace.NewError("Invalid request, no headers")
	}
	for i := 0; i < readLen; i++ {
		if buffer[i] == '\r' && i+1 < readLen && buffer[i+1] == '\n' {
			// if this is an empty line, headers are finished
			if i == startLine {
				startData = i + 2
				break
			}
			// otherwise this is a new header line
			header := buffer[startLine:i]
			if r.prefix != "" {
				logHeader("%s %s", r.prefix, string(header))
			}
			startLine = i + 2
			headers = append(headers, string(header))
			i++
		}
	}
	// save headers
	if len(headers) == 0 {
		return nil, stacktrace.NewError("Invalid request, no headers")
	}
	h.headers = headers
	h.data = buffer[startData:readLen]
	h.startData = startData
	r.header = &h
	return &h, nil
}

func (rh *RequestHeader) analyseRequestLine() error {
	var err error
	// analyse first line
	headerLine := rh.headers[0]
	line := strings.Split(headerLine, " ")
	if len(line) != 3 {
		return stacktrace.NewError("Invalid request line, expecting 'METHOD URL VERSION': %v", headerLine)
	}
	rh.method = line[0]
	rh.url = line[1]
	rh.lineUrl = line[1]
	rh.version = GetHttpVersion(line[2])
	if strings.ToUpper(rh.method) == "CONNECT" {
		rh.isConnect = true
		hp := strings.Split(rh.url, ":")
		if len(hp) == 0 || len(hp) > 2 {
			return stacktrace.NewError("Invalid request line, expecting 'CONNECT host[:port] VERSION': %v", headerLine)
		}
		rh.host = hp[0]
		rh.port = 443
		rh.isSsl = false
		if len(hp) == 2 {
			rh.port, err = strconv.Atoi(hp[1])
			if err != nil {
				return stacktrace.Propagate(err, "Invalid request line, expecting 'CONNECT host[:port] VERSION': %v", headerLine)
			}
		}
		rh.url = "https://" + rh.host
		if rh.port != 443 {
			rh.url += ":" + strconv.Itoa(rh.port)
		}
	} else {
		rh.isConnect = false
		u, err := url.Parse(rh.url)
		if err != nil {
			return stacktrace.Propagate(err, "Invalid request line, expecting 'METHOD URL VERSION': %v", headerLine)
		}
		rh.relativeUrl = u.RequestURI()
		hp := strings.Split(u.Host, ":")
		if len(hp) == 0 || len(hp) > 2 {
			return stacktrace.NewError("Invalid request line, expecting 'METHOD URL VERSION': %v", headerLine)
		}
		rh.host = hp[0]
		rh.isSsl = strings.ToUpper(u.Scheme) == "HTTPS"
		rh.port = 80
		if rh.isSsl {
			rh.port = 443
		}
		if len(hp) == 2 {
			rh.port, err = strconv.Atoi(hp[1])
			if err != nil {
				return stacktrace.Propagate(err, "Invalid request line, expecting 'METHOD URL VERSION': %v", headerLine)
			}
		}
	}
	rh.hostPort = rh.host + ":" + strconv.Itoa(rh.port)
	rh.originalUrl = rh.url
	rh.hostEmpty = rh.host == ""
	return nil
}

func (rh *RequestHeader) analyseResponseLine() error {
	var err error
	// analyse first line
	headerLine := rh.headers[0]
	line := strings.SplitN(headerLine, " ", 3)
	if len(line) != 3 {
		return stacktrace.NewError("Invalid request line, expecting 'METHOD URL VERSION': %v", headerLine)
	}
	rh.version = GetHttpVersion(line[0])
	rh.status, err = strconv.Atoi(line[1])
	if err != nil {
		return stacktrace.Propagate(err, "Invalid response line, expecting 'VERSION STATUS REASON': %s", line)
	}
	rh.reason = line[2]
	return nil
}

func (rh *RequestHeader) analyseHeaders(req bool) error {
	var err error
	// keep alive is the "request" default for HTTP1.1 and HTTP2
	// although RFC states that HTTP 1.1 is keep-alive by default, it is not working with windows update when going through kpx > tinyproxy > squid > ...
	// we decided to state that connection must be closed unless the server explicitly asks for keep-alive
	rh.keepAlive = req && (rh.version == Http11 || rh.version == Http2)
	// loop on headers
	for i, header := range rh.headers {
		lower := strings.ToLower(header)
		switch {
		case rh.host == "" && strings.HasPrefix(lower, "host:"):
			// https://www.w3.org/Protocols/rfc2616/rfc2616-sec5.html 5.1.2 => request line must use absoluteUri <=> target is a proxy
			// as rh.host = "", call to proxy is a direct call
			// 1. url is /proxy.pac, skip
			//if rh.url == "/proxy.pac" {
			//	continue
			//}
			// 2. url starts with /~/https://
			if strings.HasPrefix(rh.url, "/~/") {
				paths := strings.SplitN(rh.url, "/", 5)
				if len(paths) == 5 && (paths[2] == "http" || paths[2] == "https") {
					host, sport := splitHostPort(paths[3], "", paths[2], false)
					if sport == "http" {
						sport = "80"
					} else if sport == "https" {
						sport = "443"
					}
					rh.host = host
					port, err := strconv.Atoi(sport)
					if err != nil {
						return stacktrace.NewError("Invalid host header: %v", header)
					}
					rh.port = port
					rh.isSsl = paths[2] == "https"
					rh.directToConnect = rh.isSsl
					rh.relativeUrl = "/" + paths[4]
					rh.url = rh.relativeUrl
					rh.hostEmpty = false
				}
			} else
			// 3. host contains either http/ or https/
			if strings.Contains(lower, "/") {
				hp := strings.SplitN(header, ":", 3)
				if len(hp) < 2 || len(hp) > 3 {
					return stacktrace.NewError("Invalid host header: %v", header)
				}
				rh.host = strings.TrimLeft(hp[1], " ")
				// Uncomment when enabling HTTPS will be studied...
				if strings.HasPrefix(rh.host, "http/") {
					rh.host = rh.host[5:]
					rh.port = 80
					rh.isSsl = false
				} else if strings.HasPrefix(rh.host, "https/") {
					rh.host = rh.host[6:]
					rh.port = 443
					rh.isSsl = true
					rh.directToConnect = rh.isSsl
				}
				if len(hp) > 2 {
					port, err := strconv.Atoi(hp[2])
					if err != nil {
						return stacktrace.NewError("Invalid host header: %v", header)
					}
					rh.port = port
				}
			} else
			// 4. local web server - skip
			{
				hp := strings.SplitN(header, ":", 2)
				rh.host = strings.TrimLeft(hp[1], " ")
				continue
			}
			//
			sport := strconv.Itoa(rh.port)
			if rh.isSsl {
				rh.url = "https://" + rh.host + rh.url
				rh.headers[i] = "Host: " + rh.host
				if rh.port != 443 {
					rh.url = "https://" + rh.host + ":" + sport + rh.url
					rh.headers[i] = "Host: " + rh.host + ":" + sport
				}
			} else {
				rh.url = "http://" + rh.host + rh.url
				rh.headers[i] = "Host: " + rh.host
				if rh.port != 80 {
					rh.url = "http://" + rh.host + ":" + sport + rh.url
					rh.headers[i] = "Host: " + rh.host + ":" + sport
				}
			}
			rh.hostPort = rh.host + ":" + sport
			rh.lineUrl = rh.url
		case strings.HasPrefix(lower, "content-length:") && rh.contentLength == 0:
			rh.contentLength, err = strconv.ParseInt(strings.TrimSpace(lower[15:]), 10, 64)
			if err != nil {
				return stacktrace.Propagate(err, "Invalid content-length header: %s", header)
			}
			if rh.contentLength < 0 {
				return stacktrace.NewError("Invalid content-length header: value is < 0")
			}
		case strings.HasPrefix(lower, "transfer-encoding:"):
			if strings.Contains(lower, "chunk") {
				rh.contentLength = -1
			}
		case strings.HasPrefix(lower, "proxy-connection:"):
			rh.isProxyConnection = true
			fallthrough
		case strings.HasPrefix(lower, "connection:"):
			if strings.Contains(lower, "close") {
				rh.keepAlive = false
			} else if strings.Contains(lower, "keep-alive") {
				rh.keepAlive = true
			}
		}
	}
	return nil
}

func (r *ProxyRequest) readRequestHeaders() error {
	rh, err := r.readHeaders()
	if err != nil {
		return err // no wrap
	}
	err = rh.analyseRequestLine()
	if err != nil {
		return err // no wrap
	}
	err = rh.analyseHeaders(true)
	if err != nil {
		return err // no wrap
	}
	return nil
}

func (r *ProxyRequest) readResponseHeaders() error {
	rh, err := r.readHeaders()
	if err != nil {
		return err // no wrap
	}
	err = rh.analyseResponseLine()
	if err != nil {
		return err // no wrap
	}
	err = rh.analyseHeaders(false)
	if err != nil {
		return err // no wrap
	}
	return nil
}

func (r *ProxyRequest) injectResponseHeaders(headers []string) error {
	rh, err := r.injectHeaders(headers)
	if err != nil {
		return err // no wrap
	}
	err = rh.analyseResponseLine()
	if err != nil {
		return err // no wrap
	}
	err = rh.analyseHeaders(false)
	if err != nil {
		return err // no wrap
	}
	return nil
}

func (r *ProxyRequest) findHeader(s string) *string {
	for _, header := range r.header.headers {
		kv := strings.SplitN(header, ":", 2)
		if strings.ToLower(kv[0]) == strings.ToLower(s) {
			val := strings.TrimSpace(kv[1])
			return &val
		}
	}
	return nil
}

func (r ProxyRequest) writeStatusLine(version HttpVersion, status int, reason string) error {
	return r.writeHeaderLine(fmt.Sprintf("HTTP/%s %d %s", version.Version(), status, reason))
}

func (r ProxyRequest) writeDateHeader() error {
	return r.writeHeader("Date", time.Now().Format(time.RFC1123))
}

func (r ProxyRequest) writeHeader(key, val string) error {
	return r.writeHeaderLine(fmt.Sprintf("%s: %s", key, val))
}

func (r ProxyRequest) writeKeepAlive(keepAlive bool, isProxy bool) error {
	header := "Connection"
	if isProxy {
		header = "Proxy-Connection"
	}
	if keepAlive {
		return r.writeHeader(header, "keep-alive")
	} else {
		return r.writeHeader(header, "close")
	}
}

func (r ProxyRequest) closeHeader() error {
	return r.writeHeaderLine("")
}

func (r ProxyRequest) writeContent(content string, keepAlive bool, contentType string) error {
	err := r.writeHeader("Content-Length", strconv.Itoa(len(content)))
	if err != nil {
		return err // no wrap
	}
	err = r.writeHeader("Content-Type", contentType)
	if err != nil {
		return err // no wrap
	}
	err = r.writeKeepAlive(keepAlive, false)
	if err != nil {
		return err // no wrap
	}
	err = r.closeHeader()
	_, err = r.conn.Write([]byte(content))
	return err // no wrap
}

func (r ProxyRequest) badRequest() error {
	err := r.writeStatusLine(Http10, 400, "Bad Request")
	if err != nil {
		return err // no wrap
	}
	err = r.writeDateHeader()
	if err != nil {
		return err // no wrap
	}
	return r.writeContent("Bad Request\n", false, CT_PLAIN_UTF8)
}

func (r ProxyRequest) notFound() error {
	err := r.writeStatusLine(Http10, 404, "Not Found")
	if err != nil {
		return err // no wrap
	}
	err = r.writeDateHeader()
	if err != nil {
		return err // no wrap
	}
	return r.writeContent("Not Found\n", false, CT_PLAIN_UTF8)
}

func (r *ProxyRequest) requireAuth(proxy string) error {
	err := r.writeStatusLine(Http10, 407, "Proxy Authentication Required")
	if err != nil {
		return err // no wrap
	}
	err = r.writeDateHeader()
	if err != nil {
		return err // no wrap
	}
	err = r.writeHeader("Proxy-Authenticate", fmt.Sprintf("Basic realm=\"Authentication required for '%s', use DOMAIN\\USERNAME or USERNAME@DOMAIN or USERNAME\"", proxy))
	if err != nil {
		return err // no wrap
	}
	return r.writeContent("Proxy Authentication Required\n", false, CT_PLAIN_UTF8)
}

func (r *ProxyRequest) writeRequestLine(method string, url string, version HttpVersion) error {
	return r.writeHeaderLine(fmt.Sprintf("%s %s HTTP/%s", method, url, version.Version()))
}

func (r *ProxyRequest) writeHeaderLine(line string) error {
	if r.prefix != "" && line != "" {
		logHeader("%s %s", r.prefix, line)
	}
	_, err := r.conn.Write([]byte(fmt.Sprintf("%s\r\n", line)))
	return err // no wrap
}
