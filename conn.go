package kpx

import (
	"crypto/tls"
	"github.com/momiji/kpx/ui"
	"math"
	"net"
	"time"
)

func ConfigureConn(conn net.Conn) {
	// Reducing TIME_WAIT connections by disableing Nagle's algorythm
	if c, ok := conn.(*net.TCPConn); ok {
		_ = c.SetNoDelay(true)
		return
	}
	if c, ok := conn.(*tls.Conn); ok {
		ConfigureConn(c.NetConn())
		return
	}
}

/*
TimedConn is a wrapper around net.Conn which provides automatic read/write timeouts:
- if timeout > 0, set an absolute timeout on first read
- if timeout = 0, do not set timeout
- if timeout < 0, set a sliding timeout, which automatically increases each min( 30s , timeout/2 ).
*/
type TimedConn struct {
	conn    net.Conn
	timeout int
	last    time.Time
	self    *TimedConn
	ti      *traceInfo
	closed  bool
}

func NewTimedConn(conn net.Conn, ti *traceInfo) *TimedConn {
	c := TimedConn{conn: conn, ti: ti}
	c.self = &c
	return &c
}

func (tc *TimedConn) deadlines(reset bool) {
	//logInfo("%s - %s / %d", tc.Id, tc.last, tc.timeout)
	switch {
	case tc.timeout > 0:
		_ = tc.conn.SetReadDeadline(time.Now().Add(time.Duration(tc.timeout) * time.Second))
		tc.timeout = 0
	case tc.timeout < 0 && reset:
		_ = tc.conn.SetReadDeadline(time.Now().Add(time.Duration(-tc.timeout) * time.Second))
		tc.last = time.Now()
	case tc.timeout < 0 && time.Since(tc.last).Seconds() > math.Min(30, float64(-tc.timeout/2)):
		_ = tc.conn.SetReadDeadline(time.Now().Add(time.Duration(-tc.timeout) * time.Second))
		tc.last = time.Now()
	case tc.timeout == 0 && reset:
		_ = tc.conn.SetReadDeadline(time.Time{})
	}
	//logInfo("%s + %s / %d", tc.Id, tc.last, tc.timeout)
}

func (tc *TimedConn) Read(b []byte) (n int, err error) {
	tc.self.deadlines(false)
	n, err = tc.conn.Read(b)
	return n, err
}

func (tc *TimedConn) Write(b []byte) (n int, err error) {
	tc.self.deadlines(false)
	return tc.conn.Write(b)
}

func (tc *TimedConn) Close() error {
	if !tc.closed && trace {
		logTrace(tc.ti, "close connection")
	}
	return tc.conn.Close()
}

func (tc *TimedConn) LocalAddr() net.Addr {
	return tc.conn.LocalAddr()
}

func (tc *TimedConn) RemoteAddr() net.Addr {
	return tc.conn.RemoteAddr()
}

func (tc *TimedConn) SetDeadline(_ time.Time) error {
	return nil
}

func (tc *TimedConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (tc *TimedConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

// set read/write timeout: absolute timeout if > 0, sliding timeout if < 0, no timeout if 0.
//
// sliding timeout reinitialize the timeout each 1/2 timeout or 30 seconds to keep the connection open.
func (tc *TimedConn) setTimeout(timeout int) {
	if trace {
		logTrace(tc.ti, "set conn timeout %d", timeout)
	}
	if timeout < 0 {
		// double sliding timeout because it is expanded only 1/2 timeout
		timeout = timeout * 2
	}
	tc.timeout = timeout
	tc.last = time.Time{}
	tc.deadlines(true)
}

/*
CloseAwareConn is a connection that can detect if underlying connection is closed, but only on first Write() after Reset() has been called.
This way, we can choose when the closed connection can be replaced by a new one, ensuring connection closed is only handled when expected.

This allows to detect a restart of a remote proxy, for example.

On linux and Windows (and MacOS?), a double .Write() allows to detect a closed connection, but this trick does not work all the time.
*/
type CloseAwareConn struct {
	reset   bool
	dialer  *net.Dialer
	network string
	proxy   string
	conn    net.Conn
	reqId   int32
	currId  int32
}

func NewCloseAwareConn(dialer *net.Dialer, network string, proxy string, reqId int32) (*CloseAwareConn, error) {
	cc := &CloseAwareConn{
		reset:   false,
		dialer:  dialer,
		network: network,
		proxy:   proxy,
		conn:    nil,
		reqId:   reqId,
		currId:  reqId,
	}

	err := cc.ReOpen()
	if err != nil {
		return nil, err
	}
	return cc, nil
}

func (cc *CloseAwareConn) Reset(reqId int32) {
	cc.reset = true
	cc.currId = reqId
}

func (cc *CloseAwareConn) ReOpen() error {
	c, err := cc.dialer.Dial(cc.network, cc.proxy)
	if err != nil {
		return err
	}
	ConfigureConn(c)
	cc.conn = c
	return nil
}

func (cc *CloseAwareConn) Read(b []byte) (n int, err error) {
	return cc.conn.Read(b)
}

func (cc *CloseAwareConn) Write(b []byte) (n int, err error) {
	if cc.reset && len(b) > 0 {
		cc.reset = false
		// we can eventually recreate a new connection if writing first byte fails
		n, err = cc.conn.Write(b[0:1])
		if err != nil {
			// try to recreate the connection
			if cc.ReOpen() != nil {
				return 0, err
			}
			if trace {
				logInfo("(%d) connection %d replaced by a new one", cc.currId, cc.reqId)
			}
			return cc.conn.Write(b)
		}
		// we can eventually recreate a new connection if writing next byte fails
		n, err = cc.conn.Write(b[1:])
		if err != nil {
			// try to recreate the connection
			if cc.ReOpen() != nil {
				return 0, err
			}
			if trace {
				logInfo("(%d) connection %d replaced by a new one", cc.currId, cc.reqId)
			}
			return cc.conn.Write(b)
		}
		// and rewrite buffer
		return n + 1, nil
	}
	return cc.conn.Write(b)
}

func (cc *CloseAwareConn) Close() error {
	return cc.conn.Close()
}

func (cc *CloseAwareConn) LocalAddr() net.Addr {
	return cc.conn.LocalAddr()
}

func (cc *CloseAwareConn) RemoteAddr() net.Addr {
	return cc.conn.RemoteAddr()
}

func (cc *CloseAwareConn) SetDeadline(t time.Time) error {
	return cc.conn.SetDeadline(t)
}

func (cc *CloseAwareConn) SetReadDeadline(t time.Time) error {
	return cc.conn.SetReadDeadline(t)
}

func (cc *CloseAwareConn) SetWriteDeadline(t time.Time) error {
	return cc.conn.SetWriteDeadline(t)
}

type TrafficConn struct {
	conn       net.Conn
	bytesRead  int
	bytesWrite int
	row        *ui.TrafficRow
}

func NewTrafficConn(conn net.Conn) *TrafficConn {
	return &TrafficConn{conn: conn}
}

func (c TrafficConn) Read(b []byte) (n int, err error) {
	n, err = c.conn.Read(b)
	if c.row != nil {
		c.row.BytesReceivedPerSecond.IncrementBy(c.bytesRead + n)
		c.row.LastReceive = time.Now()
		c.bytesRead = 0
	} else {
		c.bytesRead += n
	}
	return
}

func (c TrafficConn) Write(b []byte) (n int, err error) {
	n, err = c.conn.Write(b)
	if c.row != nil {
		c.row.BytesSentPerSecond.IncrementBy(c.bytesWrite + n)
		c.row.LastSend = time.Now()
		c.bytesWrite = 0
	} else {
		c.bytesWrite += n
	}
	return
}

func (c TrafficConn) Close() error {
	return c.conn.Close()
}

func (c TrafficConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c TrafficConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c TrafficConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c TrafficConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c TrafficConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
