package kpx

import (
	"math"
	"net"
	"time"
)

/*
Wrapper around net.Conn which provides automatic read/write timeouts:
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
