package transport

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	ratecounter "github.com/enterprizesoftware/rate-counter"
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

type TrafficConn struct {
	Conn       net.Conn
	tcpConn    *net.TCPConn
	withStats  bool
	BytesRead  *ratecounter.Rate
	BytesWrite *ratecounter.Rate
	LastUse    time.Time
	Closed     atomic.Bool
}

func NewTrafficConn(conn net.Conn, withStats bool) *TrafficConn {
	var tcpConn *net.TCPConn
	switch c := conn.(type) {
	case *net.TCPConn:
		tcpConn = c
	case *tls.Conn:
		if tc, ok := c.NetConn().(*net.TCPConn); ok {
			tcpConn = tc
		}
	default:
		panic(fmt.Sprintf("unsupported connection type: %T\n", conn))
	}
	tc := &TrafficConn{
		Conn:      conn,
		tcpConn:   tcpConn,
		withStats: withStats,
	}
	if withStats {
		tc.BytesRead = ratecounter.New(100*time.Millisecond, 5*time.Second)
		tc.BytesWrite = ratecounter.New(100*time.Millisecond, 5*time.Second)
		tc.LastUse = time.Now()
	}
	return tc
}

func (tc *TrafficConn) Read(b []byte) (n int, err error) {
	n, err = tc.Conn.Read(b)
	if tc.withStats {
		tc.BytesRead.IncrementBy(n)
		tc.LastUse = time.Now()
	}
	return
}

func (tc *TrafficConn) Write(b []byte) (n int, err error) {
	n, err = tc.Conn.Write(b)
	if tc.withStats {
		tc.BytesWrite.IncrementBy(n)
		tc.LastUse = time.Now()
	}
	return
}

func (tc *TrafficConn) Close() error {
	tc.Closed.Store(true)
	return tc.Conn.Close()
}

func (tc *TrafficConn) CloseWrite() error {
	return tc.tcpConn.CloseWrite()
}

// func (tc *TrafficConn) LocalAddr() net.Addr {
// 	return tc.conn.LocalAddr()
// }

// func (tc *TrafficConn) RemoteAddr() net.Addr {
// 	return tc.conn.RemoteAddr()
// }

// func (tc *TrafficConn) SetDeadline(t time.Time) error {
// 	return tc.conn.SetDeadline(t)
// }

// func (tc *TrafficConn) SetReadDeadline(t time.Time) error {
// 	return tc.conn.SetReadDeadline(t)
// }

// func (tc *TrafficConn) SetWriteDeadline(t time.Time) error {
// 	return tc.conn.SetWriteDeadline(t)
// }
