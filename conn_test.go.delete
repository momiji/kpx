package kpx

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestClosedConnFailsOnWrite(t *testing.T) {
	hp := "127.0.0.1:12345"
	// create a fake server on random port
	l, err := net.Listen("tcp4", hp)
	if err != nil {
		t.Fatalf("error listen: %v", err)
	}
	go func() {
		http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
			fmt.Fprintf(writer, "Hello, %s!", request.URL.Path[1:])
		})
		http.Serve(l, nil)
	}()
	// create a connection to this random port
	dialer := new(net.Dialer)
	c, err := dialer.Dial("tcp4", hp)
	if err != nil {
		t.Fatalf("error dial: %v", err)
	}
	ConfigureConn(c)
	// get content
	_, err = c.Write([]byte("GET /world HTTP/1.0\n\n"))
	if err != nil {
		t.Fatalf("error write 1: %v", err)
	}
	b := make([]byte, 4096)
	n, err := c.Read(b)
	if err != nil {
		t.Fatalf("error read 1: %v", err)
	}
	if !strings.Contains(string(b[0:n]), "Hello, world!") {
		t.Fatalf("error, 'Hello, world!' not found")
	}
	// restart http server
	l.Close()
	// get content and check it fails
	_, err = c.Write([]byte("G"))
	if err != nil {
		t.Log("Fail on first write: success")
		return
	}
	_, err = c.Write([]byte("ET / HTTP/1.0\n\n"))
	if err != nil {
		t.Log("Fail on second write: success")
		return
	}
	n, err = c.Read(b)
	if err != nil {
		// unfortunately, this still happen from time to time
		t.Fatalf("error read 2: %v", err)
	}
	t.Fatalf("error write and read")
}

func TestLostConnection(t *testing.T) {
	hp := "127.0.0.1:12345"
	// create a fake server on random port
	l, err := net.Listen("tcp4", hp)
	if err != nil {
		t.Fatalf("error listen: %v", err)
	}
	go func() {
		http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
			fmt.Fprintf(writer, "Hello, %s!", request.URL.Path[1:])
		})
		http.Serve(l, nil)
	}()
	// create a connection to this random port
	dialer := new(net.Dialer)
	c, err := dialer.Dial("tcp4", hp)
	if err != nil {
		t.Fatalf("error dial: %v", err)
	}
	// get content
	_, err = c.Write([]byte("GET /world HTTP/1.0\n\n"))
	if err != nil {
		t.Fatalf("error write 1: %v", err)
	}
	b := make([]byte, 4096)
	n, err := c.Read(b)
	if err != nil {
		t.Fatalf("error read 1: %v", err)
	}
	if !strings.Contains(string(b[0:n]), "Hello, world!") {
		t.Fatalf("error, 'Hello, world!' not found")
	}
	c.SetDeadline(time.Now().Add(time.Second * 5))
	time.Sleep(time.Second * 60)
	l.Close()
}
