package main

import (
	"net"
	"testing"
	"time"
)

func TestListenerCapacityAndRelease(t *testing.T) {
	raw, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer raw.Close()
	l := &limitedListener{Listener: raw, slots: make(chan struct{}, 1)}
	first, e := net.Dial("tcp", raw.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer first.Close()
	accepted, e := l.Accept()
	if e != nil {
		t.Fatal(e)
	}
	defer accepted.Close()
	next := make(chan net.Conn, 1)
	go func() {
		c, e := l.Accept()
		if e == nil {
			next <- c
		}
	}()
	rejected, e := net.Dial("tcp", raw.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer rejected.Close()
	_ = rejected.SetReadDeadline(time.Now().Add(time.Second))
	if _, e = rejected.Read(make([]byte, 1)); e == nil {
		t.Fatal("excess socket accepted")
	} else if n, ok := e.(net.Error); ok && n.Timeout() {
		t.Fatal("excess socket not closed")
	}
	_ = accepted.Close()
	_ = accepted.Close() // release exactly once
	third, e := net.Dial("tcp", raw.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer third.Close()
	select {
	case c := <-next:
		c.Close()
	case <-time.After(time.Second):
		t.Fatal("slot not released")
	}
}
