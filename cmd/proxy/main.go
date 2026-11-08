package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/Cipher7788/anonymity-proxy/internal/proxy"
)

// Bound sockets before HTTP parsing/authentication, including idle and TLS clients.
type limitedListener struct {
	net.Listener
	slots chan struct{}
}
type countedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *countedConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &countedConn{Conn: c, release: func() { <-l.slots }}, nil
		default:
			_ = c.Close()
		}
	}
}

func run() error {
	path := flag.String("config", "", "JSON configuration file")
	check := flag.Bool("check-config", false, "validate configuration and credentials without listening")
	flag.Parse()
	c, err := proxy.LoadConfig(*path)
	if err != nil {
		return err
	}
	password := os.Getenv("PROXY_PASSWORD")
	if secret := os.Getenv("PROXY_PASSWORD_FILE"); secret != "" {
		b, e := os.ReadFile(secret)
		if e != nil {
			return e
		}
		password = string(b)
		for len(password) > 0 && (password[len(password)-1] == '\n' || password[len(password)-1] == '\r') {
			password = password[:len(password)-1]
		}
	}
	p, err := proxy.New(c, os.Getenv("PROXY_USERNAME"), password)
	if err != nil {
		return err
	}
	defer p.Close()
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	if c.TLSCert != "" {
		cert, e := tls.LoadX509KeyPair(c.TLSCert, c.TLSKey)
		if e != nil {
			return e
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	if *check {
		return nil
	}
	srv := &http.Server{Addr: c.Listen, Handler: p, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: c.RequestTimeout(), WriteTimeout: c.RequestTimeout(), IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10, TLSConfig: tlsConfig, TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}, ErrorLog: log.New(io.Discard, "", 0)}
	listener, err := net.Listen("tcp", c.Listen)
	if err != nil {
		return err
	}
	bounded := &limitedListener{Listener: listener, slots: make(chan struct{}, c.MaxConcurrent)}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() {
		if c.TLSCert != "" {
			done <- srv.ServeTLS(bounded, "", "")
		} else {
			done <- srv.Serve(bounded)
		}
	}()
	slog.Info("proxy started", "listen", c.Listen, "tls", c.TLSCert != "")
	select {
	case err = <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		p.Close()
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err = srv.Shutdown(shutdown); err != nil {
			_ = srv.Close()
			return err
		}
	}
	requests, rejected := p.Stats()
	slog.Info("proxy stopped", "requests", requests, "rejected", rejected)
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "proxy:", err)
		os.Exit(1)
	}
}
