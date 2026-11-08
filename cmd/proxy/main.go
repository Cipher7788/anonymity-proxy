package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

	"github.com/Cipher7788/anonymity-proxy/internal/ops"
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
	health := flag.Bool("healthcheck", false, "check the configured listener with certificate verification")
	flag.Parse()
	c, err := proxy.LoadConfig(*path)
	if err != nil {
		return err
	}
	password, err := ops.Secret("PROXY_PASSWORD")
	if err != nil {
		return err
	}
	if *health {
		return ops.Health(context.Background(), c.Listen, c.TLSCert != "", os.Getenv("PROXY_TLS_SERVER_NAME"), os.Getenv("PROXY_CA_FILE"), os.Getenv("PROXY_USERNAME"), password)
	}
	p, err := proxy.New(c, os.Getenv("PROXY_USERNAME"), password)
	if err != nil {
		return err
	}
	defer p.Close()
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	var expiry int64
	if c.TLSCert != "" {
		cert, e := tls.LoadX509KeyPair(c.TLSCert, c.TLSKey)
		if e != nil {
			return e
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
		leaf, e := x509.ParseCertificate(cert.Certificate[0])
		if e != nil {
			return e
		}
		expiry = leaf.NotAfter.Unix()
	}
	token, err := ops.Secret("PROXY_METRICS_TOKEN")
	if err != nil {
		return err
	}
	var bounded *limitedListener
	if token != "" {
		if err = p.ConfigureMetrics(token, expiry, func() int {
			if bounded == nil {
				return 0
			}
			return len(bounded.slots)
		}); err != nil {
			return err
		}
	}
	if *check {
		return nil
	}
	srv := &http.Server{Addr: c.Listen, Handler: p, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: c.RequestTimeout(), WriteTimeout: c.RequestTimeout() + time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10, TLSConfig: tlsConfig, TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}, ErrorLog: log.New(io.Discard, "", 0)}
	listener, err := net.Listen("tcp", c.Listen)
	if err != nil {
		return err
	}
	bounded = &limitedListener{Listener: listener, slots: make(chan struct{}, c.MaxConcurrent)}
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
