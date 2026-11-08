package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testPassword = "test-password-at-least-16-bytes"

func authorization() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte("tester:"+testPassword))
}
func newTestProxy(t *testing.T) *Proxy {
	t.Helper()
	p, e := New(DefaultConfig(), "tester", testPassword)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(p.Close)
	return p
}

func TestPublicIP(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.100.100.200", "0.0.0.0", "224.0.0.1", "240.0.0.1", "198.18.0.1", "192.0.2.1", "::1", "::ffff:127.0.0.1", "fc00::1", "fe80::1", "2001:db8::1", "64:ff9b::a00:1", "2002:a00:1::1"} {
		if publicIP(netip.MustParseAddr(ip)) {
			t.Errorf("accepted %s", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if !publicIP(netip.MustParseAddr(ip)) {
			t.Errorf("denied %s", ip)
		}
	}
}

func TestSafeDialDeniesPrivate(t *testing.T) {
	for _, address := range []string{"127.0.0.1:80", "[::1]:443", "169.254.169.254:80", "8.8.8.8:25", "[::ffff:127.0.0.1]:80"} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		c, e := safeDial([]string{"80", "443"})(ctx, "tcp", address)
		cancel()
		if c != nil {
			c.Close()
		}
		if e == nil {
			t.Errorf("accepted %s", address)
		}
	}
}

func TestAuthenticationAndValidation(t *testing.T) {
	p := newTestProxy(t)
	for _, tc := range []struct {
		method, target, auth string
		status               int
	}{
		{"GET", "http://example.com", "", 407},
		{"GET", "http://example.com", "Basic wrong", 407},
		{"GET", "/healthz", authorization(), 200},
		{"GET", "/", authorization(), 400},
		{"GET", "https://example.com", authorization(), 400},
		{"GET", "http://127.0.0.1", authorization(), 403},
		{"GET", "http://example.com:22", authorization(), 403},
		{"CONNECT", "example.com:25", authorization(), 403},
	} {
		t.Run(tc.method+tc.target+tc.auth, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.target, nil)
			r.Header.Set("Proxy-Authorization", tc.auth)
			w := httptest.NewRecorder()
			p.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("got %d want %d", w.Code, tc.status)
			}
		})
	}
}

// Inject a local dialer only in tests. Production has no private-network bypass.
func routeTo(p *Proxy, address string) {
	p.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}
	p.transport.DialContext = p.dial
}

func TestHTTPForwardingAndHeaderIsolation(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = http.NewResponseController(w).EnableFullDuplex()
		for _, k := range []string{"Proxy-Authorization", "Forwarded", "X-Forwarded-For", "X-Real-IP", "X-Hop"} {
			if r.Header.Get(k) != "" {
				t.Errorf("leaked %s", k)
			}
		}
		if r.Host != "example.com" {
			t.Errorf("unexpected host %s", r.Host)
		}
		if r.Header.Get("Authorization") != "Bearer destination-token" {
			t.Error("origin authorization lost")
		}
		w.Header().Set("Connection", "X-Internal")
		w.Header().Set("X-Internal", "secret")
		w.WriteHeader(201)
		_, _ = io.Copy(w, r.Body)
	}))
	defer upstream.Close()
	p := newTestProxy(t)
	routeTo(p, strings.TrimPrefix(upstream.URL, "http://"))
	srv := httptest.NewServer(p)
	defer srv.Close()
	proxyURL, _ := url.Parse(srv.URL)
	proxyURL.User = url.UserPassword("tester", testPassword)
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
	payload := strings.Repeat("streaming-body", 10000)
	r, _ := http.NewRequest("POST", "http://example.com/upload", strings.NewReader(payload))
	r.Header.Set("Forwarded", "for=private")
	r.Header.Set("X-Forwarded-For", "private")
	r.Header.Set("X-Real-IP", "private")
	r.Header.Set("Connection", "X-Hop")
	r.Header.Set("X-Hop", "secret")
	r.Header.Set("Authorization", "Bearer destination-token")
	resp, e := client.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(resp.Body)
	if e != nil || resp.StatusCode != 201 || string(b) != payload {
		t.Fatalf("forwarding failed: status=%d bytes=%d err=%v", resp.StatusCode, len(b), e)
	}
	if resp.Header.Get("X-Internal") != "" {
		t.Error("hop header leaked")
	}
}

func TestHTTPSTunnel(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "secure tunnel works") }))
	defer origin.Close()
	p := newTestProxy(t)
	routeTo(p, strings.TrimPrefix(origin.URL, "https://"))
	srv := httptest.NewTLSServer(p)
	defer srv.Close()
	proxyURL, _ := url.Parse(srv.URL)
	proxyURL.User = url.UserPassword("tester", testPassword)
	roots := x509.NewCertPool()
	roots.AddCert(origin.Certificate())
	roots.AddCert(srv.Certificate())
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer tr.CloseIdleConnections()
	u, _ := url.Parse(origin.URL)
	target := "https://" + u.Hostname() + ":443/"
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
	resp, e := client.Get(target)
	if e != nil {
		t.Fatal(e)
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(resp.Body)
	if e != nil || string(b) != "secure tunnel works" {
		t.Fatalf("tunnel failed %q %v", b, e)
	}
}

func TestTunnelBufferedBytesAndShutdown(t *testing.T) {
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		c, e := listener.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
	}()
	p := newTestProxy(t)
	routeTo(p, listener.Addr().String())
	srv := httptest.NewServer(p)
	defer srv.Close()
	c, e := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.WriteString(c, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: "+authorization()+"\r\n\r\nping")
	reader := bufio.NewReader(c)
	resp, e := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
	if e != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT failed %v", e)
	}
	b := make([]byte, 4)
	if _, e = io.ReadFull(reader, b); e != nil || string(b) != "ping" {
		t.Fatalf("buffered bytes lost %q %v", b, e)
	}
	p.Close()
	if _, e = reader.ReadByte(); e == nil {
		t.Fatal("tunnel open after shutdown")
	}
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream not closed")
	}
}

func TestCapacityAndClosing(t *testing.T) {
	p := newTestProxy(t)
	for i := 0; i < cap(p.slots); i++ {
		p.slots <- struct{}{}
	}
	r := httptest.NewRequest("GET", "http://example.com/", nil)
	r.Header.Set("Proxy-Authorization", authorization())
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != 503 {
		t.Fatalf("capacity status %d", w.Code)
	}
	p.Close()
	w = httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != 503 {
		t.Fatal("accepted after close")
	}
}

func TestRequestTimeout(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer upstream.Close()
	p := newTestProxy(t)
	p.cfg.RequestTimeoutSeconds = 1
	routeTo(p, strings.TrimPrefix(upstream.URL, "http://"))
	r := httptest.NewRequest("GET", "http://example.com/", nil)
	r.Header.Set("Proxy-Authorization", authorization())
	w := httptest.NewRecorder()
	start := time.Now()
	p.ServeHTTP(w, r)
	if w.Code != 502 || time.Since(start) > 3*time.Second {
		t.Fatalf("timeout failed %d", w.Code)
	}
}

func TestConfig(t *testing.T) {
	for _, body := range []string{"null", "[]", "{}" + strings.Repeat(" ", 65536)} {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(path); err == nil {
			t.Error("accepted non-object or oversized configuration")
		}
	}
	for _, body := range []string{`{"listen":"0.0.0.0:8080"}`, `{"max_concurrent":0}`, `{"unknown":true}`, `{} {}`, `{"allowed_ports":["smtp"]}`, `{"tls_cert":"cert"}`, `{"listen":"localhost:8080"}`} {
		path := filepath.Join(t.TempDir(), "config.json")
		if e := os.WriteFile(path, []byte(body), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e := LoadConfig(path); e == nil {
			t.Errorf("accepted %s", body)
		}
	}
	if _, e := LoadConfig(""); e != nil {
		t.Fatal(e)
	}
	if _, e := New(DefaultConfig(), "tester", "short"); e == nil {
		t.Error("accepted weak credential")
	}
}

func FuzzValidateTarget(f *testing.F) {
	for _, s := range []string{"example.com:443", "[::1]:80", "bad", ":443", "example.com:25"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		host, port, e := validateTarget(s, []string{"80", "443"})
		if e == nil && (host == "" || (port != "80" && port != "443")) {
			t.Fatal("invalid target accepted")
		}
	})
}

func TestConcurrentForwarding(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer origin.Close()
	p := newTestProxy(t)
	routeTo(p, strings.TrimPrefix(origin.URL, "http://"))
	srv := httptest.NewServer(p)
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	u.User = url.UserPassword("tester", testPassword)
	tr := &http.Transport{Proxy: http.ProxyURL(u)}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.Get("http://example.com/")
			if err != nil {
				t.Error(err)
				return
			}
			defer resp.Body.Close()
			b, err := io.ReadAll(resp.Body)
			if err != nil || string(b) != "ok" {
				t.Errorf("bad concurrent response %q %v", b, err)
			}
		}()
	}
	wg.Wait()
}

func TestTunnelLifetime(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := listener.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(io.Discard, c)
	}()
	p := newTestProxy(t)
	p.cfg.TunnelTimeoutSeconds = 1
	routeTo(p, listener.Addr().String())
	srv := httptest.NewServer(p)
	defer srv.Close()
	c, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	_, _ = io.WriteString(c, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: "+authorization()+"\r\n\r\n")
	reader := bufio.NewReader(c)
	resp, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("tunnel handshake failed %v", err)
	}
	if _, err = reader.ReadByte(); err == nil {
		t.Fatal("expired tunnel still open")
	} else if n, ok := err.(net.Error); ok && n.Timeout() {
		t.Fatal("tunnel exceeded lifetime")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("upstream leaked after expiry")
	}
}

// Opt-in smoke test uses the real production resolver and policy against a public origin.
func TestPublicInternet(t *testing.T) {
	if os.Getenv("PROXY_TEST_INTERNET") != "1" {
		t.Skip("set PROXY_TEST_INTERNET=1 to exercise public egress")
	}
	p := newTestProxy(t)
	srv := httptest.NewServer(p)
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	u.User = url.UserPassword("tester", testPassword)
	tr := &http.Transport{Proxy: http.ProxyURL(u)}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 25 * time.Second}
	for _, target := range []string{"http://example.com/", "https://example.com/"} {
		resp, err := client.Get(target)
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 || !strings.Contains(string(b), "Example Domain") {
			t.Fatalf("public smoke failed: status %d, error %v", resp.StatusCode, err)
		}
	}
}
