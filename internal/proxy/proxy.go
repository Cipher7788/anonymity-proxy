package proxy

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Proxy struct {
	cfg               Config
	credential        [32]byte
	transport         *http.Transport
	dial              func(context.Context, string, string) (net.Conn, error)
	slots             chan struct{}
	mu                sync.Mutex
	tunnels           map[net.Conn]struct{}
	closing           bool
	requests          atomic.Uint64
	rejected          atomic.Uint64
	policyDenied      atomic.Uint64
	upstreamErrors    atomic.Uint64
	metricsCredential [32]byte
	metricsEnabled    bool
	certificateExpiry int64
	sockets           func() int
}

func New(c Config, user, password string) (*Proxy, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if user == "" || strings.Contains(user, ":") || len(password) < 16 {
		return nil, errors.New("username required (without colon); password must contain at least 16 bytes")
	}
	p := &Proxy{cfg: c, slots: make(chan struct{}, c.MaxConcurrent), tunnels: make(map[net.Conn]struct{})}
	p.credential = sha256.Sum256([]byte("Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))))
	p.dial = safeDial(c.AllowedPorts)
	p.transport = &http.Transport{Proxy: nil, DialContext: p.dial, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 20 * time.Second, IdleConnTimeout: 30 * time.Second, MaxIdleConns: 64, MaxIdleConnsPerHost: 4, MaxConnsPerHost: 16, DisableCompression: true, MaxResponseHeaderBytes: 1 << 20}
	return p, nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !r.URL.IsAbs() && r.URL.Path == "/metrics" {
		p.serveMetrics(w, r)
		return
	}
	p.requests.Add(1)
	candidate := sha256.Sum256([]byte(r.Header.Get("Proxy-Authorization")))
	if subtle.ConstantTimeCompare(candidate[:], p.credential[:]) != 1 {
		p.rejected.Add(1)
		w.Header().Set("Proxy-Authenticate", `Basic realm="privacy-proxy"`)
		http.Error(w, "proxy authentication required", 407)
		return
	}
	p.mu.Lock()
	closing := p.closing
	p.mu.Unlock()
	if closing {
		http.Error(w, "shutting down", 503)
		return
	}
	if !r.URL.IsAbs() && r.URL.Path == "/healthz" && r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ready"}`)
		return
	}
	select {
	case p.slots <- struct{}{}:
		defer func() { <-p.slots }()
	default:
		p.rejected.Add(1)
		http.Error(w, "capacity reached", 503)
		return
	}
	if r.Method == http.MethodConnect {
		p.connect(w, r)
		return
	}
	if !r.URL.IsAbs() || r.URL.Scheme != "http" || r.URL.Host == "" || r.URL.User != nil || r.URL.Fragment != "" {
		http.Error(w, "absolute http URL required; use CONNECT for HTTPS", 400)
		return
	}
	if r.Header.Get("Upgrade") != "" {
		http.Error(w, "protocol upgrades are unsupported", 400)
		return
	}
	address := r.URL.Host
	if r.URL.Port() == "" {
		address = net.JoinHostPort(r.URL.Hostname(), "80")
	}
	if _, _, err := validateTarget(address, p.cfg.AllowedPorts); err != nil {
		p.policyDenied.Add(1)
		http.Error(w, "destination denied", 403)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), p.cfg.RequestTimeout())
	defer cancel()
	out := r.Clone(ctx)
	out.RequestURI = ""
	out.Host = out.URL.Host
	out.Close = false
	stripHeaders(out.Header)
	rc := http.NewResponseController(w)
	_ = rc.EnableFullDuplex()
	deadline := time.Now().Add(p.cfg.RequestTimeout())
	_ = rc.SetReadDeadline(deadline)
	_ = rc.SetWriteDeadline(deadline)
	defer rc.SetReadDeadline(time.Time{})
	defer rc.SetWriteDeadline(time.Time{})
	resp, err := p.transport.RoundTrip(out)
	if err != nil {
		code := 502
		if errors.Is(err, ErrDenied) {
			code = 403
			p.policyDenied.Add(1)
		} else {
			p.upstreamErrors.Add(1)
		}
		http.Error(w, http.StatusText(code), code)
		return
	}
	defer resp.Body.Close()
	stripHeaders(resp.Header)
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if err = rc.Flush(); err != nil {
		panic(http.ErrAbortHandler)
	}
	if _, err = io.Copy(flushingWriter{writer: w, controller: rc}, resp.Body); err != nil {
		panic(http.ErrAbortHandler)
	}
}

// Forward small chunks immediately, including events on long-lived streams.
// Without an explicit flush, net/http buffers them until its buffer fills.
type flushingWriter struct {
	writer     io.Writer
	controller *http.ResponseController
}

func (w flushingWriter) Write(b []byte) (int, error) {
	n, err := w.writer.Write(b)
	if err == nil {
		err = w.controller.Flush()
	}
	return n, err
}

func stripHeaders(h http.Header) {
	for _, v := range h.Values("Connection") {
		for _, k := range strings.Split(v, ",") {
			h.Del(strings.TrimSpace(k))
		}
	}
	for _, k := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-IP", "Via"} {
		h.Del(k)
	}
}

func (p *Proxy) connect(w http.ResponseWriter, r *http.Request) {
	if r.ProtoMajor != 1 || r.ContentLength > 0 || len(r.TransferEncoding) > 0 {
		http.Error(w, "HTTP/1 CONNECT without a body required", 400)
		return
	}
	if _, _, err := validateTarget(r.Host, p.cfg.AllowedPorts); err != nil {
		p.policyDenied.Add(1)
		http.Error(w, "destination denied", 403)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	upstream, err := p.dial(ctx, "tcp", r.Host)
	if err != nil {
		code := 502
		if errors.Is(err, ErrDenied) {
			code = 403
			p.policyDenied.Add(1)
		} else {
			p.upstreamErrors.Add(1)
		}
		http.Error(w, http.StatusText(code), code)
		return
	}
	defer upstream.Close()
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "CONNECT unavailable", 501)
		return
	}
	client, rw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	p.mu.Lock()
	if p.closing {
		p.mu.Unlock()
		return
	}
	p.tunnels[client] = struct{}{}
	p.tunnels[upstream] = struct{}{}
	p.mu.Unlock()
	defer func() { p.mu.Lock(); delete(p.tunnels, client); delete(p.tunnels, upstream); p.mu.Unlock() }()
	deadline := time.Now().Add(time.Duration(p.cfg.TunnelTimeoutSeconds) * time.Second)
	_ = client.SetDeadline(deadline)
	_ = upstream.SetDeadline(deadline)
	if _, err = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err = rw.Flush(); err != nil {
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(upstream, rw)
		if c, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		} else {
			_ = upstream.Close()
		}
	}()
	_, _ = io.Copy(client, upstream)
	_ = client.Close()
	_ = upstream.Close()
	<-done
}

func (p *Proxy) Close() {
	p.mu.Lock()
	p.closing = true
	for c := range p.tunnels {
		_ = c.Close()
	}
	p.mu.Unlock()
	p.transport.CloseIdleConnections()
}
func (p *Proxy) Stats() (uint64, uint64) { return p.requests.Load(), p.rejected.Load() }
