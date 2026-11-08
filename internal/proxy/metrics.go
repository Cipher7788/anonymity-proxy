package proxy

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"runtime"
)

// ConfigureMetrics must be called before serving. This credential cannot proxy traffic.
func (p *Proxy) ConfigureMetrics(token string, certificateExpiry int64, sockets func() int) error {
	if len(token) < 32 {
		return errors.New("metrics token must contain at least 32 bytes")
	}
	p.metricsCredential = sha256.Sum256([]byte("Bearer " + token))
	p.metricsEnabled = true
	p.certificateExpiry = certificateExpiry
	p.sockets = sockets
	return nil
}

func (p *Proxy) serveMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !p.metricsEnabled {
		http.NotFound(w, r)
		return
	}
	candidate := sha256.Sum256([]byte(r.Header.Get("Authorization")))
	if subtle.ConstantTimeCompare(candidate[:], p.metricsCredential[:]) != 1 {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "metrics authentication required", 401)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", 405)
		return
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	metric := func(name, kind, help string, value any) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n%s %v\n", name, help, name, kind, name, value)
	}
	metric("proxy_requests_total", "counter", "Requests including authenticated health probes; excludes metric scrapes.", p.requests.Load())
	metric("proxy_rejected_total", "counter", "Authentication and operation capacity rejections.", p.rejected.Load())
	metric("proxy_policy_denied_total", "counter", "Destination policy rejections.", p.policyDenied.Load())
	metric("proxy_upstream_errors_total", "counter", "Failed upstream requests or tunnel connections.", p.upstreamErrors.Load())
	metric("proxy_active_operations", "gauge", "Current forwarding operations and tunnels.", len(p.slots))
	metric("proxy_capacity", "gauge", "Configured socket and operation limit.", cap(p.slots))
	if p.sockets != nil {
		metric("proxy_open_connections", "gauge", "Accepted client sockets, including idle connections.", p.sockets())
	}
	metric("proxy_tls_certificate_expiry_timestamp_seconds", "gauge", "Proxy TLS leaf expiry; zero if TLS is disabled.", p.certificateExpiry)
	metric("proxy_heap_bytes", "gauge", "Go allocated heap bytes.", m.HeapAlloc)
	metric("proxy_goroutines", "gauge", "Go goroutines.", runtime.NumGoroutine())
}
