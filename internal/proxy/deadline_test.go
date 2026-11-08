package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestServerDeadlineAllowsTimeoutResponse(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stream" {
			_, _ = io.WriteString(w, "data: first\n\n")
			w.(http.Flusher).Flush()
		}
		<-r.Context().Done()
	}))
	defer origin.Close()
	p := newTestProxy(t)
	p.cfg.RequestTimeoutSeconds = 1
	routeTo(p, strings.TrimPrefix(origin.URL, "http://"))
	srv := httptest.NewUnstartedServer(p)
	srv.Config.ReadTimeout = time.Second
	srv.Config.WriteTimeout = 2 * time.Second
	srv.Start()
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	u.User = url.UserPassword("tester", testPassword)
	tr := &http.Transport{Proxy: http.ProxyURL(u)}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 4 * time.Second}
	resp, e := client.Get("http://example.com/slow")
	if e != nil {
		t.Fatal("timeout response lost", e)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != 502 {
		t.Fatalf("got %d", resp.StatusCode)
	}
	resp.Body.Close()
	stream, e := client.Get("http://example.com/stream")
	if e != nil {
		t.Fatal(e)
	}
	defer stream.Body.Close()
	b := make([]byte, len("data: first\n\n"))
	if n, e := io.ReadFull(stream.Body, b); e != nil || string(b) != "data: first\n\n" {
		t.Fatalf("stream after timeout: status=%d bytes=%d body=%q error=%v", stream.StatusCode, n, b, e)
	}
}
