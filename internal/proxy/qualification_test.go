package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Cipher7788/anonymity-proxy/internal/ops"
)

func TestLoadQualification(t *testing.T) {
	if os.Getenv("PROXY_QUALIFY") != "1" {
		t.Skip("set PROXY_QUALIFY=1 for controlled load/resource qualification")
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	goroutines := runtime.NumGoroutine()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, strings.Repeat("x", 1024)) }))
	p := newTestProxy(t)
	routeTo(p, strings.TrimPrefix(origin.URL, "http://"))
	srv := httptest.NewServer(p)
	u, _ := url.Parse(srv.URL)
	u.User = url.UserPassword("tester", testPassword)
	tr := &http.Transport{Proxy: http.ProxyURL(u), MaxIdleConns: 32, MaxIdleConnsPerHost: 16}
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	report, e := ops.Load(context.Background(), client, ops.LoadOptions{Target: "http://example.com/", Duration: 5 * time.Second, Concurrency: 16, MaxErrorRate: 0, P95Limit: 2 * time.Second})
	tr.CloseIdleConnections()
	p.Close()
	srv.Close()
	origin.Close()
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > goroutines+16 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	result := struct {
		ops.LoadReport
		GoroutinesBefore, GoroutinesAfter int
		HeapBefore, HeapAfter             uint64
	}{report, goroutines, runtime.NumGoroutine(), before.HeapAlloc, after.HeapAlloc}
	if path := os.Getenv("PROXY_REPORT_DIR"); path != "" {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
		b, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(path, "controlled-load.json"), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if e != nil {
		t.Fatal(e)
	}
	if len(p.slots) != 0 {
		t.Fatal("active operations leaked")
	}
	if result.GoroutinesAfter > goroutines+16 {
		t.Fatal("goroutines did not recover")
	}
	if after.HeapAlloc > before.HeapAlloc+32<<20 {
		t.Fatal("retained heap exceeded 32 MiB growth budget")
	}
}
