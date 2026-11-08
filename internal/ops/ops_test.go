package ops

import (
	"context"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInitializerAndTLSImport(t *testing.T) {
	dir := t.TempDir()
	o := InitOptions{Directory: dir, Mode: "development", Hostname: "localhost"}
	if e := Init(o); e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{".env", "secrets/proxy_password", "secrets/metrics_token", "tls/key.pem", "tls/cert.pem", "deploy/generated/prometheus.yml", "deploy/generated/alertmanager.yml"} {
		if _, e := os.Stat(filepath.Join(dir, path)); e != nil {
			t.Fatal(e)
		}
	}
	if e := Init(o); e == nil {
		t.Fatal("overwrote initialized deployment")
	}
	o.Mode = "production"
	o.CertFile = filepath.Join(dir, "tls/cert.pem")
	o.KeyFile = filepath.Join(dir, "tls/key.pem")
	o.CAFile = filepath.Join(dir, "tls/ca.pem")
	if _, _, _, e := importedTLS(o); e != nil {
		t.Fatal(e)
	}
	o.Hostname = "wrong.example"
	if _, _, _, e := importedTLS(o); e == nil {
		t.Fatal("accepted mismatched hostname")
	}
	o.Hostname = ""
	if _, _, _, e := importedTLS(o); e == nil {
		t.Fatal("accepted import without hostname verification")
	}
	if e := Init(InitOptions{Directory: t.TempDir(), Mode: "development", Hostname: "localhost", BindIP: "0.0.0.0"}); e == nil {
		t.Fatal("exposed development credentials")
	}
}

func TestSecrets(t *testing.T) {
	f := filepath.Join(t.TempDir(), "secret")
	if e := os.WriteFile(f, []byte("file-secret\r\n"), 0600); e != nil {
		t.Fatal(e)
	}
	t.Setenv("TEST_SECRET", "environment")
	t.Setenv("TEST_SECRET_FILE", f)
	s, e := Secret("TEST_SECRET")
	if e != nil || s != "file-secret" {
		t.Fatal("file precedence failed")
	}
	if e = os.WriteFile(f, []byte(strings.Repeat("a", 4097)), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = Secret("TEST_SECRET"); e == nil {
		t.Fatal("accepted oversized secret")
	}
}

func TestHealthVerifiesTLSAndAuth(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") == "" {
			w.WriteHeader(407)
			return
		}
		_, _ = io.WriteString(w, `{"status":"ready"}`)
	}))
	defer srv.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if e := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0600); e != nil {
		t.Fatal(e)
	}
	listen := strings.TrimPrefix(srv.URL, "https://")
	if e := Health(context.Background(), listen, true, "", ca, "user", "password"); e != nil {
		t.Fatal(e)
	}
	if e := Health(context.Background(), listen, true, "", "", "user", "password"); e == nil {
		t.Fatal("trusted unknown certificate")
	}
	if e := Health(context.Background(), listen, true, "wrong.example", ca, "user", "password"); e == nil {
		t.Fatal("accepted wrong certificate hostname")
	}
}

func TestLoadGates(t *testing.T) {
	for _, status := range []int{200, 503} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status); _, _ = io.WriteString(w, "ok") }))
		report, e := Load(context.Background(), srv.Client(), LoadOptions{Target: srv.URL, Duration: time.Second, Concurrency: 2, MaxErrorRate: 0, P95Limit: time.Second})
		srv.Close()
		if report.Completed == 0 {
			t.Fatal("no load generated")
		}
		if status == 200 && (e != nil || !report.Passed) {
			t.Fatal("healthy load failed", e)
		}
		if status == 503 && (e == nil || report.Passed) {
			t.Fatal("failed load passed")
		}
	}
	if _, e := Client("http://remote.example:8080", "u", "p", ""); e == nil {
		t.Fatal("accepted plaintext remote proxy")
	}
}
