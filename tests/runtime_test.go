package tests

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Cipher7788/anonymity-proxy/internal/ops"
)

func TestContainerRuntime(t *testing.T) {
	if os.Getenv("PROXY_RUNTIME_TEST") != "1" {
		t.Skip("requires isolated Compose runtime stack")
	}
	root := os.Getenv("PROXY_DEPLOY_DIR")
	if root == "" {
		t.Fatal("PROXY_DEPLOY_DIR required")
	}
	secret := func(name string) string {
		b, e := os.ReadFile(filepath.Join(root, "secrets", name))
		if e != nil {
			t.Fatal(e)
		}
		return strings.TrimSpace(string(b))
	}
	password, token := secret("proxy_password"), secret("metrics_token")
	ca := filepath.Join(root, "tls/ca.pem")
	client, e := ops.Client("https://localhost:8080", "operator", password, ca)
	if e != nil {
		t.Fatal(e)
	}
	defer client.CloseIdleConnections()
	tc, e := ops.TLSConfig(ca)
	if e != nil {
		t.Fatal(e)
	}
	direct := &http.Client{Transport: &http.Transport{TLSClientConfig: tc}, Timeout: 5 * time.Second}
	defer direct.CloseIdleConnections()
	get := func(target string, status int) {
		t.Helper()
		resp, e := client.Get(target)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		if resp.StatusCode != status {
			t.Fatalf("got %d want %d", resp.StatusCode, status)
		}
	}
	health := func() error {
		return ops.Health(context.Background(), "127.0.0.1:8080", true, "localhost", ca, "operator", password)
	}
	waitHealthy := func() {
		t.Helper()
		deadline := time.Now().Add(45 * time.Second)
		for time.Now().Before(deadline) {
			if health() == nil {
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
		t.Fatal("proxy did not recover")
	}
	docker := func(args ...string) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		base := []string{"compose", "-f", "compose.yaml", "-f", "compose.runtime.yaml"}
		cmd := exec.CommandContext(ctx, "docker", append(base, args...)...)
		cmd.Dir = root
		b, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("docker operation failed: %v %s", e, b)
		}
		return b
	}
	t.Run("readiness_auth_and_verified_TLS", func(t *testing.T) {
		waitHealthy()
		r, e := direct.Get("https://localhost:8080/healthz")
		if e != nil {
			t.Fatal(e)
		}
		r.Body.Close()
		if r.StatusCode != 407 {
			t.Fatal("unauthenticated health accepted")
		}
		if e := ops.Health(context.Background(), "127.0.0.1:8080", true, "localhost", "", "operator", password); e == nil {
			t.Fatal("untrusted proxy certificate accepted")
		}
	})
	t.Run("HTTP_and_HTTPS", func(t *testing.T) { get("http://origin:8081/ok", 200); get("https://origin:8443/ok", 200) })
	t.Run("private_and_metadata_denial", func(t *testing.T) { get("http://127.0.0.1:8081/", 403); get("http://169.254.169.254:8081/", 403) })
	t.Run("upstream_reset_and_timeout", func(t *testing.T) {
		get("http://origin:8081/reset", 502)
		start := time.Now()
		get("http://origin:8081/slow", 502)
		if time.Since(start) > 5*time.Second {
			t.Fatal("timeout not enforced")
		}
	})
	t.Run("streaming", func(t *testing.T) {
		r, e := client.Get("http://origin:8081/stream")
		if e != nil {
			t.Fatal(e)
		}
		defer r.Body.Close()
		b := make([]byte, len("data: first\n\n"))
		if _, e = io.ReadFull(r.Body, b); e != nil || string(b) != "data: first\n\n" {
			t.Fatal("streaming failed", e)
		}
	})
	t.Run("metrics_isolation", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "https://localhost:8080/metrics", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		r, e := direct.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		if r.StatusCode != 200 || !strings.Contains(string(b), "proxy_policy_denied_total") {
			t.Fatal("metrics unavailable")
		}
		if strings.Contains(string(b), password) || strings.Contains(string(b), "origin:") {
			t.Fatal("sensitive metrics")
		}
	})
	t.Run("tunnel_expiry", func(t *testing.T) {
		c, e := tls.Dial("tcp", "localhost:8080", tc)
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(6 * time.Second))
		auth := base64.StdEncoding.EncodeToString([]byte("operator:" + password))
		_, _ = io.WriteString(c, "CONNECT origin:8443 HTTP/1.1\r\nHost: origin:8443\r\nProxy-Authorization: Basic "+auth+"\r\n\r\n")
		r := bufio.NewReader(c)
		resp, e := http.ReadResponse(r, &http.Request{Method: "CONNECT"})
		if e != nil || resp.StatusCode != 200 {
			t.Fatal("tunnel handshake failed", e)
		}
		if _, e = r.ReadByte(); e == nil {
			t.Fatal("tunnel did not expire")
		} else if ne, ok := e.(net.Error); ok && ne.Timeout() {
			t.Fatal("lifetime exceeded")
		}
	})
	t.Run("controlled_container_load", func(t *testing.T) {
		report, e := ops.Load(context.Background(), client, ops.LoadOptions{Target: "https://origin:8443/ok", Duration: 5 * time.Second, Concurrency: 4, MaxErrorRate: .01, P95Limit: time.Second})
		b, _ := json.MarshalIndent(report, "", "  ")
		if err := os.MkdirAll(filepath.Join(root, "reports"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "reports/container-load.json"), b, 0600); err != nil {
			t.Fatal(err)
		}
		if e != nil {
			t.Fatal(e)
		}
	})
	t.Run("read_only_nonroot_and_limits", func(t *testing.T) {
		id := strings.TrimSpace(string(docker("ps", "-q", "proxy")))
		cmd := exec.Command("docker", "inspect", id)
		b, e := cmd.Output()
		if e != nil {
			t.Fatal(e)
		}
		var info []struct {
			Config     struct{ User string }
			HostConfig struct {
				ReadonlyRootfs bool
				Memory         int64
				CapDrop        []string
			}
		}
		if e = json.Unmarshal(b, &info); e != nil || len(info) != 1 {
			t.Fatal("invalid container inspection", e)
		}
		if info[0].Config.User != "10001:10001" || !info[0].HostConfig.ReadonlyRootfs || info[0].HostConfig.Memory <= 0 || len(info[0].HostConfig.CapDrop) == 0 {
			t.Fatal("container hardening missing")
		}
	})
	t.Run("monitoring_scrape", func(t *testing.T) {
		deadline := time.Now().Add(45 * time.Second)
		for time.Now().Before(deadline) {
			r, e := http.Get("http://127.0.0.1:9090/api/v1/targets")
			if e == nil {
				var out struct {
					Data struct{ ActiveTargets []struct{ Health string } }
				}
				e = json.NewDecoder(r.Body).Decode(&out)
				r.Body.Close()
				if e == nil && len(out.Data.ActiveTargets) > 0 && out.Data.ActiveTargets[0].Health == "up" {
					return
				}
			}
			time.Sleep(time.Second)
		}
		t.Fatal("Prometheus TLS/token scrape failed")
	})
	t.Run("graceful_stop_and_restart", func(t *testing.T) {
		client.CloseIdleConnections()
		docker("stop", "-t", "20", "proxy")
		defer docker("start", "proxy")
		logs := docker("logs", "--no-color", "proxy")
		if !strings.Contains(string(logs), "proxy stopped") {
			t.Fatal("no graceful shutdown record")
		}
		docker("start", "proxy")
		waitHealthy()
	})
	t.Run("crash_recovery", func(t *testing.T) {
		client.CloseIdleConnections()
		docker("kill", "-s", "KILL", "proxy")
		waitHealthy()
	})
}
