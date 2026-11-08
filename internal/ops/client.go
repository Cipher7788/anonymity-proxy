package ops

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func Secret(name string) (string, error) {
	if path := os.Getenv(name + "_FILE"); path != "" {
		f, e := os.Open(path)
		if e != nil {
			return "", e
		}
		defer f.Close()
		b, e := io.ReadAll(io.LimitReader(f, 4097))
		if e != nil {
			return "", e
		}
		if len(b) > 4096 {
			return "", errors.New("secret exceeds 4096 bytes")
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	return os.Getenv(name), nil
}

func TLSConfig(caFile string) (*tls.Config, error) {
	roots, e := x509.SystemCertPool()
	if e != nil {
		roots = x509.NewCertPool()
	}
	if caFile != "" {
		b, e := os.ReadFile(caFile)
		if e != nil {
			return nil, e
		}
		if !roots.AppendCertsFromPEM(b) {
			return nil, errors.New("CA file contains no certificates")
		}
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, nil
}

func Client(proxyAddress, user, password, caFile string) (*http.Client, error) {
	u, e := url.Parse(proxyAddress)
	if e != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("invalid proxy URL; credentials belong in secret files")
	}
	if u.Scheme == "http" {
		ip := net.ParseIP(u.Hostname())
		if ip == nil || !ip.IsLoopback() {
			return nil, errors.New("plaintext proxy testing is limited to loopback")
		}
	}
	t, e := TLSConfig(caFile)
	if e != nil {
		return nil, e
	}
	u.User = url.UserPassword(user, password)
	tr := &http.Transport{Proxy: http.ProxyURL(u), TLSClientConfig: t, MaxIdleConns: 128, MaxIdleConnsPerHost: 64, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, IdleConnTimeout: 10 * time.Second}
	return &http.Client{Transport: tr, Timeout: 15 * time.Second}, nil
}

func Health(ctx context.Context, listen string, tlsEnabled bool, serverName, caFile, user, password string) error {
	host, port, e := net.SplitHostPort(listen)
	if e != nil {
		return e
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		host = "127.0.0.1"
		if ip.To4() == nil {
			host = "::1"
		}
	}
	scheme := "http"
	if tlsEnabled {
		scheme = "https"
	}
	tc, e := TLSConfig(caFile)
	if e != nil {
		return e
	}
	tc.ServerName = serverName
	tr := &http.Transport{TLSClientConfig: tc, Proxy: nil}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	req, e := http.NewRequestWithContext(ctx, "GET", scheme+"://"+net.JoinHostPort(host, port)+"/healthz", nil)
	if e != nil {
		return e
	}
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+password)))
	resp, e := c.Do(req)
	if e != nil {
		return errors.New("health connection or certificate verification failed")
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if e != nil {
		return e
	}
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"ready"`) {
		return fmt.Errorf("health returned status %d", resp.StatusCode)
	}
	return nil
}
