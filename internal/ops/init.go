package ops

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

type InitOptions struct{ Directory, Hostname, Mode, CertFile, KeyFile, CAFile, WebhookFile, BindIP string }

func randomSecret() (string, error) {
	b := make([]byte, 32)
	_, e := rand.Read(b)
	return hex.EncodeToString(b), e
}

func developmentTLS(host string) ([]byte, []byte, []byte, error) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, nil, nil, e
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return nil, nil, nil, e
	}
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Proxy development certificate"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(30 * 24 * time.Hour), DNSNames: []string{host, "localhost", "proxy", "origin"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		return nil, nil, nil, e
	}
	pk, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return nil, nil, nil, e
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), certPEM, nil
}

func importedTLS(o InitOptions) ([]byte, []byte, []byte, error) {
	if !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$`).MatchString(o.Hostname) {
		return nil, nil, nil, errors.New("certificate import requires an explicit valid hostname")
	}
	cert, e := os.ReadFile(o.CertFile)
	if e != nil {
		return nil, nil, nil, e
	}
	key, e := os.ReadFile(o.KeyFile)
	if e != nil {
		return nil, nil, nil, e
	}
	pair, e := tls.X509KeyPair(cert, key)
	if e != nil {
		return nil, nil, nil, e
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		return nil, nil, nil, e
	}
	caFile := o.CAFile
	if caFile == "" {
		caFile = "/etc/ssl/certs/ca-certificates.crt"
	}
	ca, e := os.ReadFile(caFile)
	if e != nil {
		return nil, nil, nil, errors.New("supply -ca with a trusted CA bundle")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, nil, nil, errors.New("invalid CA bundle")
	}
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		c, e := x509.ParseCertificate(der)
		if e != nil {
			return nil, nil, nil, e
		}
		intermediates.AddCert(c)
	}
	if _, e = leaf.Verify(x509.VerifyOptions{DNSName: o.Hostname, Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); e != nil {
		return nil, nil, nil, e
	}
	if time.Until(leaf.NotAfter) < 7*24*time.Hour {
		return nil, nil, nil, errors.New("certificate must have at least seven days remaining")
	}
	return cert, key, ca, nil
}

func atomicFile(path string, data []byte, mode os.FileMode) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".proxy-stage-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(mode); e != nil {
		f.Close()
		return e
	}
	if _, e = f.Write(data); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(name, path)
}

func Init(o InitOptions) error {
	if !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$`).MatchString(o.Hostname) {
		return errors.New("invalid hostname")
	}
	if o.BindIP == "" {
		o.BindIP = "127.0.0.1"
	}
	if net.ParseIP(o.BindIP) == nil || net.ParseIP(o.BindIP).To4() == nil {
		return errors.New("bind must be an IPv4 literal")
	}
	if o.Mode != "development" && o.Mode != "production" {
		return errors.New("mode must be development or production")
	}
	if o.Mode == "development" && !net.ParseIP(o.BindIP).IsLoopback() {
		return errors.New("development setup must bind to loopback")
	}
	var cert, key, ca []byte
	var e error
	if o.Mode == "development" {
		cert, key, ca, e = developmentTLS(o.Hostname)
	} else {
		cert, key, ca, e = importedTLS(o)
	}
	if e != nil {
		return e
	}
	var webhook []byte
	if o.WebhookFile != "" {
		webhook, e = os.ReadFile(o.WebhookFile)
		if e != nil {
			return e
		}
		u, err := url.Parse(string(trimSecret(webhook)))
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			return errors.New("alert webhook must be an HTTPS URL without userinfo")
		}
	}
	if o.Mode == "production" && len(webhook) == 0 {
		return errors.New("production setup requires -alert-webhook-file for notifications")
	}
	password, e := randomSecret()
	if e != nil {
		return e
	}
	token, e := randomSecret()
	if e != nil {
		return e
	}
	alertConfig := "route:\n  receiver: local-only\nreceivers:\n  - name: local-only\n"
	if len(webhook) > 0 {
		alertConfig = "route:\n  receiver: operations\n  group_wait: 30s\n  repeat_interval: 4h\nreceivers:\n  - name: operations\n    webhook_configs:\n      - url_file: /run/secrets/alert_webhook\n        send_resolved: true\n"
	} else {
		webhook = []byte("https://example.invalid/not-configured")
	}
	prometheus := fmt.Sprintf("global:\n  scrape_interval: 15s\n  evaluation_interval: 15s\nrule_files:\n  - /etc/prometheus/alerts.yml\nalerting:\n  alertmanagers:\n    - static_configs:\n        - targets: ['alertmanager:9093']\nscrape_configs:\n  - job_name: proxy\n    scheme: https\n    metrics_path: /metrics\n    authorization:\n      credentials_file: /run/secrets/metrics_token\n    tls_config:\n      ca_file: /run/secrets/proxy_ca\n      server_name: %s\n    static_configs:\n      - targets: ['proxy:8080']\n", o.Hostname)
	files := map[string][]byte{
		".env":                   []byte(fmt.Sprintf("PROXY_USERNAME=operator\nPROXY_TLS_SERVER_NAME=%s\nPROXY_BIND_IP=%s\n", o.Hostname, o.BindIP)),
		"secrets/proxy_password": []byte(password), "secrets/metrics_token": []byte(token), "secrets/alert_webhook": trimSecret(webhook),
		"tls/cert.pem": cert, "tls/key.pem": key, "tls/ca.pem": ca,
		"deploy/generated/prometheus.yml": []byte(prometheus), "deploy/generated/alertmanager.yml": []byte(alertConfig),
	}
	for name := range files {
		if _, e = os.Lstat(filepath.Join(o.Directory, name)); !os.IsNotExist(e) {
			return fmt.Errorf("refusing to replace existing file %s", name)
		}
	}
	for _, dir := range []string{"secrets", "tls", "deploy/generated"} {
		p := filepath.Join(o.Directory, dir)
		if info, err := os.Lstat(p); err == nil && info.Mode()&os.ModeSymlink != 0 {
			return errors.New("deployment directories must not be symlinks")
		}
		if e = os.MkdirAll(p, 0700); e != nil {
			return e
		}
		if e = os.Chmod(p, 0700); e != nil {
			return e
		}
	}
	for name, data := range files {
		mode := os.FileMode(0444)
		if name == ".env" {
			mode = 0600
		}
		if e = atomicFile(filepath.Join(o.Directory, name), data, mode); e != nil {
			return e
		}
	}
	return nil
}

func trimSecret(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\r' || b[len(b)-1] == '\n') {
		b = b[:len(b)-1]
	}
	return b
}

// RefreshTLS validates the complete new keypair before atomically replacing files.
// Recreate containers afterwards because local Compose secrets are file bind mounts.
func RefreshTLS(o InitOptions) error {
	cert, key, ca, e := importedTLS(o)
	if e != nil {
		return e
	}
	for name, b := range map[string][]byte{"cert.pem": cert, "key.pem": key, "ca.pem": ca} {
		if e = atomicFile(filepath.Join(o.Directory, "tls", name), b, 0444); e != nil {
			return e
		}
	}
	return nil
}

func Rotate(directory string) error {
	for _, name := range []string{"proxy_password", "metrics_token"} {
		if _, e := os.Stat(filepath.Join(directory, "secrets", name)); e != nil {
			return e
		}
	}
	for _, name := range []string{"proxy_password", "metrics_token"} {
		secret, e := randomSecret()
		if e != nil {
			return e
		}
		if e = atomicFile(filepath.Join(directory, "secrets", name), []byte(secret), 0444); e != nil {
			return e
		}
	}
	return nil
}
