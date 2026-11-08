package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Listen                string   `json:"listen"`
	TLSCert               string   `json:"tls_cert"`
	TLSKey                string   `json:"tls_key"`
	MaxConcurrent         int      `json:"max_concurrent"`
	RequestTimeoutSeconds int      `json:"request_timeout_seconds"`
	TunnelTimeoutSeconds  int      `json:"tunnel_timeout_seconds"`
	AllowedPorts          []string `json:"allowed_ports"`
}

func DefaultConfig() Config {
	return Config{Listen: "127.0.0.1:8080", MaxConcurrent: 128, RequestTimeoutSeconds: 60, TunnelTimeoutSeconds: 300, AllowedPorts: []string{"80", "443"}}
}

func LoadConfig(path string) (Config, error) {
	c := DefaultConfig()
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return c, err
		}
		defer f.Close()
		data, err := io.ReadAll(io.LimitReader(f, 65537))
		if err != nil {
			return c, err
		}
		if len(data) > 65536 {
			return c, errors.New("configuration exceeds 64 KiB")
		}
		data = bytes.TrimSpace(data)
		if len(data) == 0 || data[0] != '{' {
			return c, errors.New("configuration must be a JSON object")
		}
		d := json.NewDecoder(bytes.NewReader(data))
		d.DisallowUnknownFields()
		if err = d.Decode(&c); err != nil {
			return c, err
		}
		var extra any
		if err = d.Decode(&extra); err != io.EOF {
			return c, errors.New("configuration must contain one JSON object")
		}
	}
	return c, c.Validate()
}

func (c Config) Validate() error {
	host, port, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return errors.New("listen must be an IP:port address")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return errors.New("listen requires a literal IP")
	}
	n, e := strconv.Atoi(port)
	if e != nil || n < 1 || n > 65535 {
		return errors.New("invalid listen port")
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return errors.New("tls_cert and tls_key must be configured together")
	}
	if !ip.IsLoopback() && c.TLSCert == "" {
		return errors.New("non-loopback listeners require TLS")
	}
	if c.MaxConcurrent < 1 || c.MaxConcurrent > 10000 {
		return errors.New("max_concurrent must be between 1 and 10000")
	}
	if c.RequestTimeoutSeconds < 1 || c.RequestTimeoutSeconds > 3600 || c.TunnelTimeoutSeconds < 1 || c.TunnelTimeoutSeconds > 86400 {
		return errors.New("invalid timeout range")
	}
	if len(c.AllowedPorts) == 0 {
		return errors.New("allowed_ports cannot be empty")
	}
	for _, p := range c.AllowedPorts {
		n, e := strconv.Atoi(p)
		if e != nil || n < 1 || n > 65535 || strconv.Itoa(n) != p {
			return errors.New("allowed_ports requires canonical numeric ports")
		}
	}
	return nil
}

func (c Config) RequestTimeout() time.Duration {
	return time.Duration(c.RequestTimeoutSeconds) * time.Second
}
