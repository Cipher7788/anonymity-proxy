package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Cipher7788/anonymity-proxy/internal/ops"
)

func run() error {
	if len(os.Args) < 2 {
		return errors.New("usage: proxyctl init|tls|rotate|load [options]")
	}
	f := flag.NewFlagSet(os.Args[1], flag.ContinueOnError)
	switch os.Args[1] {
	case "rotate":
		directory := f.String("directory", ".", "deployment directory")
		if e := f.Parse(os.Args[2:]); e != nil {
			return e
		}
		return ops.Rotate(*directory)
	case "init", "tls":
		var o ops.InitOptions
		f.StringVar(&o.Directory, "directory", ".", "repository/deployment directory")
		f.StringVar(&o.Mode, "mode", "production", "production or development")
		f.StringVar(&o.Hostname, "hostname", "", "client-facing certificate hostname")
		f.StringVar(&o.BindIP, "bind", "127.0.0.1", "host bind IPv4")
		f.StringVar(&o.CertFile, "cert", "", "existing PEM certificate chain")
		f.StringVar(&o.KeyFile, "key", "", "existing PEM private key")
		f.StringVar(&o.CAFile, "ca", "", "trusted CA bundle; defaults to Linux system bundle")
		f.StringVar(&o.WebhookFile, "alert-webhook-file", "", "file containing HTTPS Alertmanager webhook URL")
		if e := f.Parse(os.Args[2:]); e != nil {
			return e
		}
		if os.Args[1] == "tls" {
			return ops.RefreshTLS(o)
		}
		return ops.Init(o)
	case "load":
		var o ops.LoadOptions
		address := f.String("proxy", "https://localhost:8080", "proxy URL without credentials")
		ca := f.String("ca", os.Getenv("PROXY_CA_FILE"), "CA bundle")
		output := f.String("output", "", "write aggregate JSON report")
		f.StringVar(&o.Target, "target", "", "controlled HTTP/HTTPS target")
		f.DurationVar(&o.Duration, "duration", 30*time.Second, "load duration, maximum 1h")
		f.IntVar(&o.Concurrency, "concurrency", 8, "workers, maximum 1024")
		f.Float64Var(&o.MaxErrorRate, "max-error-rate", .01, "allowed fraction of failed completed requests")
		f.DurationVar(&o.P95Limit, "p95-limit", 3*time.Second, "maximum p95 latency")
		if e := f.Parse(os.Args[2:]); e != nil {
			return e
		}
		password, e := ops.Secret("PROXY_PASSWORD")
		if e != nil {
			return e
		}
		if password == "" || os.Getenv("PROXY_USERNAME") == "" {
			return errors.New("PROXY_USERNAME and password secret are required")
		}
		c, e := ops.Client(*address, os.Getenv("PROXY_USERNAME"), password, *ca)
		if e != nil {
			return e
		}
		defer c.CloseIdleConnections()
		report, result := ops.Load(context.Background(), c, o)
		b, e := json.MarshalIndent(report, "", "  ")
		if e != nil {
			return e
		}
		if *output != "" {
			if e = os.WriteFile(*output, append(b, '\n'), 0600); e != nil {
				return e
			}
		}
		fmt.Println(string(b))
		return result
	default:
		return errors.New("unknown command")
	}
}

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "proxyctl:", e)
		os.Exit(1)
	}
}
