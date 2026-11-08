// Controlled upstream used only on the isolated container qualification network.
package main

import (
	"io"
	"net/http"
	"os"
	"time"
)

func main() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/slow":
			select {
			case <-time.After(10 * time.Second):
			case <-r.Context().Done():
				return
			}
		case "/reset":
			c, _, e := w.(http.Hijacker).Hijack()
			if e == nil {
				c.Close()
			}
			return
		case "/stream":
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: first\n\n")
			w.(http.Flusher).Flush()
			select {
			case <-time.After(10 * time.Second):
			case <-r.Context().Done():
				return
			}
			return
		}
		_, _ = io.WriteString(w, "fixture-ok")
	})
	errors := make(chan error, 2)
	go func() { errors <- http.ListenAndServe(":8081", handler) }()
	go func() {
		errors <- http.ListenAndServeTLS(":8443", "/run/secrets/proxy_tls_cert", "/run/secrets/proxy_tls_key", handler)
	}()
	if <-errors != nil {
		os.Exit(1)
	}
}
