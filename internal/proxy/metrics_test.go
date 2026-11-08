package proxy

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricsCredentialIsolation(t *testing.T) {
	p := newTestProxy(t)
	token := strings.Repeat("m", 64)
	if e := p.ConfigureMetrics(token, 123456, func() int { return 3 }); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		target, auth, proxyAuth string
		code                    int
	}{
		{"/metrics", "", authorization(), 401},
		{"/metrics", "Bearer wrong", "", 401},
		{"/metrics", "Bearer " + token, "", 200},
		{"http://example.com/", "Bearer " + token, "", 407},
	} {
		r := httptest.NewRequest("GET", tc.target, nil)
		r.Header.Set("Authorization", tc.auth)
		r.Header.Set("Proxy-Authorization", tc.proxyAuth)
		w := httptest.NewRecorder()
		p.ServeHTTP(w, r)
		if w.Code != tc.code {
			t.Fatalf("%s got %d want %d", tc.target, w.Code, tc.code)
		}
		if tc.code == 200 {
			b := w.Body.String()
			for _, expected := range []string{"proxy_open_connections 3", "proxy_tls_certificate_expiry_timestamp_seconds 123456", "proxy_capacity 128"} {
				if !strings.Contains(b, expected) {
					t.Error("missing metric", expected)
				}
			}
			if strings.Contains(b, token) || strings.Contains(b, "example.com") {
				t.Fatal("sensitive metric content")
			}
		}
	}
}
