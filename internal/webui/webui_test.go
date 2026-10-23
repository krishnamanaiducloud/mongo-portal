package webui

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServesIndexWithETagAndGzip(t *testing.T) {
	h := Handler()
	r := httptest.NewRequest("GET", "/db/app/orders", nil)
	r.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("index fallback: %d %s", w.Code, w.Header().Get("Content-Type"))
	}
	etag := w.Header().Get("ETag")
	if etag == "" {
		t.Fatal("missing ETag")
	}
	body := w.Body.Bytes()
	if w.Header().Get("Content-Encoding") == "gzip" {
		zr, err := gzip.NewReader(w.Body)
		if err != nil {
			t.Fatal(err)
		}
		body, _ = io.ReadAll(zr)
	}
	if !strings.Contains(string(body), "<html") {
		t.Fatal("index body")
	}
	r2 := httptest.NewRequest("GET", "/", nil)
	r2.Header.Set("If-None-Match", etag)
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, r2)
	if w2.Code != http.StatusNotModified {
		t.Fatalf("conditional request: %d", w2.Code)
	}
}

func TestSandboxCSP(t *testing.T) {
	for _, d := range []string{"sandbox allow-scripts", "connect-src 'none'", "frame-ancestors 'self'", "'unsafe-eval'"} {
		if !strings.Contains(SandboxCSP, d) {
			t.Errorf("sandbox CSP missing %q", d)
		}
	}
	if strings.Contains(SandboxCSP, "allow-same-origin") {
		t.Error("sandbox must not allow same origin")
	}
}
