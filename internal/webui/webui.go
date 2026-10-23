// Package webui serves the compiled React application embedded in the
// binary. The dist directory is populated by the frontend build; a
// placeholder index.html keeps the package buildable without it.
package webui

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
	"sync"
)

//go:embed all:dist
var dist embed.FS

// SandboxCSP is the policy of the mongosh sandbox page. The page is always
// sandboxed (opaque origin: no cookies, no access to the portal page), may
// evaluate JavaScript (required by mongosh), and cannot make any network
// request: every database operation goes through the parent page broker.
// It may start one blob: worker (the mongosh runtime), which inherits this
// policy; the worker loads its code with importScripts from 'self'.
const SandboxCSP = "default-src 'none'; script-src 'self' 'unsafe-eval'; connect-src 'none'; img-src 'none'; " +
	"style-src 'none'; font-src 'none'; media-src 'none'; object-src 'none'; frame-src 'none'; worker-src blob:; " +
	"frame-ancestors 'self'; base-uri 'none'; form-action 'none'; sandbox allow-scripts"

const sandboxPage = "shell-sandbox.html"
const sandboxDir = "shell-sandbox/"

type asset struct {
	data  []byte
	gz    []byte
	etag  string
	ctype string
}

type server struct {
	root  fs.FS
	mu    sync.Mutex
	cache map[string]*asset
}

// Handler serves static assets with ETags and gzip, and falls back to
// index.html for client-side routes.
func Handler() http.Handler {
	root, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err)
	}
	return &server{root: root, cache: map[string]*asset{}}
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	if p == "" || p == "." {
		p = "index.html"
	}
	if st, err := fs.Stat(s.root, p); err != nil || st.IsDir() {
		p = "index.html"
	}
	a, err := s.load(p)
	if err != nil {
		http.Error(w, "UI not built", http.StatusNotFound)
		return
	}
	h := w.Header()
	switch {
	case strings.HasPrefix(p, "assets/"):
		// Vite emits content-hashed file names under assets/.
		h.Set("Cache-Control", "public, max-age=31536000, immutable")
	case p == sandboxPage:
		h.Set("Content-Security-Policy", SandboxCSP)
		h.Set("X-Frame-Options", "SAMEORIGIN")
		h.Set("Cache-Control", "no-cache")
	case strings.HasPrefix(p, sandboxDir):
		// Loaded by the opaque-origin sandbox frame, which is cross-origin.
		h.Set("Cross-Origin-Resource-Policy", "cross-origin")
		h.Set("Cache-Control", "no-cache")
	default:
		h.Set("Cache-Control", "no-cache")
	}
	h.Set("Content-Type", a.ctype)
	h.Set("ETag", a.etag)
	h.Add("Vary", "Accept-Encoding")
	if match := r.Header.Get("If-None-Match"); match != "" && match == a.etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	body := a.data
	if a.gz != nil && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		h.Set("Content-Encoding", "gzip")
		body = a.gz
	}
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body)
}

func (s *server) load(p string) (*asset, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.cache[p]; ok {
		return a, nil
	}
	data, err := fs.ReadFile(s.root, p)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	a := &asset{data: data, etag: `"` + hex.EncodeToString(sum[:16]) + `"`}
	a.ctype = mime.TypeByExtension(path.Ext(p))
	if a.ctype == "" {
		a.ctype = http.DetectContentType(data)
	}
	if strings.HasSuffix(p, ".html") {
		a.ctype = "text/html; charset=utf-8"
	}
	if compressible(a.ctype) && len(data) > 1024 {
		var buf bytes.Buffer
		zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
		_, _ = zw.Write(data)
		_ = zw.Close()
		if buf.Len() < len(data) {
			a.gz = buf.Bytes()
		}
	}
	s.cache[p] = a
	return a, nil
}

func compressible(ctype string) bool {
	for _, t := range []string{"text/", "javascript", "json", "svg", "css"} {
		if strings.Contains(ctype, t) {
			return true
		}
	}
	return false
}
