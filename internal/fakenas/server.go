// Package fakenas is a simulated TOS-style NAS for tests. It serves a small
// single-page web UI and the RPC-style JSON API behind it:
//
//	GET  /                      the SPA (index.html, /static/app.js, style.css, logo.png)
//	GET  /api/nonce             {"nonce":"<hex>"}; the SPA uses it only when Scramble is set
//	POST /api/login             {"username","password"} -> {"ok":true,"data":{"token":"<csrf>"}}
//	                            plus Set-Cookie: NASSESSID=<id>; HttpOnly; Path=/
//	POST /api.php               {"act":...} with the X-Csrf-Token header and the session cookie
//	POST /api/upload            multipart: field "path" (folder), file part "file"
//	GET  /api/download?path=    the file as an attachment
//
// A missing or expired session gives 401 {"ok":false,"error":"not logged in"}
// and a wrong CSRF token gives 403 {"ok":false,"error":"bad token"}.
//
// The recorder, analyzer and end-to-end tests all run against this server, so
// its API and the SPA's element ids are a fixed contract.
package fakenas

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"io"
	"io/fs"
	"log"
	"maps"
	"net/http"
	"net/http/httptest"
	"path"
	"slices"
	"sync"
	"time"
)

// DefaultUser and DefaultPassword are the credentials when Config leaves them
// empty.
const (
	DefaultUser     = "admin"
	DefaultPassword = "hunter2-nas"
)

// Config configures a fake NAS.
type Config struct {
	// User and Password are the login credentials. They default to
	// DefaultUser and DefaultPassword.
	User, Password string
	// Scramble makes the SPA send sha256hex(password+":"+nonce) instead of
	// the password, with the nonce from GET /api/nonce. The server then
	// rejects the plain password, so a recording of it needs browser-mode
	// login.
	Scramble bool
	// TLS serves HTTPS with a self-signed certificate.
	TLS bool
}

// Server is a running fake NAS.
type Server struct {
	// URL is the base URL, such as http://127.0.0.1:41234 (no trailing slash).
	URL string

	cfg     Config
	ts      *httptest.Server
	started time.Time

	mu       sync.Mutex
	sessions map[string]string    // session id -> CSRF token
	nonces   map[string]time.Time // outstanding login nonce -> expiry
	shares   map[string]bool
	files    map[string][]byte // NAS path -> contents
	rebooted bool
}

//go:embed static
var staticFiles embed.FS

// Start starts a fake NAS on a loopback port. Call Close when done.
func Start(cfg Config) *Server {
	if cfg.User == "" {
		cfg.User = DefaultUser
	}
	if cfg.Password == "" {
		cfg.Password = DefaultPassword
	}
	s := &Server{
		cfg:      cfg,
		started:  time.Now(),
		sessions: map[string]string{},
		nonces:   map[string]time.Time{},
		shares:   map[string]bool{"public": true},
		files:    map[string][]byte{},
	}
	s.ts = httptest.NewUnstartedServer(s.handler())
	// A browser that rejects the self-signed certificate is an expected
	// test case, not something to log.
	s.ts.Config.ErrorLog = log.New(io.Discard, "", 0)
	if cfg.TLS {
		s.ts.StartTLS()
	} else {
		s.ts.Start()
	}
	s.URL = s.ts.URL
	return s
}

// Close stops the server.
func (s *Server) Close() { s.ts.Close() }

// Shares returns the share names, sorted.
func (s *Server) Shares() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Sorted(maps.Keys(s.shares))
}

// Files returns a copy of the stored files, keyed by NAS path such as
// "/public/hello.txt".
func (s *Server) Files() map[string][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string][]byte, len(s.files))
	for k, v := range s.files {
		out[k] = slices.Clone(v)
	}
	return out
}

// PutFile stores a file at a NAS path such as "/public/b.bin".
func (s *Server) PutFile(path string, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.files[path] = slices.Clone(data)
}

// ExpireSessions invalidates every session, as if the NAS timed them out.
func (s *Server) ExpireSessions() {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.sessions)
}

// Rebooted reports whether the reboot act was called.
func (s *Server) Rebooted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rebooted
}

// staticContentTypes pins the types of the SPA's assets. The file server
// would otherwise ask the OS: Windows reports .js as application/javascript
// (or whatever the registry says), so recordings would differ by platform.
var staticContentTypes = map[string]string{
	".js":  "text/javascript; charset=utf-8",
	".css": "text/css; charset=utf-8",
	".png": "image/png",
}

// staticTypes sets Content-Type from staticContentTypes before the file
// server runs; http.ServeContent keeps a type that is already set.
func staticTypes(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct, ok := staticContentTypes[path.Ext(r.URL.Path)]; ok {
			w.Header().Set("Content-Type", ct)
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handler() http.Handler {
	static, err := fs.Sub(staticFiles, "static")
	if err != nil {
		panic(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/{$}", s.serveIndex)
	mux.Handle("GET /static/", staticTypes(http.StripPrefix("/static/", http.FileServerFS(static))))
	mux.HandleFunc("/api/nonce", s.handleNonce)
	mux.HandleFunc("/api/login", s.handleLogin)
	mux.HandleFunc("/api.php", s.handleAct)
	mux.HandleFunc("/api/upload", s.handleUpload)
	mux.HandleFunc("/api/download", s.handleDownload)
	return noStore(mux)
}

// noStore turns off caching, so every recording sees real requests.
func noStore(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	})
}

// randomHex returns n random bytes as hex.
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
