package fakenas

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	maxJSONBody   = 1 << 20  // 1 MiB
	maxUploadBody = 64 << 20 // 64 MiB
	nonceTTL      = 5 * time.Minute
	maxNonces     = 1000
)

// apiError is the JSON body of every failed API call.
type apiError struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(status)
	w.Write(b)
}

func fail(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, apiError{OK: false, Error: msg})
}

func allowMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method == method || (method == http.MethodGet && r.Method == http.MethodHead) {
		return true
	}
	w.Header().Set("Allow", method)
	fail(w, http.StatusMethodNotAllowed, "method not allowed")
	return false
}

func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet) {
		return
	}
	b, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	mode := "0"
	if s.cfg.Scramble {
		mode = "1"
	}
	html := strings.Replace(string(b), `data-scramble="0"`, `data-scramble="`+mode+`"`, 1)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.WriteString(w, html)
}

func (s *Server) handleNonce(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet) {
		return
	}
	n := randomHex(16)
	now := time.Now()
	s.mu.Lock()
	for k, exp := range s.nonces {
		if now.After(exp) || len(s.nonces) >= maxNonces {
			delete(s.nonces, k)
		}
	}
	s.nonces[n] = now.Add(nonceTTL)
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"nonce": n})
}

// scrambled is what the SPA sends as the password when Scramble is set.
func scrambled(password, nonce string) string {
	sum := sha256.Sum256([]byte(password + ":" + nonce))
	return hex.EncodeToString(sum[:])
}

func equal(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

// checkPassword reports whether pw is right. With Scramble it must be the
// scrambled password for an outstanding nonce, which is then used up.
func (s *Server) checkPassword(pw string) bool {
	if !s.cfg.Scramble {
		return equal(pw, s.cfg.Password)
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for n, exp := range s.nonces {
		if now.After(exp) {
			delete(s.nonces, n)
			continue
		}
		if equal(pw, scrambled(s.cfg.Password, n)) {
			delete(s.nonces, n)
			return true
		}
	}
	return false
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBody)).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	userOK := equal(req.Username, s.cfg.User)
	if !s.checkPassword(req.Password) || !userOK {
		fail(w, http.StatusUnauthorized, "bad credentials")
		return
	}
	id, token := randomHex(16), randomHex(16)
	s.mu.Lock()
	s.sessions[id] = token
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "NASSESSID", Value: id, Path: "/", HttpOnly: true})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "data": map[string]string{"token": token}})
}

// authorize applies the rules every authenticated endpoint shares: a live
// session cookie (else 401) and its CSRF token in X-Csrf-Token (else 403).
func (s *Server) authorize(w http.ResponseWriter, r *http.Request) bool {
	var token string
	ok := false
	if c, err := r.Cookie("NASSESSID"); err == nil {
		s.mu.Lock()
		token, ok = s.sessions[c.Value]
		s.mu.Unlock()
	}
	if !ok {
		fail(w, http.StatusUnauthorized, "not logged in")
		return false
	}
	if !equal(r.Header.Get("X-Csrf-Token"), token) {
		fail(w, http.StatusForbidden, "bad token")
		return false
	}
	return true
}

type disk struct {
	ID     string `json:"id"`
	Model  string `json:"model"`
	SizeGB int    `json:"size_gb"`
	Health string `json:"health"`
}

var disks = []disk{
	{ID: "sda", Model: "WD Red 4TB", SizeGB: 4000, Health: "good"},
	{ID: "sdb", Model: "WD Red 4TB", SizeGB: 4000, Health: "good"},
}

// validShareName allows 1 to 32 letters, digits, '.', '_' and '-', not
// starting with '.'.
func validShareName(name string) bool {
	if name == "" || len(name) > 32 || name[0] == '.' {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

func (s *Server) handleAct(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodPost) || !s.authorize(w, r) {
		return
	}
	var req map[string]any
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBody)).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	act, _ := req["act"].(string)
	ok := map[string]any{"ok": true}
	switch act {
	case "getdisklist":
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "data": disks})
	case "getsysinfo":
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "data": map[string]any{
			"model":    "F4-424",
			"version":  "TOS 6.0.1",
			"uptime_s": int(time.Since(s.started).Seconds()),
		}})
	case "getsharelist":
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "data": s.Shares()})
	case "addshare":
		name, _ := req["name"].(string)
		if !validShareName(name) {
			fail(w, http.StatusBadRequest, "bad share name")
			return
		}
		s.mu.Lock()
		exists := s.shares[name]
		s.shares[name] = true
		s.mu.Unlock()
		if exists {
			fail(w, http.StatusConflict, "share exists")
			return
		}
		writeJSON(w, http.StatusOK, ok)
	case "delshare":
		name, _ := req["name"].(string)
		s.mu.Lock()
		exists := s.shares[name]
		delete(s.shares, name)
		s.mu.Unlock()
		if !exists {
			fail(w, http.StatusNotFound, "no such share")
			return
		}
		writeJSON(w, http.StatusOK, ok)
	case "reboot":
		s.mu.Lock()
		s.rebooted = true
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, ok)
	default:
		fail(w, http.StatusBadRequest, "unknown act")
	}
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodPost) || !s.authorize(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBody)
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		fail(w, http.StatusBadRequest, "bad multipart form")
		return
	}
	defer r.MultipartForm.RemoveAll()
	folder := r.FormValue("path")
	if !strings.HasPrefix(folder, "/") {
		fail(w, http.StatusBadRequest, "path must be an absolute folder such as /public")
		return
	}
	folder = path.Clean(folder)
	f, hdr, err := r.FormFile("file")
	if err != nil {
		fail(w, http.StatusBadRequest, "no file part")
		return
	}
	defer f.Close()
	name := path.Base(strings.ReplaceAll(hdr.Filename, `\`, "/"))
	if name == "" || name == "." || name == "/" || name == ".." {
		fail(w, http.StatusBadRequest, "bad file name")
		return
	}
	data, err := io.ReadAll(f)
	if err != nil {
		fail(w, http.StatusBadRequest, "bad file part")
		return
	}
	s.PutFile(path.Join(folder, name), data)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

var quoteEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`)

func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet) || !s.authorize(w, r) {
		return
	}
	p := r.URL.Query().Get("path")
	s.mu.Lock()
	data, ok := s.files[p]
	if !ok && strings.HasPrefix(p, "/") {
		data, ok = s.files[path.Clean(p)]
	}
	data = slices.Clone(data)
	s.mu.Unlock()
	if !ok {
		fail(w, http.StatusNotFound, "no such file")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+quoteEscaper.Replace(path.Base(p))+`"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		w.Write(data)
	}
}
