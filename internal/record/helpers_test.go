package record

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNormalizeURL(t *testing.T) {
	good := map[string]string{
		"192.168.1.10":            "http://192.168.1.10",
		" nas.local:5000/tos ":    "http://nas.local:5000/tos",
		"https://nas.local":       "https://nas.local",
		"HTTP://Router.lan/admin": "http://Router.lan/admin",
		"http://[fe80::1]:8080/":  "http://[fe80::1]:8080/",
	}
	for in, want := range good {
		if got, err := NormalizeURL(in); err != nil || got != want {
			t.Errorf("NormalizeURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "   ", "ftp://nas.local", "http://", "http://:80/", "https://%zz"} {
		if got, err := NormalizeURL(in); err == nil {
			t.Errorf("NormalizeURL(%q) = %q, want an error", in, got)
		}
	}
}

func TestDefaultOutName(t *testing.T) {
	at := time.Date(2026, 11, 21, 14, 25, 1, 0, time.Local)
	for in, want := range map[string]string{
		"http://nas.local:5000/x": "nas.local-20261121-142501.har",
		"http://192.168.1.10":     "192.168.1.10-20261121-142501.har",
		"http://[fe80::1]:8080/":  "fe80--1-20261121-142501.har",
		"::bad":                   "session-20261121-142501.har",
	} {
		if got := DefaultOutName(in, at); got != want {
			t.Errorf("DefaultOutName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRunChecksOutDirFirst(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{
		filepath.Join(dir, "missing", "s.har"),
		filepath.Join(file, "s.har"),
		dir,
	} {
		// The browser path does not exist either; the output check comes
		// first, so nothing is started.
		_, err := Run(context.Background(), Options{URL: "http://127.0.0.1:1", Out: out, BrowserPath: filepath.Join(dir, "nope")})
		if err == nil || !strings.Contains(err.Error(), "cannot save") {
			t.Errorf("Out %q: err = %v", out, err)
		}
	}
	if err := checkOutDir(filepath.Join(dir, "ok.har")); err != nil {
		t.Errorf("a writable directory: %v", err)
	}
}
