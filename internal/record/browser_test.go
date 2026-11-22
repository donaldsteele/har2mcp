package record

import (
	"errors"
	"testing"
)

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func existsIn(paths ...string) func(string) bool {
	return func(p string) bool {
		for _, q := range paths {
			if p == q {
				return true
			}
		}
		return false
	}
}

func lookIn(found map[string]string) func(string) (string, error) {
	return func(name string) (string, error) {
		if p, ok := found[name]; ok {
			return p, nil
		}
		return "", errors.New("not found")
	}
}

func TestFindBrowser(t *testing.T) {
	const (
		winChrome = `C:\Users\u\AppData\Local\Google\Chrome\Application\chrome.exe`
		winEdge   = `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`
		macChrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
		macHomeCr = "/Users/u/Applications/Chromium.app/Contents/MacOS/Chromium"
		macEdge   = "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"
	)
	winEnv := envMap(map[string]string{
		"ProgramFiles":      `C:\Program Files`,
		"ProgramFiles(x86)": `C:\Program Files (x86)`,
		"LocalAppData":      `C:\Users\u\AppData\Local`,
	})
	macEnv := envMap(map[string]string{"HOME": "/Users/u"})
	none := lookIn(nil)

	tests := []struct {
		name   string
		goos   string
		env    func(string) string
		exists func(string) bool
		look   func(string) (string, error)
		want   string
	}{
		{"linux chrome first", "linux", envMap(nil), existsIn("/usr/bin/chromium", "/usr/bin/google-chrome", "/opt/microsoft/msedge/msedge"), none, "/usr/bin/google-chrome"},
		{"linux chromium before edge", "linux", envMap(nil), existsIn("/opt/microsoft/msedge/msedge", "/snap/bin/chromium"), none, "/snap/bin/chromium"},
		{"linux edge", "linux", envMap(nil), existsIn("/opt/microsoft/msedge/msedge"), none, "/opt/microsoft/msedge/msedge"},
		{"linux PATH", "linux", envMap(nil), existsIn(), lookIn(map[string]string{"chromium-browser": "/usr/local/bin/chromium-browser"}), "/usr/local/bin/chromium-browser"},
		{"windows edge only", "windows", winEnv, existsIn(winEdge), none, winEdge},
		{"windows chrome before edge", "windows", winEnv, existsIn(winEdge, winChrome), none, winChrome},
		{"windows PATH", "windows", winEnv, existsIn(), lookIn(map[string]string{"msedge.exe": `C:\x\msedge.exe`}), `C:\x\msedge.exe`},
		{"mac chrome", "darwin", macEnv, existsIn(macEdge, macHomeCr, macChrome), none, macChrome},
		{"mac per-user chromium", "darwin", macEnv, existsIn(macEdge, macHomeCr), none, macHomeCr},
		{"mac edge", "darwin", macEnv, existsIn(macEdge), none, macEdge},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := findBrowser(tc.goos, tc.env, tc.exists, tc.look)
			if err != nil || got != tc.want {
				t.Errorf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}

	for _, goos := range []string{"linux", "windows", "darwin", "freebsd"} {
		if _, err := findBrowser(goos, envMap(nil), existsIn(), none); !errors.Is(err, ErrNoBrowser) {
			t.Errorf("%s with nothing installed: err = %v", goos, err)
		}
	}
}

func TestBrowserCandidatesSkipMissingEnv(t *testing.T) {
	paths, _ := browserCandidates("windows", envMap(map[string]string{"LocalAppData": `C:\L`}))
	for _, p := range paths {
		if p[0] == '\\' {
			t.Errorf("candidate %q built from an empty variable", p)
		}
	}
	if len(paths) != 3 {
		t.Errorf("paths = %q", paths)
	}
}

func TestAllocatorOptionsCount(t *testing.T) {
	// Visible and headless differ by one option; insecure adds one more.
	h := len(allocatorOptions("/b", "/p", true, false))
	v := len(allocatorOptions("/b", "/p", false, false))
	i := len(allocatorOptions("/b", "/p", true, true))
	if h != v || i != h+1 {
		t.Errorf("option counts headless %d visible %d insecure %d", h, v, i)
	}
}
