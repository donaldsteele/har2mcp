package record

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/chromedp/chromedp"
)

// ErrNoBrowser is returned by FindBrowser when no supported browser is
// installed.
var ErrNoBrowser = errors.New("no Chrome, Chromium or Edge found; install one or pass --browser <path>")

// FindBrowser returns the path of an installed Chrome, Chromium or Edge, in
// that order of preference. It looks in each OS's usual install locations
// and then on PATH.
func FindBrowser() (string, error) {
	return findBrowser(runtime.GOOS, os.Getenv, fileExists, exec.LookPath)
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// browserCandidates lists absolute install paths and PATH names to try, in
// order, for an OS. env reads environment variables.
func browserCandidates(goos string, env func(string) string) (paths, names []string) {
	switch goos {
	case "windows":
		var roots []string
		for _, v := range []string{"ProgramFiles", "ProgramFiles(x86)", "LocalAppData", "ProgramW6432"} {
			if r := env(v); r != "" {
				roots = append(roots, r)
			}
		}
		for _, rel := range []string{
			`Google\Chrome\Application\chrome.exe`,
			`Chromium\Application\chrome.exe`,
			`Microsoft\Edge\Application\msedge.exe`,
		} {
			for _, r := range roots {
				paths = append(paths, r+`\`+rel)
			}
		}
		names = []string{"chrome.exe", "chromium.exe", "msedge.exe"}
	case "darwin":
		var homes []string
		homes = append(homes, "")
		if h := env("HOME"); h != "" {
			homes = append(homes, h)
		}
		for _, app := range []string{
			"Google Chrome.app/Contents/MacOS/Google Chrome",
			"Chromium.app/Contents/MacOS/Chromium",
			"Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
		} {
			for _, h := range homes {
				paths = append(paths, h+"/Applications/"+app)
			}
		}
		names = []string{"google-chrome", "chromium", "microsoft-edge"}
	default: // linux and the BSDs
		paths = []string{
			"/usr/bin/google-chrome",
			"/usr/bin/google-chrome-stable",
			"/opt/google/chrome/chrome",
			"/usr/bin/chromium",
			"/usr/bin/chromium-browser",
			"/snap/bin/chromium",
			"/usr/local/bin/chromium",
			"/usr/bin/microsoft-edge",
			"/usr/bin/microsoft-edge-stable",
			"/opt/microsoft/msedge/msedge",
		}
		names = []string{
			"google-chrome", "google-chrome-stable", "chrome",
			"chromium", "chromium-browser",
			"microsoft-edge", "microsoft-edge-stable", "msedge",
		}
	}
	return paths, names
}

func findBrowser(goos string, env func(string) string, exists func(string) bool, lookPath func(string) (string, error)) (string, error) {
	paths, names := browserCandidates(goos, env)
	for _, p := range paths {
		if exists(p) {
			return p, nil
		}
	}
	for _, n := range names {
		if p, err := lookPath(n); err == nil && p != "" {
			// Only resolve relative paths for the OS we run on: filepath.Abs
			// uses the host's rules, and a path found for another goos (in
			// tests) must come back unchanged.
			if goos == runtime.GOOS && !filepath.IsAbs(p) {
				if abs, err := filepath.Abs(p); err == nil {
					p = abs
				}
			}
			return p, nil
		}
	}
	return "", ErrNoBrowser
}

// allocatorOptions returns the chromedp options for a recording browser: the
// given executable, a throwaway profile, no first-run or default-browser
// prompts, a visible window unless headless, and certificate errors ignored
// when insecure.
func allocatorOptions(browser, profile string, headless, insecure bool) []chromedp.ExecAllocatorOption {
	opts := append([]chromedp.ExecAllocatorOption{}, chromedp.DefaultExecAllocatorOptions[:]...)
	opts = append(opts,
		chromedp.ExecPath(browser),
		chromedp.UserDataDir(profile),
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		// No "save your password?" bubble in the middle of a recording.
		chromedp.Flag("disable-features", "Translate,BlinkGenPropertyTrees,PasswordManagerOnboarding,PasswordLeakDetection"),
		chromedp.Flag("password-store", "basic"),
		chromedp.Flag("use-mock-keychain", true),
	)
	if headless {
		opts = append(opts, chromedp.WindowSize(1280, 900))
	} else {
		opts = append(opts, chromedp.VisibleWindow)
	}
	if insecure {
		opts = append(opts, chromedp.IgnoreCertErrors)
	}
	// Chrome refuses to start its sandbox as root, which is common in
	// containers and CI.
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		opts = append(opts, chromedp.NoSandbox)
	}
	return opts
}
