// Package record drives a fresh Chrome, Chromium or Edge over the DevTools
// protocol and records what the user does as a HAR 1.2 file with har2mcp's
// extra fields.
//
// The browser runs with a throwaway profile, so the login is always
// recorded and the user's real profile is never touched. An overlay box
// injected into every page lets the user name each step ("list disks"); the
// requests made during a step get that name in _step, and the element
// clicked just before a request goes in _trigger. The login form's
// selectors and typed values go in log._har2mcp.login.
//
// A recording holds the user's password and session cookies, so it is saved
// with mode 0600.
package record

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
	"github.com/donaldsteele/har2mcp/internal/har"
	"github.com/donaldsteele/har2mcp/internal/version"
)

// DefaultBodyCap is the largest request or response body kept in a
// recording, in bytes. A larger body keeps its headers and size, but its
// text is dropped and content._truncated is set.
const DefaultBodyCap = 2097152

// drainTimeout is how long Run waits, after the recording ends, for
// requests in flight and response bodies being fetched.
const drainTimeout = 2 * time.Second

// testHookWaiting, when set by a test, runs in its own goroutine when Run
// starts waiting for the person to finish, with the first tab's context.
var testHookWaiting func(ctx context.Context)

// Options configures Run.
type Options struct {
	// URL is the page to open, such as http://192.168.1.10.
	URL string
	// Out is the file to save the HAR to. Empty means do not save.
	Out string
	// BrowserPath is the browser executable. Empty means FindBrowser.
	BrowserPath string
	// Insecure ignores TLS certificate errors (self-signed devices).
	Insecure bool
	// Headless runs the browser without a window (tests).
	Headless bool
	// BodyCap is the body size cap in bytes; 0 means DefaultBodyCap.
	BodyCap int64
	// Script, when set, drives the tab instead of a person: Run calls it
	// with the tab's chromedp context once the page has loaded, and the
	// recording ends when it returns. When nil, the recording ends when
	// the user closes the browser or ctx ends (Ctrl+C).
	Script func(ctx context.Context) error
}

// Run records a browser session and returns it as a HAR. When opts.Out is
// set, it also saves the HAR there (mode 0600) and prints a warning to
// stderr that the file holds secrets.
func Run(ctx context.Context, opts Options) (*har.HAR, error) {
	u, err := url.Parse(opts.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("record: %q is not an http:// or https:// URL", opts.URL)
	}
	if opts.Out != "" {
		if err := checkOutDir(opts.Out); err != nil {
			return nil, err
		}
	}
	bodyCap := opts.BodyCap
	if bodyCap <= 0 {
		bodyCap = DefaultBodyCap
	}
	browser := opts.BrowserPath
	if browser == "" {
		if browser, err = FindBrowser(); err != nil {
			return nil, err
		}
	} else if !fileExists(browser) {
		return nil, fmt.Errorf("record: browser %q not found", browser)
	}

	profile, err := os.MkdirTemp("", "har2mcp-profile-")
	if err != nil {
		return nil, fmt.Errorf("record: temporary profile: %w", err)
	}
	defer removeProfile(profile)

	r := newRecorder(bodyCap)

	// The browser outlives ctx on purpose: when ctx ends (Ctrl+C), Run still
	// collects the bodies in flight before it closes the browser.
	allocCtx, allocCancel := chromedp.NewExecAllocator(context.WithoutCancel(ctx),
		allocatorOptions(browser, profile, opts.Headless, opts.Insecure)...)
	defer waitAllocator(allocCtx, allocCancel)

	first := r.newTab()
	browserCtx, browserCancel := chromedp.NewContext(allocCtx,
		chromedp.WithListener(func(ev any) { r.onEvent(first, ev) }))
	defer browserCancel()

	if err := chromedp.Do(browserCtx, chromedp.Func(r.setupTab)); err != nil {
		return nil, startError(browser, err)
	}
	r.startTab(first, browserCtx)
	defer r.shutdown(browserCtx, allocCancel)
	firstID := chromedp.FromContext(browserCtx).Target.TargetID
	if err := chromedp.ListenBrowser(browserCtx, func(ev any) {
		e, ok := ev.(*target.EventTargetCreated)
		if !ok || e.TargetInfo == nil || e.TargetInfo.Type != "page" || e.TargetInfo.TargetID == firstID ||
			strings.HasPrefix(e.TargetInfo.URL, "devtools://") {
			return
		}
		r.tabOpening()
		go r.attachTab(browserCtx, e.TargetInfo.TargetID)
	}); err != nil {
		return nil, fmt.Errorf("record: %w", err)
	}

	// actx is the tab's context, ended by ctx too, for the actions Run and
	// Script run.
	actx, acancel := context.WithCancel(browserCtx)
	defer acancel()
	stop := context.AfterFunc(ctx, acancel)
	defer stop()

	if err := chromedp.Do(actx, chromedp.Navigate(opts.URL)); err != nil && ctx.Err() == nil {
		return nil, navError(opts.URL, err)
	}

	if opts.Script != nil {
		if err := opts.Script(actx); err != nil && ctx.Err() == nil {
			r.shutdown(browserCtx, allocCancel)
			return nil, fmt.Errorf("record: script: %w", err)
		}
	} else {
		exited := make(chan struct{})
		go func() {
			chromedp.WaitClosed(browserCtx)
			close(exited)
		}()
		if testHookWaiting != nil {
			go testHookWaiting(actx)
		}
		select {
		case <-ctx.Done():
		case <-r.allClosed:
		case <-exited:
		}
	}

	r.drain(drainTimeout)
	end := time.Now().UTC()
	r.shutdown(browserCtx, allocCancel)

	h := r.build(opts.URL, end)
	if opts.Out != "" {
		if err := har.Save(opts.Out, h); err != nil {
			return nil, fmt.Errorf("record: %w", err)
		}
		fmt.Fprintf(os.Stderr, "warning: %s contains your password and session cookies; keep it private (use 'har2mcp redact' before sharing)\n", opts.Out)
	}
	return h, nil
}

func startError(browser string, err error) error {
	if errors.Is(err, chromedp.ErrNoDisplay) {
		return errors.New("record: the browser window needs a desktop session, and neither DISPLAY nor WAYLAND_DISPLAY is set; run har2mcp record on a machine with a desktop (or over SSH with X forwarding)")
	}
	return fmt.Errorf("record: could not start %s: %w", browser, err)
}

func navError(u string, err error) error {
	msg := err.Error()
	if strings.Contains(msg, "ERR_CERT") || strings.Contains(msg, "ERR_SSL") {
		return fmt.Errorf("record: %s has a certificate the browser does not trust (%v); if it is your own device with a self-signed certificate, run again with --insecure", u, err)
	}
	return fmt.Errorf("record: could not open %s: %w", u, err)
}

// waitAllocator stops the browser process and waits, up to 10 seconds, for
// it to exit, so the profile is no longer in use when it is deleted.
func waitAllocator(allocCtx context.Context, allocCancel context.CancelFunc) {
	allocCancel()
	c := chromedp.FromContext(allocCtx)
	if c == nil || c.Allocator == nil {
		return
	}
	done := make(chan struct{})
	go func() {
		c.Allocator.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
	}
}

// removeProfile deletes the throwaway profile. Windows can hold its files
// for a moment after the browser exits, so it retries briefly.
func removeProfile(dir string) {
	for i := 0; i < 20; i++ {
		if err := os.RemoveAll(dir); err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// recorder holds the state of one recording. The DevTools listeners, the
// body workers and Run share it under mu.
type recorder struct {
	bodyCap int64

	mu        sync.Mutex
	steps     []har.Step
	active    int // index of the running step in steps, or -1
	stepCount int // requests started during the running step
	clicks    []click
	login     *har.LoginCapture

	reqs      []*reqRecord
	live      map[string]*reqRecord // the current hop of each request id
	hops      map[string]int
	reqExtra  map[string][]network.Headers
	respExtra map[string][]respExtra
	sockets   []*wsRecord
	liveWS    map[string]*wsRecord
	inflight  int // hops not finished
	jobs      int // body and post-data fetches queued or running

	tabs      []*tab
	openTabs  int
	allClosed chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup

	shutdownOnce sync.Once
}

func newRecorder(bodyCap int64) *recorder {
	return &recorder{
		bodyCap:   bodyCap,
		active:    -1,
		live:      map[string]*reqRecord{},
		hops:      map[string]int{},
		reqExtra:  map[string][]network.Headers{},
		respExtra: map[string][]respExtra{},
		liveWS:    map[string]*wsRecord{},
		allClosed: make(chan struct{}),
	}
}

// tab is one recorded browser tab.
type tab struct {
	r   *recorder
	idx int
	ctx context.Context // the tab's chromedp context, set by startTab

	qmu   sync.Mutex
	queue []job
	wake  chan struct{}
	dirty chan struct{}
}

type jobKind int

const (
	jobBody jobKind = iota
	jobPostData
)

// job is a DevTools command a listener cannot run itself, because a
// listener must not send commands.
type job struct {
	kind jobKind
	rr   *reqRecord
}

func (r *recorder) newTab() *tab {
	r.mu.Lock()
	defer r.mu.Unlock()
	t := &tab{r: r, idx: len(r.tabs), wake: make(chan struct{}, 1), dirty: make(chan struct{}, 1)}
	r.tabs = append(r.tabs, t)
	return t
}

func (t *tab) enqueue(j job) {
	t.qmu.Lock()
	t.queue = append(t.queue, j)
	t.qmu.Unlock()
	select {
	case t.wake <- struct{}{}:
	default:
	}
}

func (t *tab) markDirty() {
	select {
	case t.dirty <- struct{}{}:
	default:
	}
}

// notifyTabs asks every tab's overlay to refresh. r.mu is held.
func (r *recorder) notifyTabs() {
	for _, t := range r.tabs {
		t.markDirty()
	}
}

func ptr[T any](v T) *T { return &v }

// setupTab enables what a recording needs on a tab: network capture with
// buffers that fit the body cap, no cache and no service worker (so every
// request reaches the network and shows up), the binding and the overlay.
func (r *recorder) setupTab(ctx context.Context, t *chromedp.Target) error {
	resource := r.bodyCap + 1<<20
	total := max(int64(100<<20), 2*resource)
	if _, err := cdp.Call(ctx, t, network.Enable, network.EnableParams{
		MaxTotalBufferSize:    &total,
		MaxResourceBufferSize: &resource,
		MaxPostDataSize:       ptr(r.bodyCap + 1),
	}); err != nil {
		return err
	}
	if _, err := cdp.Call(ctx, t, network.SetCacheDisabled, network.SetCacheDisabledParams{CacheDisabled: true}); err != nil {
		return err
	}
	if _, err := cdp.Call(ctx, t, network.SetBypassServiceWorker, network.SetBypassServiceWorkerParams{Bypass: true}); err != nil {
		return err
	}
	if _, err := cdp.Call(ctx, t, runtime.AddBinding, runtime.AddBindingParams{Name: BindingName}); err != nil {
		return err
	}
	_, err := cdp.Call(ctx, t, page.AddScriptToEvaluateOnNewDocument, page.AddScriptToEvaluateOnNewDocumentParams{
		Source:         overlayJS,
		RunImmediately: ptr(true),
	})
	return err
}

// startTab starts the goroutines of a tab whose chromedp context is ready:
// the job worker, the overlay sync and the close watcher.
func (r *recorder) startTab(t *tab, ctx context.Context) {
	r.mu.Lock()
	t.ctx = ctx
	if t.idx == 0 {
		r.openTabs++
	}
	r.mu.Unlock()
	r.wg.Add(3)
	go func() { defer r.wg.Done(); t.work() }()
	go func() { defer r.wg.Done(); t.syncOverlay() }()
	go func() {
		defer r.wg.Done()
		if ch, err := chromedp.Detached(ctx); err == nil {
			select {
			case <-ch:
			case <-ctx.Done():
			}
		}
		r.tabClosed()
	}()
	t.markDirty()
}

// tabOpening counts a new tab before it is attached, so the recording does
// not end while a popup is still being set up.
func (r *recorder) tabOpening() {
	r.mu.Lock()
	r.openTabs++
	r.mu.Unlock()
}

func (r *recorder) tabClosed() {
	r.mu.Lock()
	r.openTabs--
	n := r.openTabs
	r.mu.Unlock()
	if n <= 0 {
		r.closeOnce.Do(func() { close(r.allClosed) })
	}
}

// attachTab records a tab the page or the user opened, such as a popup.
func (r *recorder) attachTab(parent context.Context, id target.ID) {
	t := r.newTab()
	tctx, cancel := chromedp.NewContext(parent,
		chromedp.WithTargetID(id),
		chromedp.WithListener(func(ev any) { r.onEvent(t, ev) }))
	if err := chromedp.Do(tctx, chromedp.Func(r.setupTab)); err != nil {
		cancel()
		r.tabClosed()
		return
	}
	r.startTab(t, tctx)
	r.notifyAll()
}

func (r *recorder) notifyAll() {
	r.mu.Lock()
	r.notifyTabs()
	r.mu.Unlock()
}

// work runs the tab's queued DevTools commands until the tab ends.
func (t *tab) work() {
	for {
		t.qmu.Lock()
		var j job
		ok := len(t.queue) > 0
		if ok {
			j = t.queue[0]
			t.queue = t.queue[1:]
		}
		t.qmu.Unlock()
		if !ok {
			select {
			case <-t.wake:
				continue
			case <-t.ctx.Done():
				t.dropQueue()
				return
			}
		}
		t.run(j)
	}
}

func (t *tab) dropQueue() {
	t.qmu.Lock()
	n := len(t.queue)
	t.queue = nil
	t.qmu.Unlock()
	t.r.mu.Lock()
	t.r.jobs -= n
	t.r.mu.Unlock()
}

func (t *tab) run(j job) {
	r := t.r
	switch j.kind {
	case jobBody:
		res, err := chromedp.Call(t.ctx, network.GetResponseBody, network.GetResponseBodyParams{RequestID: j.rr.id})
		r.mu.Lock()
		if err == nil {
			r.setBody(j.rr, res.Body)
		}
		r.jobs--
		r.mu.Unlock()
	case jobPostData:
		res, err := chromedp.Call(t.ctx, network.GetRequestPostData, network.GetRequestPostDataParams{RequestID: j.rr.id})
		r.mu.Lock()
		if err == nil {
			j.rr.postData = res.PostData
			j.rr.postOmitted = int64(len(res.PostData)) > r.bodyCap
		}
		r.jobs--
		r.mu.Unlock()
	}
}

// syncOverlay pushes the recorder's state to the tab's overlay box whenever
// it changes, at most five times a second.
func (t *tab) syncOverlay() {
	for {
		select {
		case <-t.ctx.Done():
			return
		case <-t.dirty:
		}
		t.r.mu.Lock()
		js := t.r.syncScript()
		t.r.mu.Unlock()
		chromedp.Call(t.ctx, runtime.Evaluate, runtime.EvaluateParams{Expression: js, Silent: ptr(true)})
		select {
		case <-t.ctx.Done():
			return
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// onEvent handles one DevTools event of tab t. It runs on the goroutine that
// reads the tab's messages, so it only updates state and queues work.
func (r *recorder) onEvent(t *tab, ev any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch e := ev.(type) {
	case *network.EventRequestWillBeSent:
		r.requestWillBeSent(t, e)
	case *network.EventRequestWillBeSentExtraInfo:
		k := reqKey(t, e.RequestID)
		r.reqExtra[k] = append(r.reqExtra[k], e.Headers)
	case *network.EventResponseReceived:
		r.responseReceived(t, e)
	case *network.EventResponseReceivedExtraInfo:
		k := reqKey(t, e.RequestID)
		r.respExtra[k] = append(r.respExtra[k], respExtra{headers: e.Headers, status: e.StatusCode, headersText: e.HeadersText})
	case *network.EventDataReceived:
		if rr := r.live[reqKey(t, e.RequestID)]; rr != nil {
			rr.dataLen += e.DataLength
		}
	case *network.EventLoadingFinished:
		r.loadingFinished(t, e)
	case *network.EventLoadingFailed:
		r.loadingFailed(t, e)
	case *network.EventWebSocketCreated:
		r.wsCreated(t, e)
	case *network.EventWebSocketWillSendHandshakeRequest:
		r.wsHandshake(t, e)
	case *network.EventWebSocketHandshakeResponseReceived:
		r.wsHandshakeResponse(t, e)
	case *network.EventWebSocketFrameSent:
		r.wsFrame(t, e.RequestID, float64(e.Timestamp), e.Response, "send")
	case *network.EventWebSocketFrameReceived:
		r.wsFrame(t, e.RequestID, float64(e.Timestamp), e.Response, "receive")
	case *network.EventWebSocketClosed:
		r.wsClosed(t, e)
	case *runtime.EventBindingCalled:
		if e.Name == BindingName {
			r.overlayEvent(t, e.Payload)
		}
	}
}

// drain waits up to timeout for requests in flight to finish and for the
// queued body fetches to complete.
func (r *recorder) drain(timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		idle := r.inflight <= 0 && r.jobs <= 0
		gone := r.openTabs <= 0
		jobs := r.jobs
		r.mu.Unlock()
		// With every tab gone no request can finish; only the queued
		// fetches (which then fail fast) are worth waiting for.
		if idle || (gone && jobs <= 0) {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// shutdown closes the browser and waits for the tab goroutines to stop. Only
// the first call does anything.
func (r *recorder) shutdown(browserCtx context.Context, allocCancel context.CancelFunc) {
	r.shutdownOnce.Do(func() {
		cctx, cancel := context.WithTimeout(browserCtx, 5*time.Second)
		chromedp.Cancel(cctx)
		cancel()
		allocCancel()
		done := make(chan struct{})
		go func() {
			r.wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	})
}

// checkOutDir fails early when the recording could not be saved, before
// the user spends time on a session.
func checkOutDir(out string) error {
	dir := filepath.Dir(out)
	st, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("record: cannot save to %s: %w", out, err)
	}
	if !st.IsDir() {
		return fmt.Errorf("record: cannot save to %s: %s is not a directory", out, dir)
	}
	if st, err := os.Stat(out); err == nil && st.IsDir() {
		return fmt.Errorf("record: cannot save to %s: it is a directory", out)
	}
	return nil
}

// NormalizeURL turns what a user typed into the URL to record: it adds
// http:// when there is no scheme ("192.168.1.10" or "nas.local:5000"), and
// rejects anything that is not an http or https URL with a host.
func NormalizeURL(arg string) (string, error) {
	s := strings.TrimSpace(arg)
	if s == "" {
		return "", errors.New("the URL is empty")
	}
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("%q is not a valid URL: %w", arg, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("%q is not an http:// or https:// URL", arg)
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("%q has no host name", arg)
	}
	return u.String(), nil
}

// DefaultOutName is the recording file name when none is given:
// <hostname>-<YYYYMMDD-HHMMSS>.har, for example nas.local-20261121-142501.har.
func DefaultOutName(rawURL string, t time.Time) string {
	host := "session"
	if u, err := url.Parse(rawURL); err == nil && u.Hostname() != "" {
		host = strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_' {
				return r
			}
			return '-'
		}, u.Hostname())
	}
	return host + "-" + t.Format("20060102-150405") + ".har"
}

// build assembles the HAR. A step still running ends at end.
func (r *recorder) build(startURL string, end time.Time) *har.HAR {
	r.mu.Lock()
	defer r.mu.Unlock()
	steps := make([]har.Step, len(r.steps))
	copy(steps, r.steps)
	if r.active >= 0 && steps[r.active].End.IsZero() {
		steps[r.active].End = end
	}
	var login *har.LoginCapture
	if r.login != nil {
		l := *r.login
		login = &l
	}
	return &har.HAR{Log: har.Log{
		Version: "1.2",
		Creator: har.Creator{Name: "har2mcp", Version: version.Version},
		Entries: r.buildEntries(steps),
		Har2mcp: &har.Meta{
			Version:  version.Version,
			StartURL: startURL,
			Steps:    steps,
			Login:    login,
		},
	}}
}
