package fakenas

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
)

// ScriptOptions configures Script.
type ScriptOptions struct {
	// UploadFile is the local file the "upload file" step uploads to
	// /public. Empty means a temporary hello.txt that contains "hi".
	UploadFile string
	// DeleteAndReboot adds two steps after the standard five: "delete
	// share", which deletes the share "media", and "reboot".
	DeleteAndReboot bool
}

// Script returns a function for record.Options.Script that drives this
// server's SPA the way a person would, naming each step in the recorder's
// overlay through window.__har2mcp:
//
//	login          types the credentials, clicks #login
//	list disks     clicks #btn-disks and waits for "sda" in #out
//	add share      types "media" in #share-name, clicks #btn-add-share
//	upload file    sets #upload-file, clicks #btn-upload (folder /public)
//	download file  clicks the a.download link of the uploaded file
//	delete share   (DeleteAndReboot) clicks .del-share[data-name="media"]
//	reboot         (DeleteAndReboot) clicks #btn-reboot
//
// Each step waits for its API call to answer and fails on an error answer.
// The function expects the recorder to have opened the server's URL; if the
// tab is elsewhere, it navigates there first.
func (s *Server) Script(o ScriptOptions) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		upload := o.UploadFile
		if upload == "" {
			dir, err := os.MkdirTemp("", "fakenas-upload-")
			if err != nil {
				return err
			}
			defer os.RemoveAll(dir)
			upload = filepath.Join(dir, "hello.txt")
			if err := os.WriteFile(upload, []byte("hi"), 0o600); err != nil {
				return err
			}
		}
		if abs, err := filepath.Abs(upload); err == nil {
			upload = abs
		}
		remote := "/public/" + filepath.Base(upload)

		loc, err := chromedp.Run(ctx, chromedp.Location())
		if err != nil {
			return err
		}
		if !strings.HasPrefix(loc, s.URL) {
			if err := chromedp.Do(ctx, chromedp.Navigate(s.URL)); err != nil {
				return err
			}
		}
		if err := chromedp.Do(ctx, chromedp.WaitVisible(chromedp.CSS("#username"))); err != nil {
			return fmt.Errorf("login form: %w", err)
		}

		steps := []scriptStep{
			{"login", func() error {
				if err := chromedp.Do(ctx,
					chromedp.SendKeys(chromedp.CSS("#username"), s.cfg.User),
					chromedp.SendKeys(chromedp.CSS("#password"), s.cfg.Password),
				); err != nil {
					return err
				}
				if err := ClickAndWait(ctx, "#login"); err != nil {
					return err
				}
				return chromedp.Do(ctx, chromedp.WaitVisible(chromedp.CSS("#btn-disks")))
			}},
			{"list disks", func() error {
				if err := ClickAndWait(ctx, "#btn-disks"); err != nil {
					return err
				}
				out, err := chromedp.Run(ctx, chromedp.TextContent(chromedp.CSS("#out")))
				if err == nil && !strings.Contains(out, "sda") {
					err = fmt.Errorf("#out has no disk sda: %s", out)
				}
				return err
			}},
			{"add share", func() error {
				if err := chromedp.Do(ctx, chromedp.SendKeys(chromedp.CSS("#share-name"), "media")); err != nil {
					return err
				}
				return ClickAndWait(ctx, "#btn-add-share")
			}},
			{"upload file", func() error {
				if err := chromedp.Do(ctx, chromedp.SetUploadFiles(chromedp.CSS("#upload-file"), []string{upload})); err != nil {
					return err
				}
				return ClickAndWait(ctx, "#btn-upload")
			}},
			{"download file", func() error {
				return ClickAndWait(ctx, `a.download[data-path="`+remote+`"]`)
			}},
		}
		if o.DeleteAndReboot {
			steps = append(steps,
				scriptStep{"delete share", func() error { return ClickAndWait(ctx, `.del-share[data-name="media"]`) }},
				scriptStep{"reboot", func() error { return ClickAndWait(ctx, "#btn-reboot") }},
			)
		}
		for _, st := range steps {
			if err := StartStep(ctx, st.label); err != nil {
				return err
			}
			if err := st.do(); err != nil {
				return fmt.Errorf("step %q: %w", st.label, err)
			}
			if err := EndStep(ctx); err != nil {
				return err
			}
		}
		return nil
	}
}

// scriptStep is one labeled step of Script.
type scriptStep struct {
	label string
	do    func() error
}

// StartStep starts a named step in the recorder overlay of the tab.
func StartStep(ctx context.Context, name string) error {
	b, _ := json.Marshal(name)
	return chromedp.Do(ctx, chromedp.Evaluate[chromedp.Void]("window.__har2mcp.startStep("+string(b)+")"))
}

// EndStep ends the running step in the recorder overlay of the tab.
func EndStep(ctx context.Context) error {
	return chromedp.Do(ctx, chromedp.Evaluate[chromedp.Void]("window.__har2mcp.endStep()"))
}

// ClickAndWait clicks the element sel finds and waits until the SPA shows
// the answer of the API call it makes in #out. It fails when the answer is
// an error.
func ClickAndWait(ctx context.Context, sel string) error {
	seq, err := chromedp.Run(ctx, chromedp.Evaluate[int](`+(document.querySelector('#out').dataset.seq || 0)`))
	if err != nil {
		return err
	}
	if err := chromedp.Do(ctx, chromedp.Click(chromedp.CSS(sel), chromedp.NodeVisible)); err != nil {
		return fmt.Errorf("click %s: %w", sel, err)
	}
	if err := chromedp.Do(ctx, chromedp.Poll[chromedp.Void](
		fmt.Sprintf(`+(document.querySelector('#out').dataset.seq || 0) > %d`, seq),
		chromedp.WithPollingInterval(25*time.Millisecond),
		chromedp.WithPollingTimeout(20*time.Second),
	)); err != nil {
		return fmt.Errorf("waiting for the answer to %s: %w", sel, err)
	}
	ok, err := chromedp.Run(ctx, chromedp.Evaluate[string](`document.querySelector('#out').dataset.ok`))
	if err != nil {
		return err
	}
	if ok != "true" {
		out, _ := chromedp.Run(ctx, chromedp.TextContent(chromedp.CSS("#out")))
		return fmt.Errorf("%s failed: %s", sel, out)
	}
	return nil
}
