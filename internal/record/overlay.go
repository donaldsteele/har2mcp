package record

import (
	_ "embed"
	"encoding/json"
	"net/url"
	"time"

	"github.com/donaldsteele/har2mcp/internal/har"
)

// BindingName is the DevTools binding the overlay script reports through.
const BindingName = "__har2mcpEmit"

// overlayJS is injected into every document of a recorded tab.
//
//go:embed overlay.js
var overlayJS string

// overlayEvent is one message from the overlay script. Which fields are set
// depends on Type; see overlay.js.
type overlayEvent struct {
	Type string  `json:"type"`
	T    float64 `json:"t"` // milliseconds since the epoch, from the page

	Name string `json:"name"` // step_start: the step; input: the field's name attribute

	// click
	Text      string `json:"text"`
	AriaLabel string `json:"ariaLabel"`
	Role      string `json:"role"`
	Selector  string `json:"selector"`

	// input
	Label     string `json:"label"`
	InputType string `json:"inputType"`
	Value     string `json:"value"`

	// login_submit
	UsernameSelector string `json:"usernameSelector"`
	PasswordSelector string `json:"passwordSelector"`
	SubmitSelector   string `json:"submitSelector"`
	Username         string `json:"username"`
	Password         string `json:"password"`
	PageURL          string `json:"pageUrl"`
}

// click is a click the overlay saw, kept to set _trigger.
type click struct {
	at      time.Time
	trigger har.Trigger
}

// eventTime is the page's timestamp of an event. The page clock and Chrome's
// request times both read the system clock, and the page stamps a click
// before the page's handler sends its request, so ordering by these times is
// reliable. A missing or absurd timestamp falls back to now.
func eventTime(ms float64, now time.Time) time.Time {
	now = now.UTC()
	if ms <= 0 {
		return now
	}
	t := time.UnixMilli(int64(ms)).UTC()
	if d := now.Sub(t); d > time.Hour || d < -time.Hour {
		return now
	}
	return t
}

// overlayEvent handles one binding call from tab t. r.mu is held.
func (r *recorder) overlayEvent(t *tab, payload string) {
	var ev overlayEvent
	if err := json.Unmarshal([]byte(payload), &ev); err != nil {
		return
	}
	at := eventTime(ev.T, time.Now())
	switch ev.Type {
	case "step_start":
		r.closeStep(at)
		r.steps = append(r.steps, har.Step{Name: ev.Name, Start: at})
		r.active = len(r.steps) - 1
		r.stepCount = 0
		r.notifyTabs()
	case "step_end":
		if r.active >= 0 {
			r.closeStep(at)
			r.notifyTabs()
		}
	case "click":
		r.clicks = append(r.clicks, click{at: at, trigger: har.Trigger{
			Text: ev.Text, AriaLabel: ev.AriaLabel, Role: ev.Role, Selector: ev.Selector,
		}})
	case "input":
		if r.active < 0 {
			return
		}
		in := har.TypedInput{Label: ev.Label, Name: ev.Name, Selector: ev.Selector, Type: ev.InputType, Value: ev.Value}
		s := &r.steps[r.active]
		for i := range s.Inputs {
			old := s.Inputs[i]
			if old.Selector == in.Selector && old.Name == in.Name && old.Label == in.Label {
				s.Inputs[i] = in
				return
			}
		}
		s.Inputs = append(s.Inputs, in)
	case "login_submit":
		// The first login form counts. A later submit replaces it only when
		// it is the same form again (a retry after a typo); a different
		// form with one password field, such as "add user", does not.
		if ev.Password == "" || (r.login != nil &&
			(r.login.PasswordSelector != ev.PasswordSelector || !samePage(r.login.PageURL, ev.PageURL))) {
			return
		}
		r.login = &har.LoginCapture{
			PageURL:          ev.PageURL,
			UsernameSelector: ev.UsernameSelector,
			PasswordSelector: ev.PasswordSelector,
			SubmitSelector:   ev.SubmitSelector,
			Username:         ev.Username,
			Password:         ev.Password,
		}
	case "hello":
		t.markDirty()
	}
}

// samePage reports whether two page URLs differ at most in their query and
// fragment.
func samePage(a, b string) bool {
	ua, errA := url.Parse(a)
	ub, errB := url.Parse(b)
	if errA != nil || errB != nil {
		return a == b
	}
	return ua.Scheme == ub.Scheme && ua.Host == ub.Host && ua.Path == ub.Path
}

// closeStep ends the running step, if any, at time at. r.mu is held.
func (r *recorder) closeStep(at time.Time) {
	if r.active < 0 {
		return
	}
	s := &r.steps[r.active]
	if at.Before(s.Start) {
		at = s.Start
	}
	s.End = at
	r.active = -1
}

// overlayState is what the recorder pushes to the overlay boxes, so every
// tab and every new document shows the running step and its request count.
type overlayState struct {
	Step  *string `json:"step"`
	Count int     `json:"count"`
	Steps int     `json:"steps"`
}

// syncScript returns the JavaScript that updates an overlay box. r.mu is
// held.
func (r *recorder) syncScript() string {
	st := overlayState{Count: r.stepCount, Steps: len(r.steps)}
	if r.active >= 0 {
		name := r.steps[r.active].Name
		st.Step = &name
	}
	b, _ := json.Marshal(st)
	return "window.__har2mcp && window.__har2mcp._sync(" + string(b) + ")"
}
