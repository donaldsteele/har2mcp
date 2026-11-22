package analyze

import (
	"strings"

	"github.com/donaldsteele/har2mcp/internal/spec"
)

// Word stems that classify an operation. A word matches when it starts with
// a stem, so "delshare" and "getdisklist" count as well as "delete share".
var (
	destructiveStems = []string{"del", "remov", "reboot", "restart", "shutdown", "poweroff", "wipe", "eras", "destroy", "purg", "format", "reset", "factory", "uninstall", "kill", "unlink", "revoke"}
	destructiveWords = []string{"rm", "halt", "drop", "clear"}
	notDestructive   = []string{"delay", "deliver", "delta", "delegat", "formats", "formatted"}
	readStems        = []string{"get", "list", "query", "status", "show", "fetch", "read", "info", "view", "search", "find", "describe", "count", "stats", "statistic", "download", "export", "poll", "ping", "check", "lookup", "browse", "enum", "load"}
	changeStems      = []string{"add", "create", "set", "update", "save", "edit", "modify", "change", "enable", "disable", "start", "stop", "apply", "write", "upload", "rename", "move", "copy", "mount", "unmount", "install", "toggle", "mkdir", "insert", "assign", "logout", "login", "submit", "exec"}
)

// words splits a label, action name or path segment into lower-case words.
func words(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return strings.Split(spec.SanitizeName(s, 256), "_")
}

// hasStem reports whether a word starts with one of stems or equals one of
// exact, ignoring words that start with one of except.
func hasStem(ws []string, stems, exact, except []string) bool {
	for _, w := range ws {
		skip := false
		for _, e := range except {
			if strings.HasPrefix(w, e) {
				skip = true
			}
		}
		if skip {
			continue
		}
		for _, s := range stems {
			if strings.HasPrefix(w, s) {
				return true
			}
		}
		for _, e := range exact {
			if w == e {
				return true
			}
		}
	}
	return false
}

// classify returns read, change or destructive. label is the step label of
// the step this operation is the main request of, or "". The kind only
// feeds MCP annotations; it never switches a tool off.
//
//   - DELETE, or a destructive word (delete, remove, reboot, format, wipe,
//     ...) in the action name, last path segment or step label: destructive
//   - GET and HEAD: read, unless the action name, or a whole word of the
//     path, is a verb that changes something (set, add, create, ...)
//   - PUT, PATCH and uploads: change
//   - a read word (get, list, query, status, ...) in the action name or
//     path, or in the step label of a request with no verb of its own: read
//   - anything else: change
func classify(d *draft, label string) string {
	op := d.op
	var actWords []string
	for _, v := range op.discVals {
		actWords = append(actWords, words(v)...)
	}
	pathWords := words(lastStaticSegment(op.path))
	nameWords := append(append([]string(nil), actWords...), pathWords...)
	labelWords := words(label)

	if op.method == "DELETE" ||
		hasStem(nameWords, destructiveStems, destructiveWords, notDestructive) ||
		hasStem(labelWords, destructiveStems, destructiveWords, notDestructive) {
		return "destructive"
	}
	isRead := hasStem(nameWords, readStems, nil, nil)
	switch op.method {
	case "GET", "HEAD":
		changes := hasStem(actWords, changeStems, nil, nil) || hasStem(pathWords, nil, changeStems, nil)
		if changes && !isRead {
			return "change"
		}
		return "read"
	case "PUT", "PATCH":
		return "change"
	}
	if d.file == "upload" {
		return "change"
	}
	if isRead {
		return "read"
	}
	if !hasStem(nameWords, changeStems, nil, nil) && hasStem(labelWords, readStems, nil, nil) && !hasStem(labelWords, changeStems, nil, nil) {
		return "read"
	}
	return "change"
}

// lastStaticSegment is the last path segment that is not a placeholder.
func lastStaticSegment(path string) string {
	segs := strings.Split(path, "/")
	for i := len(segs) - 1; i >= 0; i-- {
		if s := segs[i]; s != "" && !strings.HasPrefix(s, "{") {
			return unescapeSeg(s)
		}
	}
	return ""
}
