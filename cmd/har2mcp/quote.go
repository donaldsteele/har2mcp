package main

import (
	"runtime"
	"strings"
)

// quoteArg quotes a path or value for a command line the user may copy and
// paste into their shell (see quoteArgFor).
func quoteArg(s string) string { return quoteArgFor(runtime.GOOS, s) }

// quoteArgFor quotes s for goos's usual shell when it needs it: double quotes
// on Windows, which both cmd.exe and PowerShell understand (cmd.exe keeps
// single quotes as part of the value), and single quotes elsewhere.
func quoteArgFor(goos, s string) string {
	if goos == "windows" {
		if s != "" && !strings.ContainsAny(s, " \t\"'&|<>^()%!;$`{}@#") {
			return s
		}
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	if s != "" && !strings.ContainsAny(s, " \t\"'$`\\!*?&;|<>()[]{}#~") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
