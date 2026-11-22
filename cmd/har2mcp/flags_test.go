package main

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/donaldsteele/har2mcp/internal/version"
)

func newTestFlags() (*flag.FlagSet, *string, *string, *bool, *multiFlag) {
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	o := fs.String("o", "", "output")
	name := fs.String("name", "", "name")
	dry := fs.Bool("dry-run", false, "dry run")
	var hosts multiFlag
	fs.Var(&hosts, "host", "host")
	return fs, o, name, dry, &hosts
}

func TestParseInterspersed(t *testing.T) {
	fs, o, name, _, _ := newTestFlags()
	pos, err := parseInterspersed(fs, []string{"a.har", "-o", "x", "b.har", "--name=tos"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(pos, []string{"a.har", "b.har"}) {
		t.Fatalf("positionals = %q", pos)
	}
	if *o != "x" || *name != "tos" {
		t.Fatalf("o=%q name=%q", *o, *name)
	}
}

func TestParseInterspersedDoubleDash(t *testing.T) {
	fs, o, _, dry, _ := newTestFlags()
	pos, err := parseInterspersed(fs, []string{"--dry-run", "a.har", "--", "-o", "--name=x"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(pos, []string{"a.har", "-o", "--name=x"}) {
		t.Fatalf("positionals = %q", pos)
	}
	if !*dry || *o != "" {
		t.Fatalf("dry=%v o=%q", *dry, *o)
	}
}

func TestParseInterspersedValues(t *testing.T) {
	fs, o, _, dry, hosts := newTestFlags()
	// A flag value that looks like "--" or a flag is still a value; bool flags
	// take no separate value; repeated flags accumulate; "-" is a positional.
	pos, err := parseInterspersed(fs, []string{"-o", "--", "-dry-run", "x.har", "--host", "a", "-host=b", "-"})
	if err != nil {
		t.Fatal(err)
	}
	if *o != "--" || !*dry {
		t.Fatalf("o=%q dry=%v", *o, *dry)
	}
	if !reflect.DeepEqual(pos, []string{"x.har", "-"}) {
		t.Fatalf("positionals = %q", pos)
	}
	if !reflect.DeepEqual([]string(*hosts), []string{"a", "b"}) {
		t.Fatalf("hosts = %q", *hosts)
	}
}

func TestParseInterspersedErrors(t *testing.T) {
	for _, args := range [][]string{
		{"a.har", "--bogus"},
		{"a.har", "-o"},
		{"--dry-run=maybe"},
	} {
		fs, _, _, _, _ := newTestFlags()
		_, err := parseInterspersed(fs, args)
		if err == nil {
			t.Errorf("%q: no error", args)
			continue
		}
		if !errors.Is(err, errUsage) {
			t.Errorf("%q: error %v does not wrap errUsage", args, err)
		}
	}
	fs, _, _, _, _ := newTestFlags()
	if _, err := parseInterspersed(fs, []string{"x", "-h"}); !errors.Is(err, flag.ErrHelp) {
		t.Errorf("-h: got %v, want flag.ErrHelp", err)
	}
}

func runCLI(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestRunVersion(t *testing.T) {
	for _, arg := range []string{"version", "--version", "-version"} {
		code, out, _ := runCLI(arg)
		if code != 0 || out != "har2mcp "+version.Version+"\n" {
			t.Errorf("%s: code %d, output %q", arg, code, out)
		}
	}
}

func TestRunUsage(t *testing.T) {
	code, _, errOut := runCLI()
	if code != 2 || !strings.Contains(errOut, "Usage:") {
		t.Errorf("no args: code %d, stderr %q", code, errOut)
	}
	code, out, _ := runCLI("help")
	if code != 0 || !strings.Contains(out, "har2mcp record") || !strings.Contains(out, "har2mcp generate") {
		t.Errorf("help: code %d, stdout %q", code, out)
	}
	code, _, errOut = runCLI("frobnicate")
	if code != 2 || !strings.Contains(errOut, `unknown command "frobnicate"`) {
		t.Errorf("unknown command: code %d, stderr %q", code, errOut)
	}
}

func TestRunExitCodes(t *testing.T) {
	saved := commands
	defer func() { commands = saved }()
	commands = map[string]command{
		"ok":    {run: func([]string) error { return nil }},
		"fail":  {run: func([]string) error { return errors.New("boom") }},
		"usage": {run: func([]string) error { return usageErrorf("needs a file") }},
		"wrap":  {run: func([]string) error { return errors.Join(errors.New("x"), errUsage) }},
		"help":  {run: func([]string) error { return flag.ErrHelp }},
	}
	for name, want := range map[string]int{"ok": 0, "fail": 1, "usage": 2, "wrap": 2, "help": 0} {
		code, _, errOut := runCLI(name)
		if code != want {
			t.Errorf("%s: exit %d, want %d (stderr %q)", name, code, want, errOut)
		}
	}
	_, _, errOut := runCLI("fail")
	if errOut != "har2mcp: boom\n" {
		t.Errorf("error output = %q", errOut)
	}
	_, _, errOut = runCLI("usage")
	if !strings.Contains(errOut, "needs a file") || !strings.Contains(errOut, "har2mcp usage -h") {
		t.Errorf("usage error output = %q", errOut)
	}
}

func TestStubsAreRegistered(t *testing.T) {
	for _, name := range []string{"record", "analyze", "inspect", "redact", "enhance", "generate"} {
		c, ok := commands[name]
		if !ok || c.run == nil || c.summary == "" || !strings.HasPrefix(c.usage, name) {
			t.Errorf("command %s is not registered with a summary and usage", name)
		}
	}
}
