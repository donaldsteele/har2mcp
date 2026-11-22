package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
)

// errUsage marks errors caused by how the command was called. main prints
// them with a hint and exits 2. Return usageErrorf(...) or wrap errUsage
// with %w.
var errUsage = errors.New("usage error")

type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }
func (e *usageError) Unwrap() error { return errUsage }

// usageErrorf returns an error that wraps errUsage with the given message.
func usageErrorf(format string, a ...any) error {
	return &usageError{msg: fmt.Sprintf(format, a...)}
}

// newFlagSet returns a FlagSet for a subcommand. Its -h output shows the
// command's usage line and summary from the commands table, then the flags.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() {
		out := fs.Output()
		if c, ok := commands[name]; ok {
			fmt.Fprintf(out, "Usage: har2mcp %s\n\n%s.\n", c.usage, capitalize(c.summary))
		} else {
			fmt.Fprintf(out, "Usage: har2mcp %s [flags]\n", name)
		}
		hasFlags := false
		fs.VisitAll(func(*flag.Flag) { hasFlags = true })
		if hasFlags {
			fmt.Fprintln(out, "\nFlags:")
			fs.PrintDefaults()
		}
	}
	return fs
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// multiFlag is a string flag that may be repeated: --host a --host b.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

// parseInterspersed parses args with fs, allowing flags before, between and
// after positional arguments, and returns the positionals in order. "--"
// ends flag parsing: everything after it is positional. A non-boolean flag
// written without "=" takes the next argument as its value, even if that
// looks like a flag.
//
// A bad flag returns an error wrapping errUsage. -h or --help prints the
// usage to fs.Output() and returns flag.ErrHelp.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var flagArgs, positionals []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}
		if len(a) < 2 || a[0] != '-' {
			positionals = append(positionals, a)
			continue
		}
		flagArgs = append(flagArgs, a)
		name := strings.TrimPrefix(a[1:], "-")
		if strings.Contains(name, "=") {
			continue
		}
		f := fs.Lookup(name)
		if f == nil || isBoolFlag(f) {
			continue
		}
		if i+1 < len(args) {
			flagArgs = append(flagArgs, args[i+1])
			i++
		}
	}

	out := fs.Output()
	fs.SetOutput(io.Discard)
	err := fs.Parse(flagArgs)
	fs.SetOutput(out)
	if errors.Is(err, flag.ErrHelp) {
		if fs.Usage != nil {
			fs.Usage()
		} else {
			fmt.Fprintf(out, "Usage of %s:\n", fs.Name())
			fs.PrintDefaults()
		}
		return nil, flag.ErrHelp
	}
	if err != nil {
		return nil, &usageError{msg: err.Error()}
	}
	return append(positionals, fs.Args()...), nil
}

func isBoolFlag(f *flag.Flag) bool {
	b, ok := f.Value.(interface{ IsBoolFlag() bool })
	return ok && b.IsBoolFlag()
}
