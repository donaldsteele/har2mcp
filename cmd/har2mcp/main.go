// Command har2mcp records a labeled browser session against a device's web
// UI, analyzes it into an editable spec, and generates an MCP server from
// that spec.
//
// Exit codes: 0 success, 1 error, 2 usage error.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/donaldsteele/har2mcp/internal/version"
)

// command is one subcommand. usage is the synopsis after "har2mcp ".
type command struct {
	run     func(args []string) error
	summary string
	usage   string
}

// commandOrder is the order commands appear in the help text.
var commandOrder = []string{"record", "analyze", "inspect", "redact", "enhance", "generate"}

// commands is filled in init, because the run functions refer back to it
// (through newFlagSet) and a package-level initializer would be a cycle.
var commands map[string]command

func init() {
	commands = map[string]command{
		"record": {
			run:     runRecord,
			summary: "record a browser session you label step by step, to a HAR file",
			usage:   "record <url> [-o file.har] [--browser path] [--insecure] [--body-cap n]",
		},
		"analyze": {
			run:     runAnalyze,
			summary: "build or update an editable spec from HAR files",
			usage:   "analyze <file.har>... [-o service.spec.yaml] [--name n] [--host h]...",
		},
		"inspect": {
			run:     runInspect,
			summary: "print a redacted summary of a HAR or spec",
			usage:   "inspect <file.har|spec.yaml>",
		},
		"redact": {
			run:     runRedact,
			summary: "copy a HAR with passwords, cookies and tokens removed",
			usage:   "redact <in.har> -o <out.har>",
		},
		"enhance": {
			run:     runEnhance,
			summary: "optional: improve tool names and descriptions with Claude",
			usage:   "enhance <spec.yaml> [--model m] [--dry-run]",
		},
		"generate": {
			run:     runGenerate,
			summary: "generate MCP server source code from a spec",
			usage:   "generate <spec.yaml> [--target go] [-o dir] [--module path] [--no-tidy]",
		},
	}
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes the command line and returns the exit code.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}
	name, rest := args[0], args[1:]
	switch name {
	case "help", "-h", "-help", "--help":
		if len(rest) > 0 {
			if _, ok := commands[rest[0]]; ok {
				return run([]string{rest[0], "-h"}, stdout, stderr)
			}
			fmt.Fprintf(stderr, "har2mcp: unknown command %q\n\n", rest[0])
			printUsage(stderr)
			return 2
		}
		printUsage(stdout)
		return 0
	case "version", "-version", "--version":
		fmt.Fprintf(stdout, "har2mcp %s\n", version.Version)
		return 0
	}

	c, ok := commands[name]
	if !ok {
		fmt.Fprintf(stderr, "har2mcp: unknown command %q\n\n", name)
		printUsage(stderr)
		return 2
	}
	err := c.run(rest)
	switch {
	case err == nil:
		return 0
	case errors.Is(err, flag.ErrHelp):
		return 0
	case errors.Is(err, errUsage):
		fmt.Fprintf(stderr, "har2mcp: %v\nRun 'har2mcp %s -h' for usage.\n", err, name)
		return 2
	default:
		fmt.Fprintf(stderr, "har2mcp: %v\n", err)
		return 1
	}
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `har2mcp turns a recorded browser session with a device's web UI into an
MCP server, so Claude can control the device.

Usage:
  har2mcp <command> [arguments]

Commands:
`)
	for _, name := range commandOrder {
		fmt.Fprintf(w, "  %-9s %s\n", name, commands[name].summary)
	}
	fmt.Fprint(w, `  version   print the version
  help      show this help; 'har2mcp help <command>' shows a command's flags

Typical session:
  har2mcp record http://192.168.1.10 -o nas.har
  har2mcp analyze nas.har --name nas
  har2mcp generate nas.spec.yaml --target go

Run 'har2mcp <command> -h' for a command's flags.
Docs: https://github.com/donaldsteele/har2mcp
`)
}
