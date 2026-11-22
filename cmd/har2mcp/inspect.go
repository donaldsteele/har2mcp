package main

import (
	"bufio"
	"bytes"
	"io"
	"os"

	"github.com/donaldsteele/har2mcp/internal/analyze"
	"github.com/donaldsteele/har2mcp/internal/har"
	"github.com/donaldsteele/har2mcp/internal/inspect"
	"github.com/donaldsteele/har2mcp/internal/spec"
)

// runInspect implements 'har2mcp inspect'.
func runInspect(args []string) error {
	return inspectTo(os.Stdout, args)
}

func inspectTo(stdout io.Writer, args []string) error {
	flags := newFlagSet("inspect")
	name := flags.String("name", "", "for a HAR: the service name to analyze it with")
	var hosts multiFlag
	flags.Var(&hosts, "host", "for a HAR: analyze requests to this host, as host or host:port; repeat for several")
	files, err := parseInterspersed(flags, args)
	if err != nil {
		return err
	}
	if len(files) != 1 {
		return usageErrorf("inspect needs exactly one file: a HAR or a spec")
	}
	path := files[0]
	opts := analyze.Options{Name: *name, Hosts: hosts}

	// A HAR is JSON and starts with "{". Checking that first avoids parsing
	// a large HAR as YAML before trying it as a HAR.
	isJSON, err := inspectLooksLikeJSON(path)
	if err != nil {
		return err
	}
	if isJSON {
		h, err := har.Load(path)
		if err == nil {
			return inspect.HAR(stdout, h, opts)
		}
		if s, serr := spec.Load(path); serr == nil {
			return inspect.Spec(stdout, s)
		}
		return err
	}
	s, err := spec.Load(path)
	if err == nil {
		return inspect.Spec(stdout, s)
	}
	if h, herr := har.Load(path); herr == nil {
		return inspect.HAR(stdout, h, opts)
	}
	return err
}

// inspectLooksLikeJSON reports whether a file's first non-space character,
// after any byte order mark, is "{".
func inspectLooksLikeJSON(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	head := make([]byte, 4096)
	n, err := io.ReadFull(bufio.NewReader(f), head)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return false, err
	}
	head = bytes.TrimPrefix(head[:n], []byte("\xef\xbb\xbf"))
	head = bytes.TrimLeft(head, " \t\r\n")
	return len(head) > 0 && head[0] == '{', nil
}
