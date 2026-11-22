package main

import (
	"fmt"
	"io"
	"os"

	"github.com/donaldsteele/har2mcp/internal/har"
)

// runRedact implements 'har2mcp redact'.
func runRedact(args []string) error {
	return redactTo(os.Stdout, args)
}

func redactTo(stdout io.Writer, args []string) error {
	flags := newFlagSet("redact")
	out := flags.String("o", "", "where to write the redacted HAR (required; never the input file)")
	files, err := parseInterspersed(flags, args)
	if err != nil {
		return err
	}
	if len(files) != 1 {
		return usageErrorf("redact needs one input HAR file")
	}
	in := files[0]
	if *out == "" {
		return usageErrorf("redact needs -o <out.har>; it never overwrites the input")
	}
	if redactSameFile(in, *out) {
		return usageErrorf("-o %s is the input file; choose another name so the original recording is kept", *out)
	}
	h, err := har.Load(in)
	if err != nil {
		return err
	}
	if err := har.Save(*out, har.Redact(h)); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Wrote %s with passwords, cookies and tokens replaced by %s.\n", *out, har.Redacted)
	fmt.Fprintln(stdout, "Look through it before sharing: request and response bodies can still hold other personal data, such as file and share names.")
	return nil
}

// redactSameFile reports whether out already exists and is the same file as
// in (also through a link or a different spelling of the path).
func redactSameFile(in, out string) bool {
	fi, err := os.Stat(in)
	if err != nil {
		return false
	}
	fo, err := os.Stat(out)
	if err != nil {
		return false
	}
	return os.SameFile(fi, fo)
}
