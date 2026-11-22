package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/donaldsteele/har2mcp/internal/record"
)

// runRecord implements 'har2mcp record'.
func runRecord(args []string) error {
	fs := newFlagSet("record")
	out := fs.String("o", "", "the HAR file to write (default <host>-<YYYYMMDD-HHMMSS>.har)")
	browser := fs.String("browser", "", "the Chrome, Chromium or Edge executable to use (default: found automatically)")
	insecure := fs.Bool("insecure", false, "accept self-signed and other invalid TLS certificates")
	bodyCap := fs.Int64("body-cap", record.DefaultBodyCap, "the largest request or response body to keep, in bytes")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageErrorf("record needs exactly one URL, such as http://192.168.1.10")
	}
	target, err := record.NormalizeURL(pos[0])
	if err != nil {
		return usageErrorf("record: %v", err)
	}
	if *bodyCap <= 0 {
		return usageErrorf("--body-cap must be a positive number of bytes")
	}
	if *out == "" {
		*out = record.DefaultOutName(target, time.Now())
	}

	// The first Ctrl+C ends the recording and saves it; after that the
	// default handling comes back, so a second one quits at once.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		stop()
	}()

	fmt.Println("Recording. Use the har2mcp box (bottom-right) to name each step. Close the browser window when done.")
	h, err := record.Run(ctx, record.Options{
		URL:         target,
		Out:         *out,
		BrowserPath: *browser,
		Insecure:    *insecure,
		BodyCap:     *bodyCap,
	})
	if err != nil {
		return err
	}
	steps := 0
	if h.Log.Har2mcp != nil {
		steps = len(h.Log.Har2mcp.Steps)
	}
	fmt.Printf("Saved %d requests in %d labeled steps to %s\n", len(h.Log.Entries), steps, *out)
	if steps == 0 {
		fmt.Println("No steps were labeled; analysis will name tools from the requests alone.")
	}
	fmt.Printf("Next: har2mcp analyze %s\n", shellQuote(*out))
	return nil
}

// shellQuote quotes a file name for a command line the user may copy.
func shellQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\"'$`\\!*?&;|<>()[]{}#~") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
