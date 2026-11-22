package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"

	"github.com/donaldsteele/har2mcp/internal/enhance"
	"github.com/donaldsteele/har2mcp/internal/spec"
)

// runEnhance implements 'har2mcp enhance'.
func runEnhance(args []string) error {
	fs := newFlagSet("enhance")
	model := fs.String("model", enhance.DefaultModel, "Claude model to use")
	dryRun := fs.Bool("dry-run", false, "print exactly what would be sent to Claude, and send nothing")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageErrorf("enhance takes one spec file, got %d arguments", len(pos))
	}
	path := pos[0]
	s, err := spec.Load(path)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if *dryRun {
		return enhance.Enhance(ctx, s, nil, enhance.Options{Model: *model, DryRun: true, Out: os.Stdout})
	}
	key := os.Getenv("ANTHROPIC_API_KEY")
	if key == "" {
		return errors.New("ANTHROPIC_API_KEY is not set. enhance sends tool names, request shapes and redacted response examples to the Claude API; create an API key in the Claude Console and export it as ANTHROPIC_API_KEY, or run with --dry-run to see what would be sent")
	}
	fmt.Fprintf(os.Stderr, "Sending %d tools to the Claude API (model %s)...\n", len(s.Tools), *model)
	if err := enhance.Enhance(ctx, s, enhance.NewAnthropic(key, *model), enhance.Options{Model: *model, Out: os.Stdout}); err != nil {
		return fmt.Errorf("%w (%s is unchanged)", err, path)
	}
	if err := spec.Save(path, s); err != nil {
		return err
	}
	fmt.Printf("Updated %s. Rerunning 'har2mcp analyze' keeps these names and descriptions.\nNext: har2mcp generate %s\n", path, path)
	return nil
}
