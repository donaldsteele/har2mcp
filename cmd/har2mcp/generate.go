package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/donaldsteele/har2mcp/internal/generate"
	"github.com/donaldsteele/har2mcp/internal/spec"
)

// runGenerate implements 'har2mcp generate'.
func runGenerate(args []string) error {
	fs := newFlagSet("generate")
	target := fs.String("target", "go", "output language (this version generates go)")
	out := fs.String("o", "", "output directory (default <service name>-mcp)")
	module := fs.String("module", "", "Go module path of the generated server (default <service name>-mcp)")
	noTidy := fs.Bool("no-tidy", false, "do not run 'go mod tidy' in the output directory")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageErrorf("generate takes one spec file, got %d arguments", len(pos))
	}
	s, err := spec.Load(pos[0])
	if err != nil {
		return err
	}
	outDir := *out
	if outDir == "" {
		outDir = s.Service.Name + "-mcp"
	}
	_, goErr := exec.LookPath("go")
	files, err := generate.Generate(s, generate.Options{
		Target:     *target,
		OutDir:     outDir,
		ModulePath: *module,
		Tidy:       !*noTidy && goErr == nil,
	})
	if err != nil {
		return err
	}

	enabled, disabled, review := 0, 0, 0
	for _, t := range s.Tools {
		if t.Enabled {
			enabled++
		} else {
			disabled++
		}
		if t.Review {
			review++
		}
	}
	fmt.Printf("Generated an MCP server with %d tools in %s:\n", enabled, outDir)
	wroteCustom := false
	for _, f := range files {
		fmt.Printf("  %s\n", f)
		wroteCustom = wroteCustom || f == "custom.go"
	}
	if !wroteCustom {
		fmt.Println("  custom.go (yours, left unchanged)")
	}
	if disabled > 0 {
		fmt.Printf("%d disabled tool(s) left out (enabled: false in the spec).\n", disabled)
	}
	if review > 0 || s.Auth.Review {
		flagged := fmt.Sprintf("%d tool(s)", review)
		if s.Auth.Review {
			flagged += " and the auth block"
		}
		fmt.Printf("Note: the spec flags %s for review; run 'har2mcp inspect %s' to see them.\n", flagged, pos[0])
	}
	switch {
	case *noTidy:
		fmt.Printf("\nRun 'go mod tidy' in %s before building.\n", outDir)
	case goErr != nil:
		fmt.Printf("\nGo is not on PATH. Install Go 1.26 or later, then run 'go mod tidy' in %s.\n", outDir)
	}

	bin := s.Service.Name + "-mcp"
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	binPath, err := filepath.Abs(filepath.Join(outDir, bin))
	if err != nil {
		binPath = filepath.Join(outDir, bin)
	}
	p := s.EnvPrefix()
	url := s.Service.BaseURL
	if url == "" {
		url = "http://192.168.1.10"
	}
	fmt.Printf("\nNext, build it:\n  cd %s\n  go build -o %s .\n\nThen register it with Claude Code:\n  claude mcp add --transport stdio --env %s_URL=%s", outDir, bin, p, url)
	if s.Auth.Mode != "none" {
		fmt.Printf(" --env %s_USER=your-user --env %s_PASSWORD='your-password'", p, p)
	}
	fmt.Printf(" %s -- %s\n", s.Service.Name, binPath)
	if s.Auth.Mode == "browser" {
		fmt.Println("\nThis device logs in through a browser: Chrome, Chromium or Edge must be installed where the server runs.")
	}
	fmt.Fprintf(os.Stdout, "See %s for Claude Desktop and the other settings.\n", filepath.Join(outDir, "README.md"))
	return nil
}
