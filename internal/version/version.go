// Package version holds the har2mcp version string.
package version

import (
	"runtime/debug"
	"strings"
)

// Version is the har2mcp version, without a leading "v". Release builds set
// it with:
//
//	-ldflags "-X github.com/donaldsteele/har2mcp/internal/version.Version=0.1.0"
//
// A binary built with 'go install ...@v0.1.0' falls back to the module
// version; anything else reports "dev".
var Version = "dev"

func init() {
	if Version != "dev" {
		return
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		if v := bi.Main.Version; v != "" && v != "(devel)" {
			Version = strings.TrimPrefix(v, "v")
		}
	}
}
