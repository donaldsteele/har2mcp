package generate

// Module versions that generated go.mod files require. They match har2mcp's
// own go.mod (TestVersionsMatchGoMod checks), so a generated server builds
// against the same SDK that har2mcp is tested with.
const (
	MCPSDKVersion   = "v1.8.0"
	ChromedpVersion = "v0.24.0"
	CdprotoVersion  = "v0.160.8"
)

// goDirective is the go version line of generated go.mod files.
const goDirective = "1.26"
