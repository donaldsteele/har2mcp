// Package deps blank-imports the libraries later packages will use, so that
// 'go mod tidy' keeps them in go.mod until real code imports them. Delete it
// once the recorder, generator and enhance packages exist.
package deps

import (
	_ "github.com/anthropics/anthropic-sdk-go"
	_ "github.com/chromedp/cdproto/network"
	_ "github.com/chromedp/chromedp"
	_ "github.com/modelcontextprotocol/go-sdk/mcp"
)
