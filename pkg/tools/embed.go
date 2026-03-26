package tools

import "embed"

// binsFS holds the tool binaries downloaded into pkg/tools/bins/ at build time
// by the goreleaser pre-hook. In development builds the directory is empty and
// EnsureInstalled falls back to downloading the tool at runtime.
//
//go:embed bins
var binsFS embed.FS
