// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of KubeArmor

package cbom

import "github.com/accuknox/accuknox-cli-v2/pkg/sign"

// Options holds configuration for CBOM generation.
type Options struct {
	// Source scanning
	Path string // directory to scan for source code

	// Image scanning
	Image string // container image reference (e.g. nginx:latest)

	// Project metadata embedded in metadata.component
	Name        string // project name
	Group       string // group / module prefix (e.g. "com.example" or "github.com/org")
	Version     string // project version (e.g. "1.2.3")
	Description string // short description of the project
	License     string // SPDX license identifier (e.g. "Apache-2.0")

	// Common options
	BOMFile  string // path to existing BOM to enrich/verify
	Plugins  string // comma-separated scanner plugin list
	Ignore   string // glob patterns to exclude from scanning
	OutputTo string // write CBOM JSON to this file instead of stdout
	Format   string // output format: "json" (default) or "table"

	// Signing options — sign the output artifact with cosign.
	Sign sign.Options
}
