//go:build windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of KubeArmor

package cbom

import (
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// ScanImage is not supported on Windows.
func ScanImage(opts *Options) (*cdx.BOM, error) {
	return nil, fmt.Errorf("image scanning is not supported on Windows")
}

// ScanDir is not supported on Windows.
func ScanDir(opts *Options) (*cdx.BOM, error) {
	return nil, fmt.Errorf("directory scanning is not supported on Windows")
}
