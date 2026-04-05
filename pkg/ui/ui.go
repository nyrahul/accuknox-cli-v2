// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of KubeArmor

// Package ui provides an embedded web UI server for knoxctl.
package ui

import "embed"

//go:embed static
var StaticFS embed.FS
