// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of KubeArmor

// Package sign provides artifact signing and verification using the
// sigstore/cosign library.  Keys are generated as ECDSA P-256 PEM files that
// are fully compatible with the cosign CLI (cosign sign-blob / cosign
// verify-blob).
package sign

// Options controls whether and how an artifact is signed after it is written.
type Options struct {
	// Enabled activates signing.  When false all other fields are ignored.
	Enabled bool

	// KeyRef is the path to an existing cosign-format PEM private key file
	// (e.g. "cosign.key").  Mutually exclusive with GenerateKey.
	KeyRef string

	// GenerateKey generates a fresh ECDSA P-256 key pair before signing.
	// The key files are written to <KeyOut>.key and <KeyOut>.pub.
	GenerateKey bool

	// KeyOut is the filename prefix used when GenerateKey is true.
	// Defaults to "cosign" → produces "cosign.key" and "cosign.pub".
	KeyOut string

	// Password is the passphrase used to protect (or unlock) the private key.
	// An empty string means no passphrase.
	Password string

	// SigOut is the path where the base-64 encoded signature is written.
	// Defaults to "<artifact-path>.sig".
	SigOut string
}
