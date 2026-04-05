// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of KubeArmor

package sign

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	cosigncrypto "github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

// Artifact signs the file at artifactPath according to opts.
// It is a no-op when opts.Enabled is false or artifactPath is empty.
//
// Key resolution order:
//  1. If opts.GenerateKey is true, a fresh ECDSA P-256 key pair is created and
//     written to <KeyOut>.key / <KeyOut>.pub before signing.
//  2. Otherwise opts.KeyRef (default "cosign.key") is loaded from disk.
//
// The base-64 encoded signature is written to opts.SigOut, or to
// <artifactPath>.sig when SigOut is empty.
func Artifact(artifactPath string, opts *Options) error {
	if !opts.Enabled || artifactPath == "" {
		return nil
	}

	password := []byte(opts.Password)
	passFunc := func(bool) ([]byte, error) { return password, nil }

	var keyBytes []byte

	if opts.GenerateKey {
		prefix := opts.KeyOut
		if prefix == "" {
			prefix = "cosign"
		}
		kb, err := cosigncrypto.GenerateKeyPair(passFunc)
		if err != nil {
			return fmt.Errorf("sign: generating key pair: %w", err)
		}
		privPath := prefix + ".key"
		pubPath := prefix + ".pub"
		if err := os.WriteFile(privPath, kb.PrivateBytes, 0600); err != nil {
			return fmt.Errorf("sign: writing private key %s: %w", privPath, err)
		}
		if err := os.WriteFile(pubPath, kb.PublicBytes, 0644); err != nil {
			return fmt.Errorf("sign: writing public key %s: %w", pubPath, err)
		}
		fmt.Printf("Generated key pair → %s (private)  %s (public)\n", privPath, pubPath)
		keyBytes = kb.PrivateBytes
	} else {
		keyRef := opts.KeyRef
		if keyRef == "" {
			keyRef = "cosign.key"
		}
		b, err := os.ReadFile(keyRef) // #nosec G304
		if err != nil {
			return fmt.Errorf("sign: reading key %s: %w", keyRef, err)
		}
		keyBytes = b
	}

	// Load signer from PEM private key.
	sv, err := cosigncrypto.LoadPrivateKey(keyBytes, password, nil)
	if err != nil {
		return fmt.Errorf("sign: loading private key: %w", err)
	}

	// Read the artifact.
	data, err := os.ReadFile(artifactPath) // #nosec G304
	if err != nil {
		return fmt.Errorf("sign: reading artifact %s: %w", artifactPath, err)
	}

	// Produce raw signature bytes.
	sig, err := sv.SignMessage(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("sign: signing artifact: %w", err)
	}

	// Write base-64 signature.
	sigPath := opts.SigOut
	if sigPath == "" {
		sigPath = artifactPath + ".sig"
	}
	encoded := base64.StdEncoding.EncodeToString(sig) + "\n"
	if err := os.WriteFile(sigPath, []byte(encoded), 0644); err != nil {
		return fmt.Errorf("sign: writing signature %s: %w", sigPath, err)
	}

	fmt.Printf("Artifact signed    → %s\n", sigPath)
	fmt.Printf("Verify with:         cosign verify-blob --key %s --signature %s %s\n",
		pubKeyPath(opts), sigPath, artifactPath)
	return nil
}

// SignBytes signs data entirely in-memory and returns:
//   - sigB64: base-64 encoded ECDSA signature
//   - pubKeyPEM: PEM-encoded public key (only populated when opts.GenerateKey is true)
//
// When opts.GenerateKey is true a fresh ephemeral ECDSA P-256 key pair is
// generated; no key files are written to disk.
// When opts.GenerateKey is false opts.KeyRef (default "cosign.key") is read
// from disk, decrypted with opts.Password, and used for signing.
func SignBytes(data []byte, opts *Options) (sigB64 string, pubKeyPEM []byte, err error) {
	var sv signature.SignerVerifier

	if opts.GenerateKey {
		privKey, genErr := cosigncrypto.GeneratePrivateKey()
		if genErr != nil {
			return "", nil, fmt.Errorf("sign: generating private key: %w", genErr)
		}
		sv, err = signature.LoadECDSASignerVerifier(privKey, crypto.SHA256)
		if err != nil {
			return "", nil, fmt.Errorf("sign: loading signer: %w", err)
		}
		pubKeyPEM, err = cryptoutils.MarshalPublicKeyToPEM(privKey.Public())
		if err != nil {
			return "", nil, fmt.Errorf("sign: marshaling public key: %w", err)
		}
	} else {
		keyRef := opts.KeyRef
		if keyRef == "" {
			keyRef = "cosign.key"
		}
		keyBytes, readErr := os.ReadFile(keyRef) // #nosec G304
		if readErr != nil {
			return "", nil, fmt.Errorf("sign: reading key %s: %w", keyRef, readErr)
		}
		sv, err = cosigncrypto.LoadPrivateKey(keyBytes, []byte(opts.Password), nil)
		if err != nil {
			return "", nil, fmt.Errorf("sign: loading private key: %w", err)
		}
	}

	sig, err := sv.SignMessage(bytes.NewReader(data))
	if err != nil {
		return "", nil, fmt.Errorf("sign: signing: %w", err)
	}
	return base64.StdEncoding.EncodeToString(sig), pubKeyPEM, nil
}

// Verify checks that the base-64 signature in sigPath was produced by the
// private key corresponding to the PEM public key in pubKeyPath over the file
// at artifactPath.
func Verify(artifactPath, sigPath, pubKeyPath string) error {
	data, err := os.ReadFile(artifactPath) // #nosec G304
	if err != nil {
		return fmt.Errorf("verify: reading artifact %s: %w", artifactPath, err)
	}

	rawSig, err := os.ReadFile(sigPath) // #nosec G304
	if err != nil {
		return fmt.Errorf("verify: reading signature %s: %w", sigPath, err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(rawSig)))
	if err != nil {
		return fmt.Errorf("verify: decoding signature: %w", err)
	}

	pubPEM, err := os.ReadFile(pubKeyPath) // #nosec G304
	if err != nil {
		return fmt.Errorf("verify: reading public key %s: %w", pubKeyPath, err)
	}
	pubKey, err := cosigncrypto.PemToECDSAKey(pubPEM)
	if err != nil {
		return fmt.Errorf("verify: parsing public key: %w", err)
	}

	verifier, err := signature.LoadECDSAVerifier(pubKey, crypto.SHA256)
	if err != nil {
		return fmt.Errorf("verify: loading verifier: %w", err)
	}

	if err := verifier.VerifySignature(
		bytes.NewReader(sigBytes),
		bytes.NewReader(data),
	); err != nil {
		return fmt.Errorf("verify: invalid signature: %w", err)
	}

	fmt.Printf("Signature OK: %s is authentic\n", artifactPath)
	return nil
}

// pubKeyPath returns the public key path corresponding to the signing options.
func pubKeyPath(opts *Options) string {
	prefix := opts.KeyOut
	if prefix == "" {
		prefix = "cosign"
	}
	if opts.GenerateKey {
		return prefix + ".pub"
	}
	// For a loaded key, replace ".key" suffix with ".pub".
	ref := opts.KeyRef
	if ref == "" {
		ref = "cosign.key"
	}
	if strings.HasSuffix(ref, ".key") {
		return strings.TrimSuffix(ref, ".key") + ".pub"
	}
	return ref + ".pub"
}
