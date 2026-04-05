// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of KubeArmor

package cbom

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// cryptoEntry describes a known Go crypto package and its CycloneDX properties.
type cryptoEntry struct {
	name        string
	description string
	primitive   cdx.CryptoPrimitive
	params      string // parameter set identifier (e.g. key size)
	curve       string
	mode        cdx.CryptoAlgorithmMode
	functions   []cdx.CryptoFunction
	assetType   cdx.CryptoAssetType
	protocol    cdx.CryptoProtocolType
	refs        []cdx.ExternalReference // standards/specification references
	license     string                  // SPDX license identifier for the package
}

// ref is a convenience helper for building an ExternalReference.
func ref(refType cdx.ExternalReferenceType, url string) cdx.ExternalReference {
	return cdx.ExternalReference{Type: refType, URL: url}
}

// licenseFor returns the SPDX license identifier for a Go crypto import path.
// All Go standard library packages and golang.org/x/crypto packages are BSD-3-Clause.
func licenseFor(importPath string) string {
	if strings.HasPrefix(importPath, "crypto/") || strings.HasPrefix(importPath, "golang.org/x/crypto/") {
		return "BSD-3-Clause"
	}
	return ""
}

// knownPackages maps Go import paths to their CBOM descriptor.
var knownPackages = map[string]cryptoEntry{
	// ── Standard library — symmetric ────────────────────────────────────────
	"crypto/aes": {
		name:        "AES",
		description: "Advanced Encryption Standard (AES) block cipher as defined in FIPS PUB 197.",
		primitive:   cdx.CryptoPrimitiveBlockCipher,
		functions:   []cdx.CryptoFunction{cdx.CryptoFunctionEncrypt, cdx.CryptoFunctionDecrypt},
		assetType:   cdx.CryptoAssetTypeAlgorithm,
		refs: []cdx.ExternalReference{
			ref(cdx.ERTypeOther, "https://csrc.nist.gov/publications/detail/fips/197/final"),
		},
	},
	"crypto/des": {
		name:        "DES",
		description: "Data Encryption Standard (DES) and Triple-DES (3DES) block cipher.",
		primitive:   cdx.CryptoPrimitiveBlockCipher,
		functions:   []cdx.CryptoFunction{cdx.CryptoFunctionEncrypt, cdx.CryptoFunctionDecrypt},
		assetType:   cdx.CryptoAssetTypeAlgorithm,
		refs: []cdx.ExternalReference{
			ref(cdx.ERTypeOther, "https://csrc.nist.gov/publications/detail/fips/46/3/final"),
		},
	},
	"crypto/rc4": {
		name:        "RC4",
		description: "RC4 stream cipher (deprecated; avoid in new designs).",
		primitive:   cdx.CryptoPrimitiveStreamCipher,
		functions:   []cdx.CryptoFunction{cdx.CryptoFunctionEncrypt, cdx.CryptoFunctionDecrypt},
		assetType:   cdx.CryptoAssetTypeAlgorithm,
		refs: []cdx.ExternalReference{
			ref(cdx.ERTypeOther, "https://www.rfc-editor.org/rfc/rfc7465"),
		},
	},

	// ── Standard library — hash ──────────────────────────────────────────────
	"crypto/md5": {
		name:        "MD5",
		description: "MD5 message-digest algorithm producing a 128-bit hash (deprecated for security use).",
		primitive:   cdx.CryptoPrimitiveHash,
		functions:   []cdx.CryptoFunction{cdx.CryptoFunctionDigest},
		params:      "128",
		assetType:   cdx.CryptoAssetTypeAlgorithm,
		refs: []cdx.ExternalReference{
			ref(cdx.ERTypeOther, "https://www.rfc-editor.org/rfc/rfc1321"),
		},
	},
	"crypto/sha1": {
		name:        "SHA-1",
		description: "SHA-1 hash function producing a 160-bit digest (deprecated for security use).",
		primitive:   cdx.CryptoPrimitiveHash,
		functions:   []cdx.CryptoFunction{cdx.CryptoFunctionDigest},
		params:      "160",
		assetType:   cdx.CryptoAssetTypeAlgorithm,
		refs: []cdx.ExternalReference{
			ref(cdx.ERTypeOther, "https://csrc.nist.gov/publications/detail/fips/180/4/final"),
		},
	},
	"crypto/sha256": {
		name:        "SHA-256",
		description: "SHA-2 hash function producing a 256-bit digest as defined in FIPS PUB 180-4.",
		primitive:   cdx.CryptoPrimitiveHash,
		functions:   []cdx.CryptoFunction{cdx.CryptoFunctionDigest},
		params:      "256",
		assetType:   cdx.CryptoAssetTypeAlgorithm,
		refs: []cdx.ExternalReference{
			ref(cdx.ERTypeOther, "https://csrc.nist.gov/publications/detail/fips/180/4/final"),
		},
	},
	"crypto/sha512": {
		name:        "SHA-512",
		description: "SHA-2 hash function producing a 512-bit digest as defined in FIPS PUB 180-4.",
		primitive:   cdx.CryptoPrimitiveHash,
		functions:   []cdx.CryptoFunction{cdx.CryptoFunctionDigest},
		params:      "512",
		assetType:   cdx.CryptoAssetTypeAlgorithm,
		refs: []cdx.ExternalReference{
			ref(cdx.ERTypeOther, "https://csrc.nist.gov/publications/detail/fips/180/4/final"),
		},
	},

	// ── Standard library — MAC ───────────────────────────────────────────────
	"crypto/hmac": {
		name:        "HMAC",
		description: "Hash-based Message Authentication Code (HMAC) as defined in FIPS PUB 198-1.",
		primitive:   cdx.CryptoPrimitiveMAC,
		functions:   []cdx.CryptoFunction{cdx.CryptoFunctionTag},
		assetType:   cdx.CryptoAssetTypeAlgorithm,
		refs: []cdx.ExternalReference{
			ref(cdx.ERTypeOther, "https://csrc.nist.gov/publications/detail/fips/198/1/final"),
		},
	},

	// ── Standard library — asymmetric ───────────────────────────────────────
	"crypto/rsa": {
		name:        "RSA",
		description: "RSA public-key cryptosystem used for encryption and digital signatures.",
		primitive:   cdx.CryptoPrimitivePKE,
		functions:   []cdx.CryptoFunction{cdx.CryptoFunctionEncrypt, cdx.CryptoFunctionDecrypt, cdx.CryptoFunctionSign, cdx.CryptoFunctionVerify},
		assetType:   cdx.CryptoAssetTypeAlgorithm,
		refs: []cdx.ExternalReference{
			ref(cdx.ERTypeOther, "https://www.rfc-editor.org/rfc/rfc8017"),
		},
	},
	"crypto/ecdsa": {
		name:        "ECDSA",
		description: "Elliptic Curve Digital Signature Algorithm as defined in FIPS PUB 186-5.",
		primitive:   cdx.CryptoPrimitiveSignature,
		functions:   []cdx.CryptoFunction{cdx.CryptoFunctionSign, cdx.CryptoFunctionVerify},
		assetType:   cdx.CryptoAssetTypeAlgorithm,
		refs: []cdx.ExternalReference{
			ref(cdx.ERTypeOther, "https://csrc.nist.gov/publications/detail/fips/186/5/final"),
		},
	},
	"crypto/ecdh": {
		name:        "ECDH",
		description: "Elliptic-Curve Diffie-Hellman key agreement.",
		primitive:   cdx.CryptoPrimitiveKeyAgree,
		functions:   []cdx.CryptoFunction{cdx.CryptoFunctionKeygen},
		assetType:   cdx.CryptoAssetTypeAlgorithm,
		refs: []cdx.ExternalReference{
			ref(cdx.ERTypeOther, "https://www.rfc-editor.org/rfc/rfc8037"),
		},
	},
	"crypto/ed25519": {
		name:        "Ed25519",
		description: "Edwards-curve Digital Signature Algorithm (EdDSA) over Curve25519.",
		primitive:   cdx.CryptoPrimitiveSignature,
		curve:       "Ed25519",
		functions:   []cdx.CryptoFunction{cdx.CryptoFunctionSign, cdx.CryptoFunctionVerify},
		assetType:   cdx.CryptoAssetTypeAlgorithm,
		refs: []cdx.ExternalReference{
			ref(cdx.ERTypeOther, "https://www.rfc-editor.org/rfc/rfc8032"),
		},
	},
	"crypto/elliptic": {
		name:        "ECDSA",
		description: "NIST elliptic curve operations (P-224, P-256, P-384, P-521).",
		primitive:   cdx.CryptoPrimitiveSignature,
		functions:   []cdx.CryptoFunction{cdx.CryptoFunctionKeygen},
		assetType:   cdx.CryptoAssetTypeAlgorithm,
		refs: []cdx.ExternalReference{
			ref(cdx.ERTypeOther, "https://csrc.nist.gov/publications/detail/fips/186/5/final"),
		},
	},

	// ── Standard library — random ────────────────────────────────────────────
	"crypto/rand": {
		name:        "DRBG",
		description: "Cryptographically secure pseudo-random number generator (CSPRNG).",
		primitive:   cdx.CryptoPrimitiveDRBG,
		functions:   []cdx.CryptoFunction{cdx.CryptoFunctionGenerate},
		assetType:   cdx.CryptoAssetTypeAlgorithm,
		refs: []cdx.ExternalReference{
			ref(cdx.ERTypeOther, "https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final"),
		},
	},

	// ── Standard library — DSA ──────────────────────────────────────────────
	"crypto/dsa": {
		name:        "DSA",
		description: "Digital Signature Algorithm (DSA) as defined in FIPS PUB 186-5 (deprecated).",
		primitive:   cdx.CryptoPrimitiveSignature,
		functions:   []cdx.CryptoFunction{cdx.CryptoFunctionSign, cdx.CryptoFunctionVerify},
		assetType:   cdx.CryptoAssetTypeAlgorithm,
		refs: []cdx.ExternalReference{
			ref(cdx.ERTypeOther, "https://csrc.nist.gov/publications/detail/fips/186/5/final"),
		},
	},

	// ── Standard library — protocols / infrastructure ────────────────────────
	"crypto/tls": {
		name:        "TLS",
		description: "Transport Layer Security (TLS) protocol implementation.",
		assetType:   cdx.CryptoAssetTypeProtocol,
		protocol:    cdx.CryptoProtocolTypeTLS,
		refs: []cdx.ExternalReference{
			ref(cdx.ERTypeOther, "https://www.rfc-editor.org/rfc/rfc8446"),
		},
	},
	"crypto/x509": {
		name:        "X.509",
		description: "X.509 public key infrastructure (PKI) and certificate handling.",
		assetType:   cdx.CryptoAssetTypeCertificate,
		refs: []cdx.ExternalReference{
			ref(cdx.ERTypeOther, "https://www.rfc-editor.org/rfc/rfc5280"),
		},
	},
	"crypto/x509/pkix": {
		name:        "X.509/PKIX",
		description: "ASN.1 PKIX structures used in X.509 certificates and CRLs.",
		assetType:   cdx.CryptoAssetTypeCertificate,
		refs: []cdx.ExternalReference{
			ref(cdx.ERTypeOther, "https://www.rfc-editor.org/rfc/rfc5280"),
		},
	},

	// ── golang.org/x/crypto ──────────────────────────────────────────────────
	"golang.org/x/crypto/chacha20": {
		name:        "ChaCha20",
		description: "ChaCha20 stream cipher as defined in RFC 8439.",
		primitive:   cdx.CryptoPrimitiveStreamCipher,
		functions:   []cdx.CryptoFunction{cdx.CryptoFunctionEncrypt, cdx.CryptoFunctionDecrypt},
		assetType:   cdx.CryptoAssetTypeAlgorithm,
		refs: []cdx.ExternalReference{
			ref(cdx.ERTypeOther, "https://www.rfc-editor.org/rfc/rfc8439"),
		},
	},
	"golang.org/x/crypto/chacha20poly1305": {
		name:        "ChaCha20-Poly1305",
		description: "ChaCha20-Poly1305 AEAD cipher as defined in RFC 8439.",
		primitive:   cdx.CryptoPrimitiveAE,
		functions:   []cdx.CryptoFunction{cdx.CryptoFunctionEncrypt, cdx.CryptoFunctionDecrypt},
		assetType:   cdx.CryptoAssetTypeAlgorithm,
		refs: []cdx.ExternalReference{
			ref(cdx.ERTypeOther, "https://www.rfc-editor.org/rfc/rfc8439"),
		},
	},
	"golang.org/x/crypto/argon2": {
		name:        "Argon2",
		description: "Argon2 memory-hard password hashing function (winner of the Password Hashing Competition).",
		primitive:   cdx.CryptoPrimitiveKDF,
		functions:   []cdx.CryptoFunction{cdx.CryptoFunctionKeyderive},
		assetType:   cdx.CryptoAssetTypeAlgorithm,
		refs: []cdx.ExternalReference{
			ref(cdx.ERTypeOther, "https://www.rfc-editor.org/rfc/rfc9106"),
		},
	},
	"golang.org/x/crypto/bcrypt": {
		name:        "bcrypt",
		description: "bcrypt adaptive password hashing function based on Blowfish.",
		primitive:   cdx.CryptoPrimitiveKDF,
		functions:   []cdx.CryptoFunction{cdx.CryptoFunctionKeyderive},
		assetType:   cdx.CryptoAssetTypeAlgorithm,
		refs: []cdx.ExternalReference{
			ref(cdx.ERTypeOther, "https://www.usenix.org/legacy/events/usenix99/provos/provos.pdf"),
		},
	},
	"golang.org/x/crypto/pbkdf2": {
		name:        "PBKDF2",
		description: "Password-Based Key Derivation Function 2 as defined in RFC 8018.",
		primitive:   cdx.CryptoPrimitiveKDF,
		functions:   []cdx.CryptoFunction{cdx.CryptoFunctionKeyderive},
		assetType:   cdx.CryptoAssetTypeAlgorithm,
		refs: []cdx.ExternalReference{
			ref(cdx.ERTypeOther, "https://www.rfc-editor.org/rfc/rfc8018"),
		},
	},
	"golang.org/x/crypto/scrypt": {
		name:        "scrypt",
		description: "scrypt memory-hard key derivation function as defined in RFC 7914.",
		primitive:   cdx.CryptoPrimitiveKDF,
		functions:   []cdx.CryptoFunction{cdx.CryptoFunctionKeyderive},
		assetType:   cdx.CryptoAssetTypeAlgorithm,
		refs: []cdx.ExternalReference{
			ref(cdx.ERTypeOther, "https://www.rfc-editor.org/rfc/rfc7914"),
		},
	},
	"golang.org/x/crypto/hkdf": {
		name:        "HKDF",
		description: "HMAC-based Key Derivation Function (HKDF) as defined in RFC 5869.",
		primitive:   cdx.CryptoPrimitiveKDF,
		functions:   []cdx.CryptoFunction{cdx.CryptoFunctionKeyderive},
		assetType:   cdx.CryptoAssetTypeAlgorithm,
		refs: []cdx.ExternalReference{
			ref(cdx.ERTypeOther, "https://www.rfc-editor.org/rfc/rfc5869"),
		},
	},
	"golang.org/x/crypto/blake2b": {
		name:        "BLAKE2b",
		description: "BLAKE2b cryptographic hash function optimised for 64-bit platforms.",
		primitive:   cdx.CryptoPrimitiveHash,
		functions:   []cdx.CryptoFunction{cdx.CryptoFunctionDigest},
		assetType:   cdx.CryptoAssetTypeAlgorithm,
		refs: []cdx.ExternalReference{
			ref(cdx.ERTypeOther, "https://www.rfc-editor.org/rfc/rfc7693"),
		},
	},
	"golang.org/x/crypto/blake2s": {
		name:        "BLAKE2s",
		description: "BLAKE2s cryptographic hash function optimised for 8- to 32-bit platforms.",
		primitive:   cdx.CryptoPrimitiveHash,
		functions:   []cdx.CryptoFunction{cdx.CryptoFunctionDigest},
		assetType:   cdx.CryptoAssetTypeAlgorithm,
		refs: []cdx.ExternalReference{
			ref(cdx.ERTypeOther, "https://www.rfc-editor.org/rfc/rfc7693"),
		},
	},
	"golang.org/x/crypto/nacl/box": {
		name:        "NaCl/box",
		description: "NaCl box: authenticated public-key encryption using Curve25519, XSalsa20, and Poly1305.",
		primitive:   cdx.CryptoPrimitiveAE,
		functions:   []cdx.CryptoFunction{cdx.CryptoFunctionEncrypt, cdx.CryptoFunctionDecrypt},
		assetType:   cdx.CryptoAssetTypeAlgorithm,
		refs: []cdx.ExternalReference{
			ref(cdx.ERTypeWebsite, "https://nacl.cr.yp.to/box.html"),
		},
	},
	"golang.org/x/crypto/nacl/secretbox": {
		name:        "NaCl/secretbox",
		description: "NaCl secretbox: authenticated secret-key encryption using XSalsa20 and Poly1305.",
		primitive:   cdx.CryptoPrimitiveAE,
		functions:   []cdx.CryptoFunction{cdx.CryptoFunctionEncrypt, cdx.CryptoFunctionDecrypt},
		assetType:   cdx.CryptoAssetTypeAlgorithm,
		refs: []cdx.ExternalReference{
			ref(cdx.ERTypeWebsite, "https://nacl.cr.yp.to/secretbox.html"),
		},
	},
	"golang.org/x/crypto/ssh": {
		name:        "SSH",
		description: "Secure Shell (SSH) protocol implementation.",
		assetType:   cdx.CryptoAssetTypeProtocol,
		protocol:    cdx.CryptoProtocolTypeSSH,
		refs: []cdx.ExternalReference{
			ref(cdx.ERTypeOther, "https://www.rfc-editor.org/rfc/rfc4251"),
		},
	},
	"golang.org/x/crypto/openpgp": {
		name:        "OpenPGP",
		description: "OpenPGP message format for encryption and signing (RFC 4880).",
		primitive:   cdx.CryptoPrimitiveOther,
		functions:   []cdx.CryptoFunction{cdx.CryptoFunctionEncrypt, cdx.CryptoFunctionSign},
		assetType:   cdx.CryptoAssetTypeAlgorithm,
		refs: []cdx.ExternalReference{
			ref(cdx.ERTypeOther, "https://www.rfc-editor.org/rfc/rfc4880"),
		},
	},
}

// occurrence tracks a source location where a crypto import was found.
type occurrence struct {
	file string
	line int
}

// ScanSource walks the directory at path, parses Go source files, and returns
// a slice of CycloneDX components for every distinct crypto package imported.
func ScanSource(path string) ([]cdx.Component, error) {
	seen := map[string][]occurrence{}

	err := filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Always descend into the root itself; only skip hidden/special
			// directories encountered below it.
			if p == path {
				return nil
			}
			name := d.Name()
			if name == "vendor" || name == "testdata" || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}

		fset := token.NewFileSet()
		f, parseErr := parser.ParseFile(fset, p, nil, parser.ImportsOnly)
		if parseErr != nil {
			return nil
		}

		for _, imp := range f.Imports {
			importPath := strings.Trim(imp.Path.Value, `"`)
			if _, ok := knownPackages[importPath]; ok {
				pos := fset.Position(imp.Path.Pos())
				seen[importPath] = append(seen[importPath], occurrence{
					file: p,
					line: pos.Line,
				})
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking %s: %w", path, err)
	}

	return buildComponents(seen), nil
}

// buildComponents converts the collected import occurrences into CycloneDX components.
func buildComponents(seen map[string][]occurrence) []cdx.Component {
	components := make([]cdx.Component, 0, len(seen))

	for importPath, occs := range seen {
		entry := knownPackages[importPath]
		comp := cdx.Component{
			BOMRef:      fmt.Sprintf("crypto/%s/%s", entry.name, importPath),
			Type:        cdx.ComponentTypeCryptographicAsset,
			Name:        entry.name,
			Description: entry.description,
			Scope:       cdx.ScopeRequired,
		}

		if len(entry.refs) > 0 {
			refs := entry.refs
			comp.ExternalReferences = &refs
		}

		if lic := licenseFor(importPath); lic != "" {
			lc := cdx.LicenseChoice{License: &cdx.License{ID: lic}}
			comp.Licenses = &cdx.Licenses{lc}
		}

		switch entry.assetType {
		case cdx.CryptoAssetTypeAlgorithm:
			funcs := entry.functions
			comp.CryptoProperties = &cdx.CryptoProperties{
				AssetType: cdx.CryptoAssetTypeAlgorithm,
				AlgorithmProperties: &cdx.CryptoAlgorithmProperties{
					Primitive:              entry.primitive,
					ParameterSetIdentifier: entry.params,
					Curve:                  entry.curve,
					Mode:                   entry.mode,
					CryptoFunctions:        &funcs,
				},
			}
		case cdx.CryptoAssetTypeProtocol:
			comp.CryptoProperties = &cdx.CryptoProperties{
				AssetType: cdx.CryptoAssetTypeProtocol,
				ProtocolProperties: &cdx.CryptoProtocolProperties{
					Type: entry.protocol,
				},
			}
		case cdx.CryptoAssetTypeCertificate:
			comp.CryptoProperties = &cdx.CryptoProperties{
				AssetType:             cdx.CryptoAssetTypeCertificate,
				CertificateProperties: &cdx.CertificateProperties{},
			}
		}

		// Source evidence: file locations where the import was found.
		evOccs := make([]cdx.EvidenceOccurrence, 0, len(occs))
		for _, o := range occs {
			line := o.line
			evOccs = append(evOccs, cdx.EvidenceOccurrence{
				Location: o.file,
				Line:     &line,
			})
		}
		comp.Evidence = &cdx.Evidence{Occurrences: &evOccs}

		components = append(components, comp)
	}

	return components
}

// parseImports extracts all import paths from a single Go source file.
// Used in tests.
func parseImports(src string) ([]string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", src, parser.ImportsOnly)
	if err != nil {
		return nil, err
	}
	var imports []string
	ast.Inspect(f, func(n ast.Node) bool {
		if imp, ok := n.(*ast.ImportSpec); ok {
			imports = append(imports, strings.Trim(imp.Path.Value, `"`))
		}
		return true
	})
	return imports, nil
}
