// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of KubeArmor

package cbom

import (
	"os"
	"path/filepath"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// ----- source scanner tests -----

func TestParseImports_CryptoPackages(t *testing.T) {
	src := `package main
import (
	"crypto/aes"
	"crypto/sha256"
	_ "crypto/rand"
)
func main() { _ = aes.NewCipher; _ = sha256.New }
`
	imports, err := parseImports(src)
	if err != nil {
		t.Fatalf("parseImports: %v", err)
	}
	want := map[string]bool{
		"crypto/aes":    true,
		"crypto/sha256": true,
		"crypto/rand":   true,
	}
	for _, imp := range imports {
		delete(want, imp)
	}
	if len(want) > 0 {
		t.Errorf("missing imports: %v", want)
	}
}

func TestScanSource_KnownPackages(t *testing.T) {
	dir := t.TempDir()

	// Write a Go file that imports several crypto packages
	src := `package foo
import (
	"crypto/aes"
	"crypto/rsa"
	"crypto/tls"
	"golang.org/x/crypto/bcrypt"
)
var _ = aes.NewCipher
var _ = rsa.GenerateKey
var _ = tls.Dial
var _ = bcrypt.GenerateFromPassword
`
	if err := os.WriteFile(filepath.Join(dir, "crypto_test.go"), []byte(src), 0600); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	components, err := ScanSource(dir)
	if err != nil {
		t.Fatalf("ScanSource: %v", err)
	}
	if len(components) == 0 {
		t.Fatal("expected at least one component, got none")
	}

	found := map[string]bool{}
	for _, c := range components {
		found[c.Name] = true
		if c.Type != cdx.ComponentTypeCryptographicAsset {
			t.Errorf("component %q: want type cryptographic-asset, got %s", c.Name, c.Type)
		}
		if c.CryptoProperties == nil {
			t.Errorf("component %q: missing CryptoProperties", c.Name)
		}
		if c.Evidence == nil || c.Evidence.Occurrences == nil {
			t.Errorf("component %q: missing Evidence.Occurrences", c.Name)
		}
	}

	for _, name := range []string{"AES", "RSA", "TLS", "bcrypt"} {
		if !found[name] {
			t.Errorf("expected component %q not found; got: %v", name, keys(found))
		}
	}
}

func TestScanSource_DotPath(t *testing.T) {
	// Regression test: passing "." as path must not skip the root directory.
	dir := t.TempDir()
	src := `package foo
import "crypto/aes"
var _ = aes.NewCipher
`
	if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte(src), 0600); err != nil {
		t.Fatal(err)
	}

	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(orig) }()

	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	components, err := ScanSource(".")
	if err != nil {
		t.Fatalf("ScanSource('.'): %v", err)
	}
	if len(components) == 0 {
		t.Error("expected crypto components when path is '.', got none")
	}
}

func TestScanSource_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	components, err := ScanSource(dir)
	if err != nil {
		t.Fatalf("ScanSource on empty dir: %v", err)
	}
	if len(components) != 0 {
		t.Errorf("expected 0 components for empty dir, got %d", len(components))
	}
}

func TestScanSource_NonCryptoFile(t *testing.T) {
	dir := t.TempDir()
	src := `package main
import "fmt"
func main() { fmt.Println("hello") }
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0600); err != nil {
		t.Fatalf("writing test file: %v", err)
	}
	components, err := ScanSource(dir)
	if err != nil {
		t.Fatalf("ScanSource: %v", err)
	}
	if len(components) != 0 {
		t.Errorf("expected 0 crypto components, got %d", len(components))
	}
}

func TestScanSource_SkipsVendor(t *testing.T) {
	dir := t.TempDir()

	// Real file with crypto
	src := `package main
import "crypto/aes"
var _ = aes.NewCipher
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0600); err != nil {
		t.Fatal(err)
	}

	// vendor directory with crypto — should be skipped
	vendorDir := filepath.Join(dir, "vendor", "some", "pkg")
	if err := os.MkdirAll(vendorDir, 0750); err != nil {
		t.Fatal(err)
	}
	vendorSrc := `package pkg
import "crypto/rsa"
var _ = rsa.GenerateKey
`
	if err := os.WriteFile(filepath.Join(vendorDir, "pkg.go"), []byte(vendorSrc), 0600); err != nil {
		t.Fatal(err)
	}

	components, err := ScanSource(dir)
	if err != nil {
		t.Fatalf("ScanSource: %v", err)
	}
	for _, c := range components {
		if c.Name == "RSA" {
			t.Error("RSA from vendor dir should have been skipped")
		}
	}
}

func TestScanSource_EvidenceOccurrences(t *testing.T) {
	dir := t.TempDir()
	src := `package foo
import "crypto/sha256"
var _ = sha256.New
`
	if err := os.WriteFile(filepath.Join(dir, "hash.go"), []byte(src), 0600); err != nil {
		t.Fatal(err)
	}

	components, err := ScanSource(dir)
	if err != nil {
		t.Fatalf("ScanSource: %v", err)
	}
	if len(components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(components))
	}
	c := components[0]
	if c.Evidence == nil || c.Evidence.Occurrences == nil || len(*c.Evidence.Occurrences) == 0 {
		t.Fatal("expected Evidence.Occurrences to be populated")
	}
	occ := (*c.Evidence.Occurrences)[0]
	if occ.Location == "" {
		t.Error("occurrence Location should not be empty")
	}
	if occ.Line == nil || *occ.Line == 0 {
		t.Error("occurrence Line should be populated")
	}
}

func TestScanSource_DeduplicatesAcrossFiles(t *testing.T) {
	dir := t.TempDir()

	for i, name := range []string{"a.go", "b.go"} {
		_ = i
		src := `package foo
import "crypto/aes"
var _ = aes.NewCipher
`
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0600); err != nil {
			t.Fatal(err)
		}
	}

	components, err := ScanSource(dir)
	if err != nil {
		t.Fatalf("ScanSource: %v", err)
	}
	// Should return one AES component with two occurrences
	var aesComp *cdx.Component
	for i := range components {
		if components[i].Name == "AES" {
			aesComp = &components[i]
		}
	}
	if aesComp == nil {
		t.Fatal("AES component not found")
	}
	if aesComp.Evidence == nil || aesComp.Evidence.Occurrences == nil {
		t.Fatal("missing occurrences")
	}
	if len(*aesComp.Evidence.Occurrences) != 2 {
		t.Errorf("expected 2 occurrences (one per file), got %d", len(*aesComp.Evidence.Occurrences))
	}
}

// ----- BOM construction tests -----

func TestNewBOM_Source(t *testing.T) {
	comps := []cdx.Component{
		{
			Type: cdx.ComponentTypeCryptographicAsset,
			Name: "AES",
			CryptoProperties: &cdx.CryptoProperties{
				AssetType: cdx.CryptoAssetTypeAlgorithm,
			},
		},
	}
	opts := &Options{
		Name:        "my-project",
		Group:       "com.example",
		Version:     "1.0.0",
		Description: "Test project",
		License:     "Apache-2.0",
	}
	bom := newBOM(comps, "my-project", "", opts)
	if bom.SerialNumber == "" {
		t.Error("SerialNumber should be set")
	}
	if bom.Metadata == nil || bom.Metadata.Timestamp == "" {
		t.Error("Metadata.Timestamp should be set")
	}
	if bom.Metadata.Lifecycles == nil || len(*bom.Metadata.Lifecycles) == 0 {
		t.Error("Metadata.Lifecycles should be set")
	} else if (*bom.Metadata.Lifecycles)[0].Phase != cdx.LifecyclePhaseBuild {
		t.Errorf("expected lifecycle phase 'build', got %s", (*bom.Metadata.Lifecycles)[0].Phase)
	}
	c := bom.Metadata.Component
	if c == nil {
		t.Fatal("Metadata.Component should be set")
	}
	if c.Name != "my-project" {
		t.Errorf("component name = %q, want %q", c.Name, "my-project")
	}
	if c.Group != "com.example" {
		t.Errorf("component group = %q, want %q", c.Group, "com.example")
	}
	if c.Version != "1.0.0" {
		t.Errorf("component version = %q, want %q", c.Version, "1.0.0")
	}
	if c.Description != "Test project" {
		t.Errorf("component description = %q, want %q", c.Description, "Test project")
	}
	if c.PackageURL == "" {
		t.Error("PackageURL should be set when group and version are provided")
	}
	if c.Licenses == nil {
		t.Error("Licenses should be set")
	}
	if bom.Components == nil || len(*bom.Components) != 1 {
		t.Error("expected 1 component")
	}
}

func TestNewBOM_Image(t *testing.T) {
	bom := newBOM(nil, "", "nginx:latest", &Options{})
	if bom.Metadata.Component == nil || bom.Metadata.Component.Name != "nginx:latest" {
		t.Error("Metadata.Component should reflect image name")
	}
	if bom.Metadata.Component.Type != cdx.ComponentTypeContainer {
		t.Errorf("expected container type, got %s", bom.Metadata.Component.Type)
	}
	if bom.Metadata.Lifecycles == nil {
		t.Error("Metadata.Lifecycles should be set")
	}
}

func TestBOMRef_MetadataComponent(t *testing.T) {
	cases := []struct {
		name    string
		opts    Options
		source  string
		wantRef string
	}{
		{
			name:    "purl when group and version present",
			opts:    Options{Group: "com.example", Version: "1.0.0"},
			source:  "myapp",
			wantRef: "pkg:generic/com.example/myapp@1.0.0",
		},
		{
			name:    "purl when only version present (no group)",
			opts:    Options{Version: "2.3.4"},
			source:  "myapp",
			wantRef: "pkg:generic/myapp@2.3.4",
		},
		{
			name:    "name only when no version",
			opts:    Options{},
			source:  "myapp",
			wantRef: "myapp",
		},
		{
			name:    "image name only",
			opts:    Options{},
			source:  "",
			wantRef: "nginx:latest",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			image := ""
			if tc.source == "" {
				image = "nginx:latest"
			}
			bom := newBOM(nil, tc.source, image, &tc.opts)
			if bom.Metadata == nil || bom.Metadata.Component == nil {
				t.Fatal("metadata.component must be set")
			}
			if bom.Metadata.Component.BOMRef == "" {
				t.Error("bom-ref must not be empty")
			}
			if bom.Metadata.Component.BOMRef != tc.wantRef {
				t.Errorf("bom-ref = %q, want %q", bom.Metadata.Component.BOMRef, tc.wantRef)
			}
		})
	}
}

func TestComponentCount(t *testing.T) {
	bom := &cdx.BOM{
		Components: &[]cdx.Component{
			{Type: cdx.ComponentTypeCryptographicAsset, Name: "AES"},
			{Type: cdx.ComponentTypeCryptographicAsset, Name: "RSA"},
			{Type: cdx.ComponentTypeLibrary, Name: "some-lib"},
		},
	}
	if got := ComponentCount(bom); got != 2 {
		t.Errorf("ComponentCount = %d, want 2", got)
	}
}

func TestComponentCount_NilComponents(t *testing.T) {
	bom := &cdx.BOM{}
	if got := ComponentCount(bom); got != 0 {
		t.Errorf("ComponentCount = %d, want 0", got)
	}
}

func TestEnforceLicenses(t *testing.T) {
	known := cdx.Licenses{cdx.LicenseChoice{License: &cdx.License{ID: "Apache-2.0"}}}
	bom := &cdx.BOM{
		Components: &[]cdx.Component{
			// crypto asset with no license → should get "unknown"
			{Type: cdx.ComponentTypeCryptographicAsset, Name: "AES"},
			// crypto asset with existing license → must not be overwritten
			{Type: cdx.ComponentTypeCryptographicAsset, Name: "RSA", Licenses: &known},
			// non-crypto component with no license → must not be touched
			{Type: cdx.ComponentTypeLibrary, Name: "some-lib"},
		},
	}
	enforceLicenses(bom)

	comps := *bom.Components
	// AES: should now have "unknown"
	if comps[0].Licenses == nil || len(*comps[0].Licenses) == 0 {
		t.Fatal("AES: expected Licenses to be set")
	}
	if id := (*comps[0].Licenses)[0].License.ID; id != "unknown" {
		t.Errorf("AES license = %q, want %q", id, "unknown")
	}
	// RSA: existing license must be preserved
	if id := (*comps[1].Licenses)[0].License.ID; id != "Apache-2.0" {
		t.Errorf("RSA license = %q, want %q", id, "Apache-2.0")
	}
	// some-lib: no license should have been added
	if comps[2].Licenses != nil {
		t.Error("some-lib: non-crypto component should not have a license added")
	}
}

func TestScanSource_ComponentAttributes(t *testing.T) {
	dir := t.TempDir()
	src := `package foo
import "crypto/sha256"
var _ = sha256.New
`
	if err := os.WriteFile(filepath.Join(dir, "hash.go"), []byte(src), 0600); err != nil {
		t.Fatal(err)
	}
	components, err := ScanSource(dir)
	if err != nil {
		t.Fatalf("ScanSource: %v", err)
	}
	if len(components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(components))
	}
	c := components[0]
	if c.Description == "" {
		t.Error("component Description should not be empty")
	}
	if c.Scope != cdx.ScopeRequired {
		t.Errorf("component Scope = %q, want %q", c.Scope, cdx.ScopeRequired)
	}
	if c.ExternalReferences == nil || len(*c.ExternalReferences) == 0 {
		t.Error("component ExternalReferences should be populated")
	}
	if c.Licenses == nil || len(*c.Licenses) == 0 {
		t.Error("component Licenses should be populated")
	} else if (*c.Licenses)[0].License == nil || (*c.Licenses)[0].License.ID != "BSD-3-Clause" {
		t.Errorf("component License ID = %q, want %q", (*c.Licenses)[0].License.ID, "BSD-3-Clause")
	}
}

// ----- knownPackages coverage test -----

func TestKnownPackages_AlgorithmPropertiesNotNil(t *testing.T) {
	for pkg, entry := range knownPackages {
		if entry.assetType == cdx.CryptoAssetTypeAlgorithm && entry.primitive == "" {
			t.Errorf("package %q: algorithm asset type but primitive is empty", pkg)
		}
	}
}

// ----- helpers -----

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
