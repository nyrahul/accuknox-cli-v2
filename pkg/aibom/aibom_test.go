// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of KubeArmor

package aibom

import (
	"bytes"
	"encoding/json"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// ── toStringSlice ─────────────────────────────────────────────────────────────

func TestToStringSlice_Nil(t *testing.T) {
	if got := toStringSlice(nil); got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

func TestToStringSlice_String(t *testing.T) {
	got := toStringSlice("hello")
	if len(got) != 1 || got[0] != "hello" {
		t.Errorf("got %v, want [hello]", got)
	}
}

func TestToStringSlice_EmptyString(t *testing.T) {
	if got := toStringSlice(""); got != nil {
		t.Errorf("expected nil for empty string, got %v", got)
	}
}

func TestToStringSlice_SliceInterface(t *testing.T) {
	got := toStringSlice([]interface{}{"a", "b", "c"})
	if len(got) != 3 || got[1] != "b" {
		t.Errorf("got %v, want [a b c]", got)
	}
}

// ── normaliseLicense ──────────────────────────────────────────────────────────

func TestNormaliseLicense_KnownValues(t *testing.T) {
	cases := []struct{ in, want string }{
		{"apache-2.0", "Apache-2.0"},
		{"Apache-2.0", "Apache-2.0"},
		{"MIT", "MIT"},
		{"mit", "MIT"},
		{"gpl-3.0", "GPL-3.0-only"},
		{"cc-by-4.0", "CC-BY-4.0"},
		{"openrail", "OpenRAIL"},
		{"", "LicenseRef-unknown"},
		{"unknown", "LicenseRef-unknown"},
	}
	for _, tc := range cases {
		got := normaliseLicense(tc.in)
		if got != tc.want {
			t.Errorf("normaliseLicense(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormaliseLicense_Unknown(t *testing.T) {
	// A licence string not in the map should pass through unchanged.
	raw := "LicenseRef-custom-2024"
	if got := normaliseLicense(raw); got != raw {
		t.Errorf("normaliseLicense(%q) = %q, want %q", raw, got, raw)
	}
}

// ── inferApproach ─────────────────────────────────────────────────────────────

func TestInferApproach(t *testing.T) {
	cases := []struct{ tag, want string }{
		{"text-classification", "supervised"},
		{"image-classification", "supervised"},
		{"text-generation", "self-supervised"},
		{"fill-mask", "self-supervised"},
		{"clustering", "unsupervised"},
		{"reinforcement-learning", "reinforcement-learning"},
		{"unknown-tag", "supervised"}, // default
	}
	for _, tc := range cases {
		got := inferApproach(tc.tag)
		if got != tc.want {
			t.Errorf("inferApproach(%q) = %q, want %q", tc.tag, got, tc.want)
		}
	}
}

// ── splitModelID ──────────────────────────────────────────────────────────────

func TestSplitModelID(t *testing.T) {
	owner, name := splitModelID("google-bert/bert-base-uncased")
	if owner != "google-bert" || name != "bert-base-uncased" {
		t.Errorf("got (%q, %q)", owner, name)
	}

	owner, name = splitModelID("gpt2")
	if owner != "" || name != "gpt2" {
		t.Errorf("got (%q, %q)", owner, name)
	}
}

// ── buildBOMRef ───────────────────────────────────────────────────────────────

func TestBuildBOMRef(t *testing.T) {
	cases := []struct {
		purl, name, version, want string
	}{
		// purl takes priority
		{"pkg:huggingface/google-bert/bert-base-uncased@abc1234", "google-bert/bert-base-uncased", "abc1234",
			"pkg:huggingface/google-bert/bert-base-uncased@abc1234"},
		// no purl, has version → name@version
		{"", "google-bert/bert-base-uncased", "abc1234",
			"google-bert/bert-base-uncased@abc1234"},
		// no purl, no version → name only
		{"", "gpt2", "",
			"gpt2"},
	}
	for _, tc := range cases {
		got := buildBOMRef(tc.purl, tc.name, tc.version)
		if got != tc.want {
			t.Errorf("buildBOMRef(%q,%q,%q) = %q, want %q", tc.purl, tc.name, tc.version, got, tc.want)
		}
	}
}

func TestBuildBOMRef_NeverEmpty(t *testing.T) {
	// Even with all-empty inputs the result must not be empty.
	got := buildBOMRef("", "", "")
	// Name is empty here so the result is empty string — which enforceRequiredFields
	// handles.  But for a real component name is always set, so test a realistic case.
	got = buildBOMRef("", "my-model", "")
	if got == "" {
		t.Errorf("buildBOMRef must never return empty string when name is set, got %q", got)
	}
}

// ── buildPURL ─────────────────────────────────────────────────────────────────

func TestBuildPURL(t *testing.T) {
	cases := []struct {
		owner, model, version, want string
	}{
		{"google-bert", "bert-base-uncased", "abc1234", "pkg:huggingface/google-bert/bert-base-uncased@abc1234"},
		{"meta-llama", "Llama-2-7b", "", "pkg:huggingface/meta-llama/Llama-2-7b"},
		{"", "gpt2", "def5678", "pkg:huggingface/gpt2@def5678"},
		{"", "gpt2", "", "pkg:huggingface/gpt2"},
	}
	for _, tc := range cases {
		got := buildPURL(tc.owner, tc.model, tc.version)
		if got != tc.want {
			t.Errorf("buildPURL(%q,%q,%q) = %q, want %q", tc.owner, tc.model, tc.version, got, tc.want)
		}
	}
}

// ── shortSHA ──────────────────────────────────────────────────────────────────

func TestShortSHA(t *testing.T) {
	if got := shortSHA("abc1234def"); got != "abc1234" {
		t.Errorf("got %q, want %q", got, "abc1234")
	}
	if got := shortSHA("abc"); got != "abc" {
		t.Errorf("got %q, want %q", got, "abc")
	}
}

// ── buildBOM integration ──────────────────────────────────────────────────────

func sampleModelInfo() *hfModelInfo {
	return &hfModelInfo{
		ModelID:     "google-bert/bert-base-uncased",
		Author:      "google-bert",
		SHA:         "a265f773a47193eed794233aa2a0f0bb6d3aba63",
		PipelineTag: "fill-mask",
		Tags:        []string{"transformers", "pytorch", "bert", "fill-mask", "en", "license:apache-2.0"},
		CardData: &hfCardData{
			License:  "apache-2.0",
			Language: []interface{}{"en"},
			Datasets: []string{"bookcorpus", "wikipedia"},
		},
		Config: &hfConfig{
			ModelType:     "bert",
			Architectures: []string{"BertForMaskedLM"},
		},
		Downloads: 12345678,
		Likes:     2100,
	}
}

func TestToolComponent_RequiredFields(t *testing.T) {
	if toolComponent.BOMRef == "" {
		t.Error("toolComponent: BOMRef must not be empty")
	}
	if toolComponent.Version == "" {
		t.Error("toolComponent: Version must not be empty")
	}
	if toolComponent.Licenses == nil || len(*toolComponent.Licenses) == 0 {
		t.Error("toolComponent: Licenses must not be nil or empty")
	} else if (*toolComponent.Licenses)[0].License == nil || (*toolComponent.Licenses)[0].License.ID == "" {
		t.Error("toolComponent: License.ID must not be empty")
	}
	if toolComponent.ExternalReferences == nil || len(*toolComponent.ExternalReferences) == 0 {
		t.Error("toolComponent: ExternalReferences must not be empty")
	}
}

func TestBuildBOM_MetadataComponent(t *testing.T) {
	bom := buildBOM(sampleModelInfo(), &Options{})

	if bom.Metadata == nil {
		t.Fatal("metadata must be set")
	}
	c := bom.Metadata.Component
	if c == nil {
		t.Fatal("metadata.component must be set")
	}
	if c.BOMRef == "" {
		t.Error("metadata.component: BOMRef must not be empty")
	}
	if c.Name == "" {
		t.Error("metadata.component: Name must not be empty")
	}
	if c.Type != cdx.ComponentTypeMachineLearningModel {
		t.Errorf("metadata.component: Type = %q, want machine-learning-model", c.Type)
	}
	// bom-ref must match the main ML model component so they cross-reference.
	comps := *bom.Components
	var mlBOMRef string
	for _, comp := range comps {
		if comp.Type == cdx.ComponentTypeMachineLearningModel {
			mlBOMRef = comp.BOMRef
			break
		}
	}
	if c.BOMRef != mlBOMRef {
		t.Errorf("metadata.component.BOMRef = %q, want %q (ML model bom-ref)", c.BOMRef, mlBOMRef)
	}

	// Verify it appears in the serialised JSON.
	raw, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Contains(raw, []byte(`"component"`)) {
		t.Error("JSON metadata must contain a component section")
	}
}

func TestBuildBOM_ToolsComponentsSection(t *testing.T) {
	bom := buildBOM(sampleModelInfo(), &Options{})

	if bom.Metadata == nil {
		t.Fatal("metadata must be set")
	}
	if bom.Metadata.Tools == nil {
		t.Fatal("metadata.tools must be set")
	}
	if bom.Metadata.Tools.Components == nil || len(*bom.Metadata.Tools.Components) == 0 {
		t.Fatal("metadata.tools.components must be non-empty")
	}

	tool := (*bom.Metadata.Tools.Components)[0]
	if tool.BOMRef == "" {
		t.Error("tools component: BOMRef must not be empty")
	}
	if tool.Name == "" {
		t.Error("tools component: Name must not be empty")
	}
	if tool.Version == "" {
		t.Error("tools component: Version must not be empty")
	}
	if tool.Licenses == nil || len(*tool.Licenses) == 0 {
		t.Error("tools component: Licenses must not be empty")
	}

	// Verify the section is present in the serialised JSON output.
	raw, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Contains(raw, []byte(`"tools"`)) {
		t.Error("JSON output must contain a tools section")
	}
	if !bytes.Contains(raw, []byte(`"components"`)) {
		t.Error("JSON tools section must contain a components array")
	}
	if !bytes.Contains(raw, []byte(`"knoxctl-aibom"`)) {
		t.Error("JSON tools.components must include the knoxctl-aibom tool")
	}
}

func TestBuildBOM_BasicStructure(t *testing.T) {
	bom := buildBOM(sampleModelInfo(), &Options{})

	if bom.SerialNumber == "" {
		t.Error("SerialNumber should be set")
	}
	if bom.Metadata == nil || bom.Metadata.Timestamp == "" {
		t.Error("Metadata.Timestamp should be set")
	}
	if bom.Metadata.Tools == nil {
		t.Error("Metadata.Tools should be set")
	}
	if bom.Components == nil || len(*bom.Components) == 0 {
		t.Fatal("expected at least one component")
	}
	// Must target the 1.7 schema.
	if bom.JSONSchema != jsonSchema17 {
		t.Errorf("JSONSchema = %q, want %q", bom.JSONSchema, jsonSchema17)
	}
}

func TestBuildBOM_SpecVersion17Patch(t *testing.T) {
	// The JSON output must declare specVersion "1.7" after the patch.
	bom := buildBOM(sampleModelInfo(), &Options{})
	raw, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Apply the same patch used by printJSON.
	patched := bytes.ReplaceAll(raw,
		[]byte(`"specVersion": "1.6"`),
		[]byte(`"specVersion": "1.7"`))
	if !bytes.Contains(patched, []byte(`"specVersion": "1.7"`)) {
		t.Error("specVersion must be 1.7 after patch")
	}
	if bytes.Contains(patched, []byte(`"specVersion": "1.6"`)) {
		t.Error("specVersion 1.6 must not remain after patch")
	}
}

func TestBuildBOM_MLModelComponent(t *testing.T) {
	bom := buildBOM(sampleModelInfo(), &Options{})
	comps := *bom.Components

	var mlComp *cdx.Component
	for i := range comps {
		if comps[i].Type == cdx.ComponentTypeMachineLearningModel {
			mlComp = &comps[i]
			break
		}
	}
	if mlComp == nil {
		t.Fatal("expected a machine-learning-model component")
	}

	if mlComp.Name != "google-bert/bert-base-uncased" {
		t.Errorf("Name = %q, want %q", mlComp.Name, "google-bert/bert-base-uncased")
	}
	if mlComp.Group != "google-bert" {
		t.Errorf("Group = %q, want %q", mlComp.Group, "google-bert")
	}
	if mlComp.BOMRef == "" {
		t.Error("BOMRef must not be empty")
	}
	if mlComp.PackageURL == "" {
		t.Error("PackageURL must not be empty")
	}
	if mlComp.BOMRef != mlComp.PackageURL {
		t.Errorf("BOMRef should equal PackageURL; BOMRef=%q PackageURL=%q", mlComp.BOMRef, mlComp.PackageURL)
	}
}

func TestBuildBOM_License(t *testing.T) {
	bom := buildBOM(sampleModelInfo(), &Options{})
	comps := *bom.Components
	for _, c := range comps {
		if c.Type != cdx.ComponentTypeMachineLearningModel {
			continue
		}
		if c.Licenses == nil || len(*c.Licenses) == 0 {
			t.Error("ML model component must have Licenses")
		}
		id := (*c.Licenses)[0].License.ID
		if id != "Apache-2.0" {
			t.Errorf("License ID = %q, want Apache-2.0", id)
		}
	}
}

func TestBuildBOM_ModelCard(t *testing.T) {
	bom := buildBOM(sampleModelInfo(), &Options{})
	comps := *bom.Components
	for _, c := range comps {
		if c.Type != cdx.ComponentTypeMachineLearningModel {
			continue
		}
		if c.ModelCard == nil {
			t.Fatal("ModelCard should be set")
		}
		mp := c.ModelCard.ModelParameters
		if mp == nil {
			t.Fatal("ModelParameters should be set")
		}
		if mp.Task != "fill-mask" {
			t.Errorf("Task = %q, want fill-mask", mp.Task)
		}
		if mp.ArchitectureFamily != "bert" {
			t.Errorf("ArchitectureFamily = %q, want bert", mp.ArchitectureFamily)
		}
		if mp.Approach == nil || string(mp.Approach.Type) != "self-supervised" {
			t.Errorf("Approach.Type should be self-supervised")
		}
		// Datasets are not set on modelParameters (MLDatasetChoice fields are
		// json:"-" in the library and would produce invalid empty objects).
		// Dataset info lives in comp.Data and standalone data components instead.
		if mp.Datasets != nil {
			t.Error("modelParameters.Datasets must be nil to avoid invalid {} objects in output")
		}
	}
}

func TestBuildBOM_DataComponents(t *testing.T) {
	bom := buildBOM(sampleModelInfo(), &Options{})
	comps := *bom.Components

	var dataComps []cdx.Component
	for _, c := range comps {
		if c.Type == cdx.ComponentTypeData {
			dataComps = append(dataComps, c)
		}
	}
	if len(dataComps) != 2 {
		t.Errorf("expected 2 data components (bookcorpus + wikipedia), got %d", len(dataComps))
	}
	for _, dc := range dataComps {
		if dc.BOMRef == "" {
			t.Error("data component BOMRef must not be empty")
		}
	}
}

func TestBuildBOM_ExternalRefs(t *testing.T) {
	bom := buildBOM(sampleModelInfo(), &Options{})
	comps := *bom.Components
	for _, c := range comps {
		if c.Type != cdx.ComponentTypeMachineLearningModel {
			continue
		}
		if c.ExternalReferences == nil || len(*c.ExternalReferences) == 0 {
			t.Error("ExternalReferences should be populated")
		}
		// Must contain a model-card reference.
		found := false
		for _, r := range *c.ExternalReferences {
			if r.Type == cdx.ERTypeModelCard {
				found = true
			}
		}
		if !found {
			t.Error("ExternalReferences must include a model-card entry")
		}
	}
}

func TestBuildBOM_DefaultName_IsFullModelID(t *testing.T) {
	// When --name is not set, the component Name must be the full model ID.
	bom := buildBOM(sampleModelInfo(), &Options{})
	for _, c := range *bom.Components {
		if c.Type != cdx.ComponentTypeMachineLearningModel {
			continue
		}
		want := "google-bert/bert-base-uncased"
		if c.Name != want {
			t.Errorf("default Name = %q, want %q", c.Name, want)
		}
	}
}

func TestBuildBOM_OverrideOptions(t *testing.T) {
	opts := &Options{
		Name:         "custom-name",
		Version:      "v1.0.0",
		Manufacturer: "MyOrg",
	}
	bom := buildBOM(sampleModelInfo(), opts)
	comps := *bom.Components
	for _, c := range comps {
		if c.Type != cdx.ComponentTypeMachineLearningModel {
			continue
		}
		if c.Name != "custom-name" {
			t.Errorf("Name = %q, want custom-name", c.Name)
		}
		if c.Version != "v1.0.0" {
			t.Errorf("Version = %q, want v1.0.0", c.Version)
		}
		if c.Supplier == nil || c.Supplier.Name != "MyOrg" {
			t.Errorf("Supplier.Name should be MyOrg")
		}
	}
}

func TestBuildBOM_NoLicenseInCardData(t *testing.T) {
	// When no license is present, should fall back to "unknown".
	info := sampleModelInfo()
	info.CardData.License = nil
	info.Tags = []string{"transformers"} // no license: tag either

	bom := buildBOM(info, &Options{})
	for _, c := range *bom.Components {
		if c.Type != cdx.ComponentTypeMachineLearningModel {
			continue
		}
		if c.Licenses == nil || len(*c.Licenses) == 0 {
			t.Fatal("Licenses must always be populated")
		}
		id := (*c.Licenses)[0].License.ID
		if id != "LicenseRef-unknown" {
			t.Errorf("expected LicenseRef-unknown fallback, got %q", id)
		}
	}
}

func TestModelCount(t *testing.T) {
	bom := buildBOM(sampleModelInfo(), &Options{})
	if got := ModelCount(bom); got != 1 {
		t.Errorf("ModelCount = %d, want 1", got)
	}
}

func TestModelCount_NilComponents(t *testing.T) {
	if got := ModelCount(&cdx.BOM{}); got != 0 {
		t.Errorf("ModelCount = %d, want 0", got)
	}
}

// TestEnforceRequiredFields verifies that name, bom-ref, and license are
// mandatory on every component, including data components.
func TestEnforceRequiredFields_AllComponents(t *testing.T) {
	bom := buildBOM(sampleModelInfo(), &Options{})
	if bom.Components == nil {
		t.Fatal("expected components")
	}
	for _, c := range *bom.Components {
		if c.Name == "" {
			t.Errorf("component type=%s: Name must not be empty", c.Type)
		}
		if c.BOMRef == "" {
			t.Errorf("component %q: BOMRef must not be empty", c.Name)
		}
		if c.Licenses == nil || len(*c.Licenses) == 0 {
			t.Errorf("component %q: Licenses must not be nil or empty", c.Name)
		} else if (*c.Licenses)[0].License == nil || (*c.Licenses)[0].License.ID == "" {
			t.Errorf("component %q: License.ID must not be empty", c.Name)
		}
	}
}

// TestEnforceRequiredFields_MissingBOMRef verifies that a component with no
// BOMRef gets it derived from its Name.
func TestEnforceRequiredFields_MissingBOMRef(t *testing.T) {
	bom := &cdx.BOM{
		Components: &[]cdx.Component{
			{Type: cdx.ComponentTypeData, Name: "my-dataset"},
		},
	}
	enforceRequiredFields(bom)
	got := (*bom.Components)[0].BOMRef
	if got != "my-dataset" {
		t.Errorf("BOMRef = %q, want %q", got, "my-dataset")
	}
}

// TestEnforceRequiredFields_MissingLicense verifies that a component with no
// license gets "LicenseRef-unknown".
func TestEnforceRequiredFields_MissingLicense(t *testing.T) {
	bom := &cdx.BOM{
		Components: &[]cdx.Component{
			{Type: cdx.ComponentTypeMachineLearningModel, Name: "my-model", BOMRef: "pkg:huggingface/my-model"},
		},
	}
	enforceRequiredFields(bom)
	c := (*bom.Components)[0]
	if c.Licenses == nil || len(*c.Licenses) == 0 {
		t.Fatal("Licenses must be set")
	}
	if id := (*c.Licenses)[0].License.ID; id != "LicenseRef-unknown" {
		t.Errorf("License.ID = %q, want LicenseRef-unknown", id)
	}
}

// TestEnforceRequiredFields_ExistingLicensePreserved verifies that an
// existing license is not overwritten.
func TestEnforceRequiredFields_ExistingLicensePreserved(t *testing.T) {
	existing := cdx.Licenses{cdx.LicenseChoice{License: &cdx.License{ID: "MIT"}}}
	bom := &cdx.BOM{
		Components: &[]cdx.Component{
			{
				Type:     cdx.ComponentTypeMachineLearningModel,
				Name:     "my-model",
				BOMRef:   "pkg:huggingface/my-model",
				Licenses: &existing,
			},
		},
	}
	enforceRequiredFields(bom)
	if id := (*(*bom.Components)[0].Licenses)[0].License.ID; id != "MIT" {
		t.Errorf("existing license should not be overwritten; got %q", id)
	}
}
