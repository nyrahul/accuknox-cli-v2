// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of KubeArmor

// Package aibom generates AI Bill of Materials (AIBOM) documents compliant
// with CycloneDX 1.6. It fetches model metadata from the HuggingFace API and
// produces a machine-readable inventory of AI/ML model components including
// training datasets, architecture, licensing, and performance metrics.
package aibom

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"

	"github.com/accuknox/accuknox-cli-v2/pkg/sign"
)

const (
	// specVersion17 is the CycloneDX 1.7 specification version string.
	// The Go library (v0.9.3) only defines constants up to 1.6, so we set
	// the specVersion and $schema fields manually after marshaling.
	specVersion17 = "1.7"
	jsonSchema17  = "http://cyclonedx.org/schema/bom-1.7.schema.json"

	// toolVersion is the version stamped into the tool component entry.
	toolVersion = "1.0.0"
)

// toolComponent is stamped into the metadata.tools.components section of every
// AIBOM produced by knoxctl.  All fields required by the 1.7 schema (type,
// name) plus the recommended fields (bom-ref, version, licenses) are set.
var toolComponent = cdx.Component{
	BOMRef:    "pkg:generic/accuknox/knoxctl-aibom@" + toolVersion,
	Type:      cdx.ComponentTypeApplication,
	Publisher: "AccuKnox",
	Name:      "knoxctl-aibom",
	Version:   toolVersion,
	Licenses:  &cdx.Licenses{{License: &cdx.License{ID: "Apache-2.0"}}},
	ExternalReferences: &[]cdx.ExternalReference{
		{
			Type: cdx.ERTypeWebsite,
			URL:  "https://github.com/accuknox/accuknox-cli-v2",
		},
	},
}

// Generate fetches model metadata from HuggingFace and returns a CycloneDX BOM.
func Generate(opts *Options) (*cdx.BOM, error) {
	if opts.ModelID == "" {
		return nil, fmt.Errorf("--model is required")
	}

	info, err := fetchModel(opts.ModelID, opts.Token)
	if err != nil {
		return nil, err
	}

	return buildBOM(info, opts), nil
}

// Output writes the BOM to stdout or to opts.OutputTo.
func Output(bom *cdx.BOM, opts *Options) error {
	switch strings.ToLower(opts.Format) {
	case "table":
		return printTable(bom, opts)
	default:
		return printJSON(bom, opts)
	}
}

// ModelCount returns the number of machine-learning-model components in the BOM.
func ModelCount(bom *cdx.BOM) int {
	if bom.Components == nil {
		return 0
	}
	count := 0
	for _, c := range *bom.Components {
		if c.Type == cdx.ComponentTypeMachineLearningModel {
			count++
		}
	}
	return count
}

// ──────────────────────────────────────────────────────────────────────────────
// BOM construction
// ──────────────────────────────────────────────────────────────────────────────

func buildBOM(info *hfModelInfo, opts *Options) *cdx.BOM {
	bom := cdx.NewBOM()
	bom.SerialNumber = "urn:uuid:" + uuid.New().String()
	// Override to CycloneDX 1.7.  The library only supports up to 1.6; we
	// set JSONSchema here and patch specVersion in the JSON output.
	bom.JSONSchema = jsonSchema17

	// Build the main ML model component first so we can reference its
	// bom-ref and name in metadata.component.
	modelComp := buildModelComponent(info, opts)

	bom.Metadata = &cdx.Metadata{
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Lifecycles: &[]cdx.Lifecycle{{Phase: cdx.LifecyclePhaseBuild}},
		Tools: &cdx.ToolsChoice{
			Components: &[]cdx.Component{toolComponent},
		},
		// Component identifies the subject of this BOM (the AI model being
		// described), mirroring the pattern used by knoxctl-cbom.
		Component: &cdx.Component{
			BOMRef: modelComp.BOMRef,
			Type:   cdx.ComponentTypeMachineLearningModel,
			Name:   modelComp.Name,
		},
	}
	allComps := []cdx.Component{modelComp}
	allComps = append(allComps, buildDataComponents(info)...)
	bom.Components = &allComps

	// Guarantee name, bom-ref, and license are present on every component.
	enforceRequiredFields(bom)

	return bom
}

// enforceRequiredFields ensures that every component in the BOM carries the
// three mandatory fields: Name, BOMRef, and Licenses.  Missing licenses are
// filled in with "LicenseRef-unknown" so the field is never silently absent.
// A missing BOMRef is derived from the component name as a last resort.
func enforceRequiredFields(bom *cdx.BOM) {
	if bom.Components == nil {
		return
	}
	unknown := cdx.Licenses{cdx.LicenseChoice{License: &cdx.License{ID: "LicenseRef-unknown"}}}
	comps := *bom.Components
	for i := range comps {
		// BOMRef — must never be empty; fall back to name if purl was not set.
		if comps[i].BOMRef == "" {
			comps[i].BOMRef = comps[i].Name
		}
		// Licenses — every component must declare a license or "LicenseRef-unknown".
		if comps[i].Licenses == nil || len(*comps[i].Licenses) == 0 {
			comps[i].Licenses = &unknown
		}
	}
}

// buildModelComponent constructs the machine-learning-model CycloneDX component.
func buildModelComponent(info *hfModelInfo, opts *Options) cdx.Component {
	modelID := info.effectiveID()

	// Derive owner from "owner/model" format.  The full modelID is used as
	// the component name by default so it is immediately recognisable.
	owner, _ := splitModelID(modelID)

	// Default name is the full HuggingFace model ID (e.g. "google-bert/bert-base-uncased").
	name := modelID
	if opts.Name != "" {
		name = opts.Name
	}
	manufacturer := owner
	if opts.Manufacturer != "" {
		manufacturer = opts.Manufacturer
	}

	// Version: prefer the short SHA for reproducibility.
	version := shortSHA(info.SHA)
	if opts.Version != "" {
		version = opts.Version
	}

	// Package URL (purl): pkg:huggingface/{owner}/{model}@{sha}
	// The purl still uses owner+shortname so it remains a valid purl.
	_, shortName := splitModelID(modelID)
	if opts.Name != "" {
		shortName = opts.Name
	}
	purl := buildPURL(owner, shortName, version)

	// bom-ref must always be present.  Priority: purl → name@version → name.
	bomRef := buildBOMRef(purl, name, version)

	comp := cdx.Component{
		BOMRef:      bomRef,
		Type:        cdx.ComponentTypeMachineLearningModel,
		Name:        name,
		Group:       owner,
		Version:     version,
		PackageURL:  purl,
		Description: buildDescription(info),
	}

	// Supplier / manufacturer.
	if manufacturer != "" {
		comp.Supplier = &cdx.OrganizationalEntity{Name: manufacturer}
	}

	// Licenses from the model card.
	comp.Licenses = buildLicenses(info)

	// Tags as CycloneDX component tags.
	if len(info.Tags) > 0 {
		tags := info.Tags
		comp.Tags = &tags
	}

	// External references: repository, model card, downloads.
	comp.ExternalReferences = buildExternalRefs(modelID, info)

	// Static model attributes as CycloneDX properties.
	comp.Properties = buildProperties(info)

	// Software dependencies (frameworks) as nested library sub-components.
	comp.Components = buildSoftwareDependencies(info)

	// Model card with parameters, quantitative analysis, and considerations.
	comp.ModelCard = buildModelCard(info)

	// Inline data components for training datasets.
	comp.Data = buildInlineDatasets(info)

	return comp
}

// buildModelCard constructs the CycloneDX MLModelCard entry.
func buildModelCard(info *hfModelInfo) *cdx.MLModelCard {
	mc := &cdx.MLModelCard{}

	mc.ModelParameters = buildModelParameters(info)
	mc.QuantitativeAnalysis = buildQuantitativeAnalysis(info)
	mc.Considerations = buildConsiderations(info)

	// Return nil if nothing was populated to keep the JSON clean.
	if mc.ModelParameters == nil && mc.QuantitativeAnalysis == nil && mc.Considerations == nil {
		return nil
	}
	return mc
}

// buildModelParameters populates task, architecture, datasets, and I/O info.
func buildModelParameters(info *hfModelInfo) *cdx.MLModelParameters {
	params := &cdx.MLModelParameters{}
	empty := true

	// Task derived from pipeline_tag.
	task := info.PipelineTag
	if info.CardData != nil && info.CardData.PipelineTag != "" {
		task = info.CardData.PipelineTag
	}
	if task != "" {
		params.Task = task
		empty = false
	}

	// Architecture from config.json.
	if info.Config != nil {
		if info.Config.ModelType != "" {
			params.ArchitectureFamily = info.Config.ModelType
			empty = false
		}
		if len(info.Config.Architectures) > 0 {
			params.ModelArchitecture = info.Config.Architectures[0]
			empty = false
		}
	}

	// Learning approach inferred from pipeline tag.
	if task != "" {
		approachType := cdx.MLModelParametersApproachType(inferApproach(task))
		params.Approach = &cdx.MLModelParametersApproach{Type: approachType}
		empty = false
	}

	// Note: MLDatasetChoice fields are all tagged json:"-" in the library, so
	// we do not set params.Datasets here — doing so would produce invalid empty
	// objects {}.  Dataset information is instead carried by comp.Data (inline
	// ComponentData entries) and the standalone data-type components.

	// I/O format parameters derived from the pipeline task.
	if task != "" {
		ins, outs := inferModalities(task)
		if ins != nil {
			params.Inputs = &ins
			empty = false
		}
		if outs != nil {
			params.Outputs = &outs
			empty = false
		}
	}

	if empty {
		return nil
	}
	return params
}

// buildQuantitativeAnalysis extracts performance metrics from model-index results
// and adds architectural metrics from config.json.
func buildQuantitativeAnalysis(info *hfModelInfo) *cdx.MLQuantitativeAnalysis {
	var metrics []cdx.MLPerformanceMetric

	// Evaluation results from the model card model-index block.
	if info.CardData != nil {
		for _, entry := range info.CardData.ModelIndex {
			for _, result := range entry.Results {
				for _, m := range result.Metrics {
					if m.Value == nil {
						continue
					}
					metric := cdx.MLPerformanceMetric{
						Type:  m.Type,
						Value: fmt.Sprintf("%v", m.Value),
						Slice: result.Dataset.Name,
					}
					if metric.Type == "" {
						metric.Type = m.Name
					}
					metrics = append(metrics, metric)
				}
			}
		}
	}

	// Architectural metrics from config.json.
	if info.Config != nil {
		if info.Config.MaxPositionEmbeddings > 0 {
			metrics = append(metrics, cdx.MLPerformanceMetric{
				Type:  "maxInputTokens",
				Value: strconv.Itoa(info.Config.MaxPositionEmbeddings),
				Slice: "architecture",
			})
		}
		if info.Config.VocabSize > 0 {
			metrics = append(metrics, cdx.MLPerformanceMetric{
				Type:  "vocabSize",
				Value: strconv.Itoa(info.Config.VocabSize),
				Slice: "architecture",
			})
		}
		if info.Config.HiddenSize > 0 {
			metrics = append(metrics, cdx.MLPerformanceMetric{
				Type:  "hiddenSize",
				Value: strconv.Itoa(info.Config.HiddenSize),
				Slice: "architecture",
			})
		}
		if info.Config.NumHiddenLayers > 0 {
			metrics = append(metrics, cdx.MLPerformanceMetric{
				Type:  "numLayers",
				Value: strconv.Itoa(info.Config.NumHiddenLayers),
				Slice: "architecture",
			})
		}
		if info.Config.NumAttentionHeads > 0 {
			metrics = append(metrics, cdx.MLPerformanceMetric{
				Type:  "numAttentionHeads",
				Value: strconv.Itoa(info.Config.NumAttentionHeads),
				Slice: "architecture",
			})
		}
	}

	// Total parameter count from safetensors metadata.
	if totalParams := parseSafeTensors(info.SafeTensors); totalParams > 0 {
		metrics = append(metrics, cdx.MLPerformanceMetric{
			Type:  "totalParameters",
			Value: formatParamCount(totalParams),
			Slice: "architecture",
		})
	}

	if len(metrics) == 0 {
		return nil
	}
	return &cdx.MLQuantitativeAnalysis{PerformanceMetrics: &metrics}
}

// buildConsiderations builds the considerations block from tags and model card hints.
func buildConsiderations(info *hfModelInfo) *cdx.MLModelCardConsiderations {
	cons := &cdx.MLModelCardConsiderations{}
	empty := true

	// Derive use-cases from pipeline tag.
	task := info.PipelineTag
	if info.CardData != nil && info.CardData.PipelineTag != "" {
		task = info.CardData.PipelineTag
	}
	if task != "" {
		useCases := []string{formatTask(task)}
		cons.UseCases = &useCases
		empty = false
	}

	// Derive intended users from tags (e.g. "legal", "medical", "finance").
	users := inferUsers(info.Tags)
	if len(users) > 0 {
		cons.Users = &users
		empty = false
	}

	// Mark deprecated or discouraged use via technical limitations.
	limits := inferLimitations(info)
	if len(limits) > 0 {
		cons.TechnicalLimitations = &limits
		empty = false
	}

	// Performance tradeoffs based on model size and quantisation.
	tradeoffs := buildPerformanceTradeoffs(info)
	if len(tradeoffs) > 0 {
		cons.PerformanceTradeoffs = &tradeoffs
		empty = false
	}

	// Ethical and security considerations.
	ethics := buildEthicalConsiderations(info)
	if ethics != nil {
		cons.EthicalConsiderations = ethics
		empty = false
	}

	// Environmental / CO2 impact.
	envCons := buildEnvironmentalConsiderations(info)
	if envCons != nil {
		cons.EnvironmentalConsiderations = envCons
		empty = false
	}

	if empty {
		return nil
	}
	return cons
}

// buildLicenses builds the CycloneDX Licenses list from model card license data.
func buildLicenses(info *hfModelInfo) *cdx.Licenses {
	var rawLicenses []string

	if info.CardData != nil {
		rawLicenses = info.CardData.licenses()
	}

	// Fallback: scan tags for licence hints (e.g. "license:mit").
	if len(rawLicenses) == 0 {
		for _, tag := range info.Tags {
			if strings.HasPrefix(tag, "license:") {
				rawLicenses = append(rawLicenses, strings.TrimPrefix(tag, "license:"))
			}
		}
	}

	if len(rawLicenses) == 0 {
		rawLicenses = []string{"unknown"}
	}

	licenses := make(cdx.Licenses, 0, len(rawLicenses))
	for _, raw := range rawLicenses {
		id := normaliseLicense(raw)
		licenses = append(licenses, cdx.LicenseChoice{License: &cdx.License{ID: id}})
	}
	return &licenses
}

// buildExternalRefs builds the list of external references for the component.
func buildExternalRefs(modelID string, info *hfModelInfo) *[]cdx.ExternalReference {
	refs := []cdx.ExternalReference{
		{
			Type: cdx.ERTypeWebsite,
			URL:  fmt.Sprintf("%s/%s", hfWebBase, modelID),
		},
		{
			Type:    cdx.ERTypeModelCard,
			URL:     fmt.Sprintf("%s/%s/blob/main/README.md", hfWebBase, modelID),
			Comment: "HuggingFace model card",
		},
		{
			Type: cdx.ERTypeVCS,
			URL:  fmt.Sprintf("%s/%s", hfWebBase, modelID),
		},
	}

	// Direct download / API endpoint.
	refs = append(refs, cdx.ExternalReference{
		Type:    cdx.ERTypeDistribution,
		URL:     fmt.Sprintf("%s/api/models/%s", hfWebBase, modelID),
		Comment: "HuggingFace model API",
	})

	// Base model back-reference.
	if info.CardData != nil {
		for _, base := range info.CardData.baseModels() {
			refs = append(refs, cdx.ExternalReference{
				Type:    cdx.ERTypeOther,
				URL:     fmt.Sprintf("%s/%s", hfWebBase, base),
				Comment: "base model",
			})
		}
	}

	return &refs
}

// buildDataComponents builds standalone data-type components for training datasets.
func buildDataComponents(info *hfModelInfo) []cdx.Component {
	if info.CardData == nil || len(info.CardData.Datasets) == 0 {
		return nil
	}

	comps := make([]cdx.Component, 0, len(info.CardData.Datasets))
	for _, ds := range info.CardData.Datasets {
		dsURL := fmt.Sprintf("https://huggingface.co/datasets/%s", ds)
		comp := cdx.Component{
			BOMRef:      "dataset/" + ds,
			Type:        cdx.ComponentTypeData,
			Name:        ds,
			Description: "Training / evaluation dataset",
			ExternalReferences: &[]cdx.ExternalReference{
				{Type: cdx.ERTypeWebsite, URL: dsURL},
			},
		}
		comps = append(comps, comp)
	}
	return comps
}

// buildInlineDatasets builds ComponentData entries that live inside the model
// component's Data field (separate from the top-level data components).
func buildInlineDatasets(info *hfModelInfo) *[]cdx.ComponentData {
	if info.CardData == nil || len(info.CardData.Datasets) == 0 {
		return nil
	}

	data := make([]cdx.ComponentData, 0, len(info.CardData.Datasets))
	for _, ds := range info.CardData.Datasets {
		data = append(data, cdx.ComponentData{
			BOMRef:         "dataset/" + ds,
			Type:           cdx.ComponentDataTypeDataset,
			Name:           ds,
			Description:    "Training / evaluation dataset",
			Classification: "training",
			Contents: &cdx.ComponentDataContents{
				URL: fmt.Sprintf("https://huggingface.co/datasets/%s", ds),
			},
		})
	}
	return &data
}

// ──────────────────────────────────────────────────────────────────────────────
// Output
// ──────────────────────────────────────────────────────────────────────────────

func printJSON(bom *cdx.BOM, opts *Options) error {
	data, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling AIBOM: %w", err)
	}
	// The library serialises specVersion as "1.6" (no 1.7 constant exists yet).
	// Patch it to "1.7" so the output validates against the 1.7 schema.
	data = bytes.ReplaceAll(data,
		[]byte(`"specVersion": "1.6"`),
		[]byte(`"specVersion": "`+specVersion17+`"`))

	if opts.OutputTo != "" {
		if err := os.WriteFile(opts.OutputTo, data, 0600); err != nil {
			return fmt.Errorf("writing AIBOM to %s: %w", opts.OutputTo, err)
		}
		fmt.Printf("AIBOM written to %s\n", opts.OutputTo)
		return sign.Artifact(opts.OutputTo, &opts.Sign)
	}
	fmt.Println(string(data))
	return nil
}

func printTable(bom *cdx.BOM, opts *Options) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	defer w.Flush()

	fmt.Fprintln(w, "MODEL\tGROUP\tVERSION\tTASK\tARCHITECTURE\tLICENSE")
	fmt.Fprintln(w, "-----\t-----\t-------\t----\t------------\t-------")

	if bom.Components == nil {
		return nil
	}
	for _, c := range *bom.Components {
		if c.Type != cdx.ComponentTypeMachineLearningModel {
			continue
		}
		task := ""
		arch := ""
		if c.ModelCard != nil && c.ModelCard.ModelParameters != nil {
			task = c.ModelCard.ModelParameters.Task
			arch = c.ModelCard.ModelParameters.ArchitectureFamily
			if c.ModelCard.ModelParameters.ModelArchitecture != "" {
				arch = c.ModelCard.ModelParameters.ModelArchitecture
			}
		}
		license := ""
		if c.Licenses != nil && len(*c.Licenses) > 0 {
			lics := make([]string, 0, len(*c.Licenses))
			for _, lc := range *c.Licenses {
				if lc.License != nil {
					lics = append(lics, lc.License.ID)
				}
			}
			license = strings.Join(lics, ", ")
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			c.Name, c.Group, c.Version, task, arch, license)
	}

	if opts.OutputTo != "" {
		fmt.Printf("\n(use --format json to save full AIBOM to %s)\n", opts.OutputTo)
	}
	return nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Small helpers
// ──────────────────────────────────────────────────────────────────────────────

// splitModelID splits "owner/model" into ("owner", "model").
// For models without an owner returns ("", modelID).
func splitModelID(modelID string) (owner, name string) {
	parts := strings.SplitN(modelID, "/", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "", modelID
}

// shortSHA returns the first 7 characters of a git SHA, or the whole string.
func shortSHA(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}

// buildBOMRef derives a mandatory bom-ref for the component.
// Priority: purl (stable, globally unique) → name@version → name.
// The returned value is guaranteed to be non-empty.
func buildBOMRef(purl, name, version string) string {
	switch {
	case purl != "":
		return purl
	case version != "":
		return name + "@" + version
	default:
		return name
	}
}

// buildPURL builds a Package URL for a HuggingFace model.
func buildPURL(owner, model, version string) string {
	if owner != "" {
		if version != "" {
			return fmt.Sprintf("pkg:huggingface/%s/%s@%s", owner, model, version)
		}
		return fmt.Sprintf("pkg:huggingface/%s/%s", owner, model)
	}
	if version != "" {
		return fmt.Sprintf("pkg:huggingface/%s@%s", model, version)
	}
	return fmt.Sprintf("pkg:huggingface/%s", model)
}

// buildDescription builds a human-readable description from available metadata.
func buildDescription(info *hfModelInfo) string {
	parts := []string{}
	if info.PipelineTag != "" {
		parts = append(parts, fmt.Sprintf("Task: %s", formatTask(info.PipelineTag)))
	}
	if info.Config != nil && info.Config.ModelType != "" {
		parts = append(parts, fmt.Sprintf("Architecture: %s", info.Config.ModelType))
	}
	if info.Downloads > 0 {
		parts = append(parts, fmt.Sprintf("Downloads: %d", info.Downloads))
	}
	if info.Likes > 0 {
		parts = append(parts, fmt.Sprintf("Likes: %d", info.Likes))
	}
	if len(parts) == 0 {
		return fmt.Sprintf("HuggingFace model: %s", info.effectiveID())
	}
	return strings.Join(parts, ". ")
}

// formatTask converts a pipeline_tag slug to a readable string.
func formatTask(tag string) string {
	return strings.ReplaceAll(tag, "-", " ")
}

// inferUsers returns a list of intended user types inferred from model tags.
func inferUsers(tags []string) []string {
	domainTags := map[string]string{
		"legal":    "Legal professionals",
		"medical":  "Medical / healthcare practitioners",
		"finance":  "Finance / banking professionals",
		"biology":  "Researchers in biology / life sciences",
		"code":     "Software developers",
		"math":     "Researchers / educators in mathematics",
		"science":  "Scientific researchers",
		"security": "Security practitioners",
	}
	seen := map[string]bool{}
	var users []string
	for _, tag := range tags {
		lower := strings.ToLower(tag)
		for key, label := range domainTags {
			if strings.Contains(lower, key) && !seen[label] {
				users = append(users, label)
				seen[label] = true
			}
		}
	}
	return users
}

// inferLimitations returns known technical limitations based on model metadata.
func inferLimitations(info *hfModelInfo) []string {
	var limits []string
	for _, tag := range info.Tags {
		lower := strings.ToLower(tag)
		if strings.Contains(lower, "deprecated") {
			limits = append(limits, "Model is deprecated; migration to a newer version is recommended")
		}
		if strings.Contains(lower, "not-for-all-audiences") {
			limits = append(limits, "Not suitable for all audiences")
		}
	}
	if info.CardData != nil && strings.ToLower(info.CardData.Inference) == "false" {
		limits = append(limits, "Direct inference not recommended by the model author")
	}
	return limits
}

// ──────────────────────────────────────────────────────────────────────────────
// Rich enrichment helpers
// ──────────────────────────────────────────────────────────────────────────────

// parseSafeTensors extracts the total parameter count from the safetensors metadata.
// HuggingFace returns this as {"total": N, ...}. Returns 0 if unavailable.
func parseSafeTensors(raw interface{}) int64 {
	if raw == nil {
		return 0
	}
	m, ok := raw.(map[string]interface{})
	if !ok {
		return 0
	}
	if v, ok := m["total"].(float64); ok && v > 0 {
		return int64(v)
	}
	return 0
}

// bytesPerParam returns the memory cost per parameter for a given dtype.
func bytesPerParam(dtype string) float64 {
	switch strings.ToLower(dtype) {
	case "float16", "bfloat16", "fp16", "bf16":
		return 2.0
	case "float8", "fp8", "int8":
		return 1.0
	case "int4", "4bit", "nf4":
		return 0.5
	default: // float32 / unknown
		return 4.0
	}
}

// formatParamCount formats a parameter count as a human-readable string, e.g. "7.0B", "125M".
func formatParamCount(n int64) string {
	switch {
	case n >= 1_000_000_000:
		return fmt.Sprintf("%.1fB", float64(n)/1_000_000_000)
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	default:
		return fmt.Sprintf("%d", n)
	}
}

// isGated reports whether a model has restricted access based on the HuggingFace gated field.
func isGated(gated interface{}) bool {
	if gated == nil {
		return false
	}
	switch v := gated.(type) {
	case bool:
		return v
	case string:
		return v != "" && v != "false"
	}
	return false
}

// co2Detail holds parsed CO2 emissions information from the HuggingFace model card.
type co2Detail struct {
	KgCO2Eq              float64
	Source               string
	TrainingType         string
	GeographicalLocation string
	HardwareUsed         string
}

// parseCO2Detail parses the co2_eq_emissions card field, which can be a bare number
// (kg CO2 equivalent) or an object with structured fields.
func parseCO2Detail(raw interface{}) *co2Detail {
	if raw == nil {
		return nil
	}
	d := &co2Detail{}
	switch v := raw.(type) {
	case float64:
		if v <= 0 {
			return nil
		}
		d.KgCO2Eq = v
		return d
	case map[string]interface{}:
		if e, ok := v["emissions"].(float64); ok {
			d.KgCO2Eq = e
		}
		if s, ok := v["source"].(string); ok {
			d.Source = s
		}
		if t, ok := v["training_type"].(string); ok {
			d.TrainingType = t
		}
		if l, ok := v["geographical_location"].(string); ok {
			d.GeographicalLocation = l
		}
		if h, ok := v["hardware_used"].(string); ok {
			d.HardwareUsed = h
		}
		if d.KgCO2Eq <= 0 {
			return nil
		}
		return d
	}
	return nil
}

// containsAny reports whether s contains any of the given substrings.
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// inferModalities maps a HuggingFace pipeline_tag to CycloneDX I/O format parameters.
func inferModalities(task string) (inputs, outputs []cdx.MLInputOutputParameters) {
	task = strings.ToLower(task)
	switch {
	case containsAny(task, "text-generation", "text2text-generation", "translation",
		"summarization", "fill-mask", "text-classification", "token-classification",
		"question-answering", "sentence-similarity", "zero-shot-classification",
		"table-question-answering", "conversational"):
		return []cdx.MLInputOutputParameters{{Format: "text"}},
			[]cdx.MLInputOutputParameters{{Format: "text"}}
	case containsAny(task, "image-classification", "object-detection", "image-segmentation",
		"zero-shot-image-classification", "depth-estimation"):
		return []cdx.MLInputOutputParameters{{Format: "image"}},
			[]cdx.MLInputOutputParameters{{Format: "text"}}
	case containsAny(task, "text-to-image", "image-generation", "unconditional-image-generation"):
		return []cdx.MLInputOutputParameters{{Format: "text"}},
			[]cdx.MLInputOutputParameters{{Format: "image"}}
	case containsAny(task, "image-to-text", "visual-question-answering", "document-question-answering"):
		return []cdx.MLInputOutputParameters{{Format: "image"}, {Format: "text"}},
			[]cdx.MLInputOutputParameters{{Format: "text"}}
	case containsAny(task, "automatic-speech-recognition", "audio-classification"):
		return []cdx.MLInputOutputParameters{{Format: "audio"}},
			[]cdx.MLInputOutputParameters{{Format: "text"}}
	case containsAny(task, "text-to-speech", "text-to-audio"):
		return []cdx.MLInputOutputParameters{{Format: "text"}},
			[]cdx.MLInputOutputParameters{{Format: "audio"}}
	case containsAny(task, "audio-to-audio"):
		return []cdx.MLInputOutputParameters{{Format: "audio"}},
			[]cdx.MLInputOutputParameters{{Format: "audio"}}
	case containsAny(task, "feature-extraction", "embedding"):
		return []cdx.MLInputOutputParameters{{Format: "text"}},
			[]cdx.MLInputOutputParameters{{Format: "vector"}}
	case containsAny(task, "image-to-image"):
		return []cdx.MLInputOutputParameters{{Format: "image"}},
			[]cdx.MLInputOutputParameters{{Format: "image"}}
	case containsAny(task, "reinforcement-learning", "robotics"):
		return []cdx.MLInputOutputParameters{{Format: "state"}},
			[]cdx.MLInputOutputParameters{{Format: "action"}}
	}
	return nil, nil
}

// buildProperties builds a CycloneDX property list from model metadata.
func buildProperties(info *hfModelInfo) *[]cdx.Property {
	var props []cdx.Property
	add := func(name, value string) {
		if value != "" {
			props = append(props, cdx.Property{Name: name, Value: value})
		}
	}

	// Release / modification date
	if info.LastModified != "" {
		add("releaseDate", info.LastModified)
	}
	if info.CreatedAt != "" {
		add("createdAt", info.CreatedAt)
	}

	// Framework / library (primary dependency)
	if info.CardData != nil && info.CardData.LibraryName != "" {
		add("framework", info.CardData.LibraryName)
	}

	// Architecture from config.json
	if info.Config != nil {
		if info.Config.MaxPositionEmbeddings > 0 {
			add("maxInputTokens", strconv.Itoa(info.Config.MaxPositionEmbeddings))
		}
		if info.Config.VocabSize > 0 {
			add("vocabSize", strconv.Itoa(info.Config.VocabSize))
		}
		if info.Config.HiddenSize > 0 {
			add("hiddenSize", strconv.Itoa(info.Config.HiddenSize))
		}
		if info.Config.NumHiddenLayers > 0 {
			add("numLayers", strconv.Itoa(info.Config.NumHiddenLayers))
		}
		if info.Config.NumAttentionHeads > 0 {
			add("numAttentionHeads", strconv.Itoa(info.Config.NumAttentionHeads))
		}
		if info.Config.TorchDtype != "" {
			add("precision", info.Config.TorchDtype)
		}
	}

	// Total parameter count and estimated VRAM from safetensors
	totalParams := parseSafeTensors(info.SafeTensors)
	if totalParams > 0 {
		add("totalParameters", formatParamCount(totalParams))
		dtype := ""
		if info.Config != nil {
			dtype = info.Config.TorchDtype
		}
		bpp := bytesPerParam(dtype)
		// Add ~20% overhead for KV cache and activations.
		vramGB := float64(totalParams) * bpp / (1024 * 1024 * 1024) * 1.2
		add("minVRAMGB", fmt.Sprintf("%.1f", vramGB))
	}

	// Hardware info from CO2 emissions metadata
	if info.CardData != nil {
		if d := parseCO2Detail(info.CardData.CO2EqEmissions); d != nil {
			add("trainingHardware", d.HardwareUsed)
			add("trainingLocation", d.GeographicalLocation)
		}
	}

	// Access control
	if isGated(info.Gated) {
		add("accessControl", "gated")
	}

	// Community metrics
	if info.Downloads > 0 {
		add("downloadCount", strconv.Itoa(info.Downloads))
	}
	if info.Likes > 0 {
		add("likeCount", strconv.Itoa(info.Likes))
	}

	if len(props) == 0 {
		return nil
	}
	return &props
}

// buildSoftwareDependencies returns nested library components for frameworks inferred
// from the model card and tags.
func buildSoftwareDependencies(info *hfModelInfo) *[]cdx.Component {
	seen := map[string]bool{}
	var deps []cdx.Component

	addDep := func(name string) {
		if name != "" && !seen[name] {
			seen[name] = true
			deps = append(deps, cdx.Component{
				BOMRef: "dep/library/" + name,
				Type:   cdx.ComponentTypeLibrary,
				Name:   name,
			})
		}
	}

	// Primary framework from model card
	if info.CardData != nil && info.CardData.LibraryName != "" {
		addDep(info.CardData.LibraryName)
	}

	// Additional frameworks inferred from tags
	frameworkTags := []string{
		"pytorch", "tensorflow", "jax", "keras",
		"onnx", "gguf", "mlx", "llama.cpp",
	}
	for _, tag := range info.Tags {
		lower := strings.ToLower(tag)
		for _, fw := range frameworkTags {
			if strings.Contains(lower, fw) {
				addDep(fw)
			}
		}
	}

	if len(deps) == 0 {
		return nil
	}
	return &deps
}

// buildEthicalConsiderations builds ethical/security considerations from model metadata.
func buildEthicalConsiderations(info *hfModelInfo) *[]cdx.MLModelCardEthicalConsideration {
	var ethics []cdx.MLModelCardEthicalConsideration
	seen := map[string]bool{}

	add := func(name, mitigation string) {
		if !seen[name] {
			seen[name] = true
			ethics = append(ethics, cdx.MLModelCardEthicalConsideration{
				Name:               name,
				MitigationStrategy: mitigation,
			})
		}
	}

	// Gated / restricted access
	if isGated(info.Gated) {
		add("Restricted Access",
			"Model requires HuggingFace authorisation; accept the model terms or contact the author to gain access")
	}

	// Inference disabled by author
	if info.CardData != nil && strings.ToLower(info.CardData.Inference) == "false" {
		add("Direct Inference Discouraged",
			"The model author recommends against direct inference; consult model documentation for intended usage patterns")
	}

	// Content and safety tags
	for _, tag := range info.Tags {
		lower := strings.ToLower(tag)
		switch {
		case strings.Contains(lower, "has-bias") || lower == "bias":
			add("Potential Bias",
				"Model may reflect biases present in training data; evaluate outputs before deployment in sensitive contexts")
		case strings.Contains(lower, "adult-only") || strings.Contains(lower, "not-for-all-audiences"):
			add("Adult / Restricted Content",
				"Restrict deployment to appropriate audiences; implement content-filtering controls")
		case strings.Contains(lower, "medical") || strings.Contains(lower, "clinical") || strings.Contains(lower, "health"):
			add("Medical Use Caution",
				"Outputs must not replace professional medical advice; involve qualified healthcare providers")
		case strings.Contains(lower, "legal"):
			add("Legal Use Caution",
				"Outputs must not replace professional legal advice; consult a qualified legal professional")
		case strings.Contains(lower, "financial") || strings.Contains(lower, "finance"):
			add("Financial Use Caution",
				"Outputs must not replace professional financial advice; consult a qualified financial advisor")
		case strings.Contains(lower, "toxic") || strings.Contains(lower, "hate-speech"):
			add("Toxic Content Risk",
				"Model may generate harmful content; implement output filtering and monitoring in production")
		}
	}

	if len(ethics) == 0 {
		return nil
	}
	return &ethics
}

// buildEnvironmentalConsiderations extracts CO2 / energy information from the model card.
func buildEnvironmentalConsiderations(info *hfModelInfo) *cdx.MLModelCardEnvironmentalConsiderations {
	if info.CardData == nil {
		return nil
	}
	d := parseCO2Detail(info.CardData.CO2EqEmissions)
	if d == nil {
		return nil
	}

	var props []cdx.Property
	add := func(name, value string) {
		if value != "" {
			props = append(props, cdx.Property{Name: name, Value: value})
		}
	}

	add("co2EqKg", fmt.Sprintf("%.4f", d.KgCO2Eq))
	add("co2Source", d.Source)
	add("trainingType", d.TrainingType)
	add("trainingLocation", d.GeographicalLocation)
	add("trainingHardware", d.HardwareUsed)

	if len(props) == 0 {
		return nil
	}
	return &cdx.MLModelCardEnvironmentalConsiderations{Properties: &props}
}

// buildPerformanceTradeoffs returns a list of known performance tradeoffs inferred from
// model size and quantisation settings.
func buildPerformanceTradeoffs(info *hfModelInfo) []string {
	var tradeoffs []string

	totalParams := parseSafeTensors(info.SafeTensors)
	if totalParams >= 7_000_000_000 {
		tradeoffs = append(tradeoffs, fmt.Sprintf(
			"Large model (%s parameters) has high inference latency and memory requirements",
			formatParamCount(totalParams)))
	} else if totalParams >= 1_000_000_000 {
		tradeoffs = append(tradeoffs, fmt.Sprintf(
			"Model (%s parameters) requires moderate compute for inference",
			formatParamCount(totalParams)))
	}

	if info.Config != nil {
		switch strings.ToLower(info.Config.TorchDtype) {
		case "int8":
			tradeoffs = append(tradeoffs, "INT8 quantisation reduces memory footprint at the cost of slight accuracy degradation")
		case "int4", "4bit", "nf4":
			tradeoffs = append(tradeoffs, "4-bit quantisation significantly reduces memory usage but may noticeably affect output quality")
		}
	}

	return tradeoffs
}
