// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of KubeArmor

package aibom

// Options holds configuration for AIBOM generation.
type Options struct {
	// HuggingFace model identifier, e.g. "google-bert/bert-base-uncased"
	ModelID string

	// HuggingFace API token (optional; required for private models)
	Token string

	// Metadata overrides
	Name         string // override model name
	Version      string // override model version
	Manufacturer string // override manufacturer / supplier name

	// Output
	OutputTo string // write AIBOM JSON to this file instead of stdout
	Format   string // "json" or "table"
}

// ──────────────────────────────────────────────────────────────────────────────
// HuggingFace API response types
// ──────────────────────────────────────────────────────────────────────────────

// hfModelInfo is the response from GET https://huggingface.co/api/models/{id}.
type hfModelInfo struct {
	ModelID      string      `json:"modelId"`
	ID           string      `json:"id"`
	Author       string      `json:"author"`
	SHA          string      `json:"sha"`
	LastModified string      `json:"lastModified"`
	Tags         []string    `json:"tags"`
	PipelineTag  string      `json:"pipeline_tag"`
	CardData     *hfCardData `json:"cardData"`
	Siblings     []hfFile    `json:"siblings"`
	Config       *hfConfig   `json:"config"`
	Downloads    int         `json:"downloads"`
	Likes        int         `json:"likes"`
	SafeTensors  interface{} `json:"safetensors"`
}

// effectiveID returns the model identifier, preferring ModelID over ID.
func (m *hfModelInfo) effectiveID() string {
	if m.ModelID != "" {
		return m.ModelID
	}
	return m.ID
}

// hfCardData is the parsed YAML front-matter from the model card README.
type hfCardData struct {
	// License can be a single SPDX string or a list.
	License interface{} `json:"license"`

	// Language can be a single string or a list.
	Language interface{} `json:"language"`

	// Datasets lists training/evaluation dataset identifiers.
	Datasets []string `json:"datasets"`

	// Tags additional model card tags.
	Tags []string `json:"tags"`

	// PipelineTag overrides the top-level pipeline_tag when set.
	PipelineTag string `json:"pipeline_tag"`

	// BaseModel names the parent model when this is a fine-tune.
	BaseModel interface{} `json:"base_model"`

	// ModelIndex carries evaluation results from the model card.
	ModelIndex []hfModelIndex `json:"model-index"`

	// LibraryName e.g. "transformers", "diffusers".
	LibraryName string `json:"library_name"`

	// CO2EqEmissions can be a number or a nested object; we capture it as raw.
	CO2EqEmissions interface{} `json:"co2_eq_emissions"`

	// Inference disabled hint from model card.
	Inference string `json:"inference"`
}

// licenses returns the normalised SPDX identifiers from the card data.
func (c *hfCardData) licenses() []string {
	return toStringSlice(c.License)
}

// languages returns the list of language codes.
func (c *hfCardData) languages() []string {
	return toStringSlice(c.Language)
}

// baseModels returns the list of base model identifiers.
func (c *hfCardData) baseModels() []string {
	return toStringSlice(c.BaseModel)
}

// hfModelIndex holds the evaluation results block from the model card.
type hfModelIndex struct {
	Name    string     `json:"name"`
	Results []hfResult `json:"results"`
}

// hfResult holds a single evaluation result entry.
type hfResult struct {
	Task    hfResultTask    `json:"task"`
	Dataset hfResultDataset `json:"dataset"`
	Metrics []hfMetric      `json:"metrics"`
}

type hfResultTask struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

type hfResultDataset struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

type hfMetric struct {
	Type  string      `json:"type"`
	Value interface{} `json:"value"`
	Name  string      `json:"name"`
}

// hfFile represents a file entry in the model repository.
type hfFile struct {
	Rfilename string `json:"rfilename"`
	Size      int64  `json:"size"`
}

// hfConfig is the parsed config.json for the model.
type hfConfig struct {
	ModelType             string   `json:"model_type"`
	Architectures         []string `json:"architectures"`
	NumLabels             int      `json:"num_labels"`
	VocabSize             int      `json:"vocab_size"`
	MaxPositionEmbeddings int      `json:"max_position_embeddings"`
	HiddenSize            int      `json:"hidden_size"`
	NumAttentionHeads     int      `json:"num_attention_heads"`
	NumHiddenLayers       int      `json:"num_hidden_layers"`
	TorchDtype            string   `json:"torch_dtype"`
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

// toStringSlice normalises a JSON value that may be a single string or an
// array of strings into a consistent []string.
func toStringSlice(v interface{}) []string {
	if v == nil {
		return nil
	}
	switch t := v.(type) {
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return t
	}
	return nil
}
