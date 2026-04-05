// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of KubeArmor

package aibom

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	hfAPIBase    = "https://huggingface.co/api/models"
	hfWebBase    = "https://huggingface.co"
	hfAPITimeout = 30 * time.Second
)

// fetchModel retrieves model metadata from the HuggingFace API.
func fetchModel(modelID, token string) (*hfModelInfo, error) {
	// Normalise: strip leading "https://huggingface.co/" if someone passed a URL
	modelID = strings.TrimPrefix(modelID, "https://huggingface.co/")
	modelID = strings.Trim(modelID, "/")
	if modelID == "" {
		return nil, fmt.Errorf("model ID must not be empty")
	}

	url := fmt.Sprintf("%s/%s", hfAPIBase, modelID)

	client := &http.Client{Timeout: hfAPITimeout}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building HuggingFace API request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("querying HuggingFace API: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading HuggingFace API response: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("HuggingFace API: unauthorised — pass --token for private models")
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("model %q not found on HuggingFace", modelID)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HuggingFace API returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var info hfModelInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("parsing HuggingFace API response: %w", err)
	}

	// Ensure effectiveID is always set even if the API omits modelId.
	if info.ModelID == "" {
		info.ModelID = modelID
	}

	return &info, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// SPDX licence normalisation
// ──────────────────────────────────────────────────────────────────────────────

// spdxNormMap maps common HuggingFace licence strings (lower-cased) to their
// canonical SPDX identifiers.
var spdxNormMap = map[string]string{
	"apache-2.0":            "Apache-2.0",
	"apache-2":              "Apache-2.0",
	"apache 2.0":            "Apache-2.0",
	"mit":                   "MIT",
	"gpl-3.0":               "GPL-3.0-only",
	"gpl-3.0-only":          "GPL-3.0-only",
	"gpl-3.0-or-later":      "GPL-3.0-or-later",
	"gpl-2.0":               "GPL-2.0-only",
	"lgpl-3.0":              "LGPL-3.0-only",
	"lgpl-2.1":              "LGPL-2.1-only",
	"bsd-2-clause":          "BSD-2-Clause",
	"bsd-3-clause":          "BSD-3-Clause",
	"cc-by-4.0":             "CC-BY-4.0",
	"cc-by-sa-4.0":          "CC-BY-SA-4.0",
	"cc-by-nc-4.0":          "CC-BY-NC-4.0",
	"cc-by-nc-sa-4.0":       "CC-BY-NC-SA-4.0",
	"cc-by-nc-nd-4.0":       "CC-BY-NC-ND-4.0",
	"cc0-1.0":               "CC0-1.0",
	"cc":                    "CC0-1.0",
	"openrail":              "OpenRAIL",
	"openrail++":            "OpenRAIL++",
	"bigscience-openrail-m": "BigScience-OpenRAIL-M",
	"creativeml-openrail-m": "CreativeML-OpenRAIL-M",
	"llama2":                "Llama-2",
	"llama3":                "Llama-3",
	"gemma":                 "Gemma",
	"other":                 "LicenseRef-other",
	"unknown":               "LicenseRef-unknown",
	"":                      "LicenseRef-unknown",
}

// normaliseLicense returns the canonical SPDX identifier for the given raw
// licence string. If no mapping is found the original value is returned as-is.
func normaliseLicense(raw string) string {
	if canon, ok := spdxNormMap[strings.ToLower(strings.TrimSpace(raw))]; ok {
		return canon
	}
	return raw
}

// ──────────────────────────────────────────────────────────────────────────────
// Learning approach inference
// ──────────────────────────────────────────────────────────────────────────────

// inferApproach maps a HuggingFace pipeline_tag to a CycloneDX ML approach type.
func inferApproach(pipelineTag string) string {
	switch strings.ToLower(pipelineTag) {
	case "text-classification", "token-classification", "question-answering",
		"image-classification", "object-detection", "image-segmentation",
		"audio-classification", "automatic-speech-recognition", "table-question-answering",
		"visual-question-answering", "zero-shot-classification", "sentiment-analysis",
		"ner", "summarization", "translation":
		return "supervised"
	case "text-generation", "fill-mask", "text2text-generation",
		"image-to-text", "feature-extraction":
		return "self-supervised"
	case "unconditional-image-generation", "image-generation",
		"text-to-image", "text-to-audio", "text-to-video",
		"audio-to-audio", "image-to-image":
		return "self-supervised"
	case "clustering", "anomaly-detection":
		return "unsupervised"
	case "reinforcement-learning", "robotics":
		return "reinforcement-learning"
	default:
		return "supervised"
	}
}
