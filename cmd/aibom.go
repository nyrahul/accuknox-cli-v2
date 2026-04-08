// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of KubeArmor

package cmd

import (
	"fmt"

	"github.com/accuknox/accuknox-cli-v2/pkg/aibom"
	"github.com/spf13/cobra"
)

var aibomOpts aibom.Options
var bedrockOpts aibom.BedrockOptions

var aibomCmd = &cobra.Command{
	Use:   "aibom",
	Short: "Generate AI Bill of Materials (AIBOM)",
	Long: `Generate a CycloneDX-compliant AI Bill of Materials (AIBOM) that
inventories AI/ML model components including architecture, training datasets,
performance metrics, and licensing information.

Model metadata is fetched from the HuggingFace Hub API.`,
}

var aibomGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate AIBOM from a HuggingFace model",
	Long: `Fetch model metadata from the HuggingFace Hub and produce a
CycloneDX 1.6 AIBOM documenting the model's architecture, training datasets,
performance metrics, licensing, and external references.

Examples:
  knoxctl aibom generate --model google-bert/bert-base-uncased
  knoxctl aibom generate --model meta-llama/Llama-2-7b-hf --token $HF_TOKEN
  knoxctl aibom generate --model openai-community/gpt2 --format table
  knoxctl aibom generate --model mistralai/Mistral-7B-v0.1 --out aibom.json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		bom, err := aibom.Generate(&aibomOpts)
		if err != nil {
			return err
		}
		fmt.Printf("Found %d AI/ML model component(s)\n", aibom.ModelCount(bom))
		return aibom.Output(bom, &aibomOpts)
	},
}

var aibomBedrockCmd = &cobra.Command{
	Use:   "bedrock",
	Short: "Generate AIBOM from AWS Bedrock foundation models",
	Long: `Fetch model metadata from AWS Bedrock and produce a CycloneDX 1.6 AIBOM
documenting foundation models' capabilities, modalities, and licensing.

By default the standard AWS credential chain is used (environment variables,
~/.aws/credentials, IAM instance role).  Supply --access-key-id and
--secret-access-key to use explicit credentials instead.

Examples:
  knoxctl aibom bedrock --region us-east-1
  knoxctl aibom bedrock --region us-east-1 --model anthropic.claude-3-sonnet-20240229-v1:0
  knoxctl aibom bedrock --region us-east-1 --access-key-id AKIA... --secret-access-key ...`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Inherit shared metadata overrides from the persistent aibomCmd flags.
		bedrockOpts.Name = aibomOpts.Name
		bedrockOpts.Version = aibomOpts.Version
		bedrockOpts.Manufacturer = aibomOpts.Manufacturer
		bedrockOpts.OutputTo = aibomOpts.OutputTo
		bedrockOpts.Format = aibomOpts.Format

		bom, err := aibom.GenerateFromBedrock(&bedrockOpts)
		if err != nil {
			return err
		}
		fmt.Printf("Found %d AI/ML model component(s)\n", aibom.ModelCount(bom))
		return aibom.Output(bom, &aibomOpts)
	},
}

func init() {
	rootCmd.AddCommand(aibomCmd)
	aibomCmd.AddCommand(aibomGenerateCmd)
	aibomCmd.AddCommand(aibomBedrockCmd)

	// Required: HuggingFace model identifier
	aibomGenerateCmd.Flags().StringVar(&aibomOpts.ModelID, "model", "", "HuggingFace model identifier (e.g. google-bert/bert-base-uncased)")
	_ = aibomGenerateCmd.MarkFlagRequired("model")

	// Optional: auth token for private models
	aibomGenerateCmd.Flags().StringVar(&aibomOpts.Token, "token", "", "HuggingFace API token (required for private/gated models)")

	// Metadata overrides (persistent so future sub-commands inherit them)
	aibomCmd.PersistentFlags().StringVar(&aibomOpts.Name, "name", "", "Override model name in the AIBOM output")
	aibomCmd.PersistentFlags().StringVar(&aibomOpts.Version, "version", "", "Override model version (defaults to short git SHA from HuggingFace)")
	aibomCmd.PersistentFlags().StringVar(&aibomOpts.Manufacturer, "manufacturer", "", "Override manufacturer / supplier name")

	// Output flags
	aibomCmd.PersistentFlags().StringVar(&aibomOpts.OutputTo, "out", "", "Write AIBOM JSON to this file")
	aibomCmd.PersistentFlags().StringVar(&aibomOpts.Format, "format", "json", `Output format: "json" or "table"`)

	// Bedrock-specific flags
	aibomBedrockCmd.Flags().StringVar(&bedrockOpts.Region, "region", "", "AWS region (e.g. us-east-1)")
	_ = aibomBedrockCmd.MarkFlagRequired("region")
	aibomBedrockCmd.Flags().BoolVar(&bedrockOpts.UseDefaultCredentials, "use-default-credentials", false, "Use the default AWS credential chain (env vars / ~/.aws/credentials / IAM role)")
	aibomBedrockCmd.Flags().StringVar(&bedrockOpts.AccessKeyID, "access-key-id", "", "AWS access key ID (leave empty to use default credential chain)")
	aibomBedrockCmd.Flags().StringVar(&bedrockOpts.SecretAccessKey, "secret-access-key", "", "AWS secret access key")
	aibomBedrockCmd.Flags().StringVar(&bedrockOpts.SessionToken, "session-token", "", "AWS session token (optional)")
	aibomBedrockCmd.Flags().StringVar(&bedrockOpts.ModelID, "model", "", "Inventory a single Bedrock model ID (empty = all available models)")

	// Signing flags (only meaningful when --out is set)
	aibomCmd.PersistentFlags().BoolVar(&aibomOpts.Sign.Enabled, "sign", false, "Sign the output artifact with cosign after generation")
	aibomCmd.PersistentFlags().BoolVar(&aibomOpts.Sign.GenerateKey, "sign-generate-key", false, "Generate a new ECDSA P-256 key pair before signing")
	aibomCmd.PersistentFlags().StringVar(&aibomOpts.Sign.KeyRef, "sign-key", "", "Path to existing cosign private key (default: cosign.key)")
	aibomCmd.PersistentFlags().StringVar(&aibomOpts.Sign.KeyOut, "sign-key-out", "cosign", "Filename prefix for generated key pair (produces <prefix>.key / <prefix>.pub)")
	aibomCmd.PersistentFlags().StringVar(&aibomOpts.Sign.Password, "sign-key-password", "", "Passphrase for the signing key (empty = no passphrase)")
	aibomCmd.PersistentFlags().StringVar(&aibomOpts.Sign.SigOut, "sign-sig-out", "", "Path to write the signature (default: <out>.sig)")
}
