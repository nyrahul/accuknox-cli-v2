// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of KubeArmor

package cmd

import (
	"github.com/accuknox/accuknox-cli-v2/pkg/sign"
	"github.com/spf13/cobra"
)

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign and verify artifacts using cosign (ECDSA P-256)",
	Long: `Sign BOM artifacts and verify their signatures using the sigstore/cosign
library.  Keys are stored as standard PEM files compatible with the cosign CLI.`,
	// Skip k8s client initialisation — signing is standalone.
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
}

// ── sign artifact ──────────────────────────────────────────────────────────────

var signArtifactOpts sign.Options
var signArtifactPath string

var signArtifactCmd = &cobra.Command{
	Use:   "artifact",
	Short: "Sign a file with a cosign private key",
	Long: `Sign any file (e.g. a CBOM or AIBOM JSON) with an ECDSA P-256 private key.
The base-64 encoded signature is written to <file>.sig (or --sig-out).

Examples:
  # Generate a new key pair and sign
  knoxctl sign artifact --file cbom.json --generate-key

  # Use an existing key
  knoxctl sign artifact --file aibom.json --key cosign.key

  # Provide a key passphrase
  knoxctl sign artifact --file bom.json --key cosign.key --key-password secret`,
	RunE: func(cmd *cobra.Command, args []string) error {
		signArtifactOpts.Enabled = true
		return sign.Artifact(signArtifactPath, &signArtifactOpts)
	},
}

// ── sign verify ───────────────────────────────────────────────────────────────

var verifyArtifactPath string
var verifySigPath string
var verifyPubKeyPath string

var signVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a cosign signature over a file",
	Long: `Verify that a file's signature was produced by the private key
corresponding to the supplied public key.

Examples:
  knoxctl sign verify --file cbom.json --sig cbom.json.sig --pub cosign.pub`,
	RunE: func(cmd *cobra.Command, args []string) error {
		sig := verifySigPath
		if sig == "" {
			sig = verifyArtifactPath + ".sig"
		}
		return sign.Verify(verifyArtifactPath, sig, verifyPubKeyPath)
	},
}

func init() {
	rootCmd.AddCommand(signCmd)
	signCmd.AddCommand(signArtifactCmd)
	signCmd.AddCommand(signVerifyCmd)

	// sign artifact flags
	signArtifactCmd.Flags().StringVar(&signArtifactPath, "file", "", "Path to the file to sign")
	_ = signArtifactCmd.MarkFlagRequired("file")
	signArtifactCmd.Flags().BoolVar(&signArtifactOpts.GenerateKey, "generate-key", false, "Generate a new ECDSA P-256 key pair before signing")
	signArtifactCmd.Flags().StringVar(&signArtifactOpts.KeyRef, "key", "", "Path to existing cosign private key (default: cosign.key)")
	signArtifactCmd.Flags().StringVar(&signArtifactOpts.KeyOut, "key-out", "cosign", "Filename prefix for generated key pair (<prefix>.key / <prefix>.pub)")
	signArtifactCmd.Flags().StringVar(&signArtifactOpts.Password, "key-password", "", "Passphrase for the signing key (empty = no passphrase)")
	signArtifactCmd.Flags().StringVar(&signArtifactOpts.SigOut, "sig-out", "", "Path to write the signature (default: <file>.sig)")

	// sign verify flags
	signVerifyCmd.Flags().StringVar(&verifyArtifactPath, "file", "", "Path to the signed file")
	_ = signVerifyCmd.MarkFlagRequired("file")
	signVerifyCmd.Flags().StringVar(&verifySigPath, "sig", "", "Path to the signature file (default: <file>.sig)")
	signVerifyCmd.Flags().StringVar(&verifyPubKeyPath, "pub", "cosign.pub", "Path to the cosign public key")
}
