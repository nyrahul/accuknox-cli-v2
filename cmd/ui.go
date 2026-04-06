// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of KubeArmor

package cmd

import (
	"fmt"

	"github.com/accuknox/accuknox-cli-v2/pkg/ui"
	"github.com/accuknox/accuknox-cli-v2/pkg/version"
	"github.com/spf13/cobra"
)

var uiAddr string
var uiPort int

var uiCmd = &cobra.Command{
	Use:   "ui",
	Short: "Open the knoxctl web UI in your default browser",
	Long:  `Start an embedded web UI server and open it in the default browser. Provides a graphical interface for BOM generation (SBOM, CBOM, AIBOM), VM onboarding, security probing, and container image scanning.`,
	// Override the root PersistentPreRunE to skip k8s client initialisation,
	// which is not needed for the standalone UI server.
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		ver := version.GitSummary
		if ver == "" {
			ver = "dev"
		}
		addr := uiAddr
		if cmd.Flags().Changed("port") {
			addr = fmt.Sprintf("0.0.0.0:%d", uiPort)
		}
		srv := ui.NewServer(addr, ver)
		return srv.Start()
	},
}

func init() {
	rootCmd.AddCommand(uiCmd)
	uiCmd.Flags().StringVar(&uiAddr, "addr", "0.0.0.0:10100", "Address and port for the UI server to listen on")
	uiCmd.Flags().IntVar(&uiPort, "port", 10100, "Port for the UI server to listen on (overrides --addr port)")
}
