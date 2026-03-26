//go:build windows

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var imageScanCmd = &cobra.Command{
	Use:   "image-scan",
	Short: "scans vm container images",
	Long:  "Scans VM container images and sends back the result to saas",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("image-scan is not supported on Windows")
	},
}

func init() {
	rootCmd.AddCommand(imageScanCmd)
}
