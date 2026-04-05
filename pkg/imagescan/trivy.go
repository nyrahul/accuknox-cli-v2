package imagescan

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/accuknox/accuknox-cli-v2/pkg/tools"
)

// trivyToolName is the tool name as declared in tools.yaml.
const trivyToolName = "imgscan"

// resolveTrivyBin returns the path to the trivy binary, extracted from the
// embedded binary built from the trivy submodule during `make prebuild`.
func resolveTrivyBin() (string, error) {
	cfg, err := tools.Load()
	if err != nil {
		return "", fmt.Errorf("loading tools config: %w", err)
	}
	for i := range cfg.Tools {
		if cfg.Tools[i].Name == trivyToolName {
			return cfg.Tools[i].EnsureInstalled()
		}
	}
	return "", fmt.Errorf("tool %q not found in tools.yaml", trivyToolName)
}

// IsTrivyInstalled checks whether the embedded trivy binary is available and,
// if so, prepends its directory to PATH so kubeshield can locate it.
func IsTrivyInstalled() bool {
	path, err := resolveTrivyBin()
	if err != nil {
		fmt.Println("Container image scanner is not available. Run 'make prebuild' to build it.")
		return false
	}
	prependToPath(filepath.Dir(path))
	return true
}

// installTrivy resolves the embedded trivy binary and exposes it via PATH.
func installTrivy() error {
	path, err := resolveTrivyBin()
	if err != nil {
		return err
	}
	prependToPath(filepath.Dir(path))
	return nil
}

// prependToPath adds dir to the front of the PATH environment variable.
func prependToPath(dir string) {
	_ = os.Setenv("PATH", fmt.Sprintf("%s%c%s", dir, os.PathListSeparator, os.Getenv("PATH")))
}

// IsValidDomain validates that a domain follows the expected https:// pattern.
func IsValidDomain(domain string) bool {
	re := regexp.MustCompile(`^https:\/\/[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$`)
	return re.MatchString(domain)
}

func mapOS(goos string) string {
	switch strings.ToLower(goos) {
	case "linux":
		return "Linux"
	case "darwin":
		return "macOS"
	case "windows":
		return "Windows"
	default:
		return ""
	}
}

func mapArch(goarch string) string {
	switch goarch {
	case "amd64":
		return "64bit"
	case "386":
		return "32bit"
	case "arm64":
		return "ARM64"
	case "arm":
		return "ARM"
	default:
		return ""
	}
}
