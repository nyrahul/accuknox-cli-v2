package tools

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed tools.yaml
var embeddedConfig []byte

// Load parses the embedded tools.yaml.
func Load() (*Config, error) {
	return parse(embeddedConfig)
}

// LoadFromFile parses tools.yaml from the given path (used by build scripts).
func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}
	return parse(data)
}

func parse(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse tools config: %w", err)
	}
	return &cfg, nil
}

// ResolveForPlatform returns the PlatformConfig and resolved install filename
// for the given OS/arch, or an error if the tool is not available.
func (t *Tool) ResolveForPlatform(goos, goarch string) (*PlatformConfig, string, error) {
	platform, ok := t.Platforms[goos]
	if !ok {
		return nil, "", fmt.Errorf("tool %q is not available on %s", t.Name, goos)
	}
	cfg, ok := platform[goarch]
	if !ok {
		return nil, "", fmt.Errorf("tool %q is not available on %s/%s", t.Name, goos, goarch)
	}
	installAs := t.InstallAs
	if cfg.InstallAs != "" {
		installAs = cfg.InstallAs
	}
	return &cfg, installAs, nil
}

// EnsureInstalled checks whether the tool binary is present and downloads it
// if not. Lookup order:
//  1. Directory containing the knoxctl executable (bundled in release packages)
//  2. ~/.accuknox-config/tools/ (previously auto-downloaded)
//  3. Download to ~/.accuknox-config/tools/
func (t *Tool) EnsureInstalled() (string, error) {
	cfg, installAs, err := t.ResolveForPlatform(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return "", err
	}

	// 1. Check next to the running binary (release package layout).
	if execPath, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(execPath), installAs)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	// 2. Check the user's download cache.
	cacheDir := installDir()
	cached := filepath.Join(cacheDir, installAs)
	if _, err := os.Stat(cached); err == nil {
		return cached, nil
	}

	// 3. Download — only if sha256 is provided.
	if cfg.SHA256 == "" {
		return "", fmt.Errorf("tool %q has no sha256 checksum configured; cannot download safely", t.Name)
	}
	fmt.Printf("Downloading %s %s...\n", t.Name, t.Version)
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create install dir: %w", err)
	}
	if err := downloadAndInstall(cfg.Source, cfg.SHA256, installAs, cached); err != nil {
		return "", fmt.Errorf("failed to install %s: %w", t.Name, err)
	}
	fmt.Printf("Installed %s to %s\n", t.Name, cached)
	return cached, nil
}

// buildCacheDir returns the persistent cache directory for build-time tool downloads,
// keyed by goos/goarch so cross-platform builds don't collide.
func buildCacheDir(goos, goarch string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), ".accuknox-config", "tools", "build-cache", goos+"_"+goarch)
	}
	return filepath.Join(home, ".accuknox-config", "tools", "build-cache", goos+"_"+goarch)
}

// DownloadTo copies the tool binary for the specified goos/goarch into outputDir.
// It maintains a persistent cache under ~/.accuknox-config/tools/build-cache so
// that tools are not re-downloaded across goreleaser runs (even after dist/ is cleaned).
// Used by build scripts (e.g. scripts/download-tools) during release packaging.
func (t *Tool) DownloadTo(goos, goarch, outputDir string) error {
	cfg, installAs, err := t.ResolveForPlatform(goos, goarch)
	if err != nil {
		// Tool not available for this platform — skip silently.
		return nil
	}
	if cfg.SHA256 == "" {
		fmt.Printf("  Skipping %s (%s/%s): no sha256 configured\n", t.Name, goos, goarch)
		return nil
	}

	cacheDir := buildCacheDir(goos, goarch)
	cached := filepath.Join(cacheDir, installAs)

	// Download into the cache if not already there.
	if _, err := os.Stat(cached); os.IsNotExist(err) {
		fmt.Printf("  Downloading %s (%s/%s)...\n", t.Name, goos, goarch)
		if err := os.MkdirAll(cacheDir, 0o755); err != nil {
			return fmt.Errorf("failed to create build cache dir: %w", err)
		}
		if err := downloadAndInstall(cfg.Source, cfg.SHA256, installAs, cached); err != nil {
			return fmt.Errorf("failed to download %s for %s/%s: %w", t.Name, goos, goarch, err)
		}
		fmt.Printf("  Cached at %s\n", cached)
	} else {
		fmt.Printf("  Using cached %s\n", cached)
	}

	// Copy from cache into the output directory.
	dest := filepath.Join(outputDir, installAs)
	if err := copyFile(cached, dest); err != nil {
		return fmt.Errorf("failed to copy %s to output: %w", installAs, err)
	}
	fmt.Printf("  -> %s\n", dest)
	return nil
}

// copyFile copies src to dst preserving executable permissions.
func copyFile(src, dst string) error {
	in, err := os.Open(src) // #nosec G304
	if err != nil {
		return err
	}
	defer in.Close()

	info, err := in.Stat()
	if err != nil {
		return err
	}

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode()) // #nosec G304
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

// installDir returns the user-level tool cache directory.
func installDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), ".accuknox-config", "tools")
	}
	return filepath.Join(home, ".accuknox-config", "tools")
}

// downloadAndInstall fetches sourceURL, verifies the optional SHA256, then
// extracts the binary from .tar.gz / .zip archives or saves it directly.
func downloadAndInstall(sourceURL, expectedSHA256, installAs, destPath string) error {
	resp, err := http.Get(sourceURL) // #nosec G107
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned HTTP %d for %s", resp.StatusCode, sourceURL)
	}

	tmp, err := os.CreateTemp("", "knoxctl-tool-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	hasher := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, hasher), resp.Body); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to write download: %w", err)
	}
	tmp.Close()

	if expectedSHA256 != "" {
		got := hex.EncodeToString(hasher.Sum(nil))
		if !strings.EqualFold(got, expectedSHA256) {
			return fmt.Errorf("SHA256 mismatch: got %s, want %s", got, expectedSHA256)
		}
	}

	switch {
	case strings.HasSuffix(sourceURL, ".tar.gz") || strings.HasSuffix(sourceURL, ".tgz"):
		return extractFromTarGz(tmpPath, installAs, destPath)
	case strings.HasSuffix(sourceURL, ".zip"):
		return extractFromZip(tmpPath, installAs, destPath)
	default:
		return installBinary(tmpPath, destPath)
	}
}

// extractFromTarGz finds the entry whose base name matches installAs and
// extracts it to destPath.
func extractFromTarGz(archivePath, installAs, destPath string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("not a valid gzip file: %w", err)
	}
	defer gz.Close()

	target := strings.ToLower(strings.TrimSuffix(installAs, ".exe"))
	tr := tar.NewReader(gz)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		base := strings.ToLower(strings.TrimSuffix(filepath.Base(hdr.Name), ".exe"))
		if base == target {
			return writeExecutable(tr, destPath)
		}
	}
	return fmt.Errorf("binary %q not found in archive", installAs)
}

// extractFromZip finds the matching entry and extracts it to destPath.
func extractFromZip(archivePath, installAs, destPath string) error {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("not a valid zip file: %w", err)
	}
	defer zr.Close()

	target := strings.ToLower(strings.TrimSuffix(installAs, ".exe"))

	for _, f := range zr.File {
		base := strings.ToLower(strings.TrimSuffix(filepath.Base(f.Name), ".exe"))
		if base == target {
			rc, err := f.Open()
			if err != nil {
				return err
			}
			defer rc.Close()
			return writeExecutable(rc, destPath)
		}
	}
	return fmt.Errorf("binary %q not found in zip archive", installAs)
}

// installBinary copies src to dest with executable permissions.
func installBinary(src, dest string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dest, data, 0o755) // #nosec G306
}

// writeExecutable writes r to destPath with executable permissions.
func writeExecutable(r io.Reader, destPath string) error {
	out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755) // #nosec G304
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", destPath, err)
	}
	defer out.Close()
	if _, err := io.Copy(out, r); err != nil {
		return fmt.Errorf("failed to write %s: %w", destPath, err)
	}
	return nil
}
