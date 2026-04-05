package tools

// Config is the top-level structure of tools.yaml.
type Config struct {
	Tools []Tool `yaml:"tools"`
}

// Tool defines a single external tool bundled with knoxctl.
// install_as is the filename written to disk; it can be overridden per platform entry.
// builtin: true marks tools whose binary is built from source (e.g. a git submodule)
// rather than downloaded; EnsureInstalled will not attempt a network download for them.
type Tool struct {
	Name        string              `yaml:"name"`
	Description string              `yaml:"description"`
	InstallAs   string              `yaml:"install_as"`
	Version     string              `yaml:"version"`
	Builtin     bool                `yaml:"builtin"`   // binary is built from source, not downloaded
	Platforms   map[string]Platform `yaml:"platforms"` // keyed by GOOS
}

// Platform maps GOARCH → PlatformConfig.
type Platform map[string]PlatformConfig

// PlatformConfig holds download details for a specific OS/arch combination.
type PlatformConfig struct {
	Source    string `yaml:"source"`
	SHA256    string `yaml:"sha256"`
	InstallAs string `yaml:"install_as"` // overrides tool-level InstallAs when set
	Binary    string `yaml:"binary"`     // filename of binary inside archive (optional; defaults to install_as)
}
