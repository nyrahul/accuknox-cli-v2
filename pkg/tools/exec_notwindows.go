//go:build !windows

package tools

import (
	"os"
	"syscall"
)

// Exec replaces the current process with the tool binary (Unix exec).
func Exec(binPath string, args []string) error {
	return syscall.Exec(binPath, append([]string{binPath}, args...), os.Environ()) // #nosec G204
}
