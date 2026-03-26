//go:build windows

package tools

import (
	"os"
	"os/exec"
)

// Exec runs the tool binary as a child process (Windows has no syscall.Exec).
func Exec(binPath string, args []string) error {
	cmd := exec.Command(binPath, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
