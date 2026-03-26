//go:build !linux

package onboard

import "fmt"

func StartSystemdService(serviceName string) error {
	return fmt.Errorf("systemd is not available on this platform")
}

func StopSystemdService(serviceName string, skipDeleteDisable, force bool) error {
	return fmt.Errorf("systemd is not available on this platform")
}

func GetSystemdServiceStatus(name string) (string, error) {
	return "", fmt.Errorf("systemd is not available on this platform")
}
