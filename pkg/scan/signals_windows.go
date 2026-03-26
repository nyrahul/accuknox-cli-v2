//go:build windows

package scan

import (
	"os"
	"syscall"
)

var extraSignals = []os.Signal{syscall.SIGTERM}
