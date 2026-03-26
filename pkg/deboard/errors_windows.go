//go:build windows

package deboard

import (
	"errors"
	"syscall"
)

func isDirNotEmpty(err error) bool {
	return errors.Is(err, syscall.ERROR_DIR_NOT_EMPTY)
}
