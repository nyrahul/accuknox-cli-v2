//go:build !windows

package deboard

import (
	"errors"
	"syscall"
)

func isDirNotEmpty(err error) bool {
	return errors.Is(err, syscall.ENOTEMPTY) || errors.Is(err, syscall.EEXIST)
}
