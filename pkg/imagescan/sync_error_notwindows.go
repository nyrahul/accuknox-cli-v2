//go:build !windows

package imagescan

import (
	"errors"
	"syscall"
)

// isZapSyncError returns true for errors that can be safely ignored when
// syncing the zap logger (see https://github.com/uber-go/zap/issues/328).
func isZapSyncError(err error) bool {
	return errors.Is(err, syscall.EINVAL)
}
