//go:build windows

package imagescan

// isZapSyncError returns true for errors that can be safely ignored when
// syncing the zap logger. On Windows, syncing to stderr is not an issue.
func isZapSyncError(err error) bool {
	return false
}
