//go:build !windows
// +build !windows

package helpers

import "syscall"

func fdLimit() (uint64, bool) {
	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
		return 0, false
	}

	return uint64(limit.Cur), true
}
