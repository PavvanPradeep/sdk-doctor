//go:build !windows
// +build !windows

package cmd

import "syscall"

// syscallEHostUnreach returns the errno the category-coverage test synthesizes to prove
// tcp_unreachable is reachable through Classify. The Unix and Windows values differ, so
// this lives in a platform file the same way helpers/hostinfo_notwindows.go does.
func syscallEHostUnreach() syscall.Errno {
	return syscall.EHOSTUNREACH
}
