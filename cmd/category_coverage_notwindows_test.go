//go:build !windows
// +build !windows

package cmd

import "syscall"

// syscallEHostUnreach returns the errno proving tcp_unreachable is reachable; Windows differs
func syscallEHostUnreach() syscall.Errno {
	return syscall.EHOSTUNREACH
}
