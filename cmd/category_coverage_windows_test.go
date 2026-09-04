package cmd

import "syscall"

// WSAEHOSTUNREACH does not match syscall.EHOSTUNREACH, so this diverges from the Unix build
func syscallEHostUnreach() syscall.Errno {
	return syscall.Errno(10065)
}
