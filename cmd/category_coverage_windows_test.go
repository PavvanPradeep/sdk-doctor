package cmd

import "syscall"

// syscallEHostUnreach returns the errno the category-coverage test synthesizes to prove
// tcp_unreachable is reachable through Classify. WSAEHOSTUNREACH does not match
// syscall.EHOSTUNREACH's Unix numbering, so this is a separate value from the
// notwindows build, the same way helpers/hostinfo_windows.go diverges from its sibling.
func syscallEHostUnreach() syscall.Errno {
	return syscall.Errno(10065)
}
