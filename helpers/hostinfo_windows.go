package helpers

// Windows bounds handles by memory rather than by an RLIMIT_NOFILE equivalent
func fdLimit() (uint64, bool) {
	return 0, false
}
