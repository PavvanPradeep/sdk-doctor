package helpers

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"runtime"
	"strings"
)

type NetInterface struct {
	Name      string
	MTU       int
	Up        bool
	Addresses []string
}

type HostInfo struct {
	OS         string
	Arch       string
	GoVersion  string
	FDLimit    uint64 `json:",omitempty"`
	Interfaces []NetInterface
	Proxy      []string `json:",omitempty"`
}

var proxyVars = []string{
	"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
	"http_proxy", "https_proxy", "no_proxy",
}

func redactProxy(value string) string {
	// url.Parse misreads a scheme-less "user:pass@host:port" as scheme "user", so add one
	toParse := value
	schemeAdded := !strings.Contains(value, "://")
	if schemeAdded {
		toParse = "redact://" + value
	}

	parsed, err := url.Parse(toParse)
	if err != nil || parsed.User == nil {
		return value
	}

	if _, hasPassword := parsed.User.Password(); !hasPassword {
		return value
	}

	parsed.User = url.UserPassword(parsed.User.Username(), "xxxxx")

	result := parsed.String()
	if schemeAdded {
		result = strings.TrimPrefix(result, "redact://")
	}

	return result
}

func GatherHostInfo() HostInfo {
	info := HostInfo{
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		GoVersion: runtime.Version(),
	}

	if limit, ok := fdLimit(); ok {
		info.FDLimit = limit
	}

	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		entry := NetInterface{
			Name: iface.Name,
			MTU:  iface.MTU,
			Up:   iface.Flags&net.FlagUp != 0,
		}

		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			entry.Addresses = append(entry.Addresses, addr.String())
		}

		info.Interfaces = append(info.Interfaces, entry)
	}

	for _, name := range proxyVars {
		if value := os.Getenv(name); value != "" {
			info.Proxy = append(info.Proxy, fmt.Sprintf("%s=%s", name, redactProxy(value)))
		}
	}

	return info
}
