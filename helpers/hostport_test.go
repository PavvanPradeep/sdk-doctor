package helpers

import (
	"net"
	"net/url"
	"testing"
)

func TestHostPortServesBothTheResolverAndAURL(t *testing.T) {
	tests := []struct {
		host     string
		want     string
		wantIP   string
		wantZone string
	}{
		{host: "::1", want: "[::1]:8091", wantIP: "::1"},
		{host: "[::1]", want: "[::1]:8091", wantIP: "::1"},
		{host: "fd00::1", want: "[fd00::1]:8091", wantIP: "fd00::1"},
		{host: "[fd00::1]", want: "[fd00::1]:8091", wantIP: "fd00::1"},
		{host: "fe80::1%25en0", want: "[fe80::1%25en0]:8091", wantIP: "fe80::1", wantZone: "25en0"},
		{host: "[fe80::1%25en0]", want: "[fe80::1%25en0]:8091", wantIP: "fe80::1", wantZone: "25en0"},
		{host: "fe80::1%en0", want: "[fe80::1%en0]:8091", wantIP: "fe80::1", wantZone: "en0"},
		{host: "fe80::1%12", want: "[fe80::1%12]:8091", wantIP: "fe80::1", wantZone: "12"},
		{host: "[fe80::1%12]", want: "[fe80::1%12]:8091", wantIP: "fe80::1", wantZone: "12"},
		{host: "fe80::1%25", want: "[fe80::1%25]:8091", wantIP: "fe80::1", wantZone: "25"},
		{host: "fe80::1%251", want: "[fe80::1%251]:8091", wantIP: "fe80::1", wantZone: "251"},
		{host: "fe80::1%2512", want: "[fe80::1%2512]:8091", wantIP: "fe80::1", wantZone: "2512"},
		{host: "fe80::1%dead", want: "[fe80::1%dead]:8091", wantIP: "fe80::1", wantZone: "dead"},
		{host: "127.0.0.1", want: "127.0.0.1:8091", wantIP: "127.0.0.1"},
		{host: "node.example.com", want: "node.example.com:8091"},
	}

	for _, test := range tests {
		got := HostPort(test.host, 8091)
		if got != test.want {
			t.Errorf("HostPort(%q, 8091) = %q, want %q", test.host, got, test.want)
			continue
		}

		if _, _, err := net.SplitHostPort(got); err != nil {
			t.Errorf("HostPort(%q, 8091) = %q is unreadable by SplitHostPort: %s",
				test.host, got, err)
		}

		if test.wantIP != "" {
			addr, err := net.ResolveTCPAddr("tcp", got)
			if err != nil {
				t.Errorf("HostPort(%q, 8091) = %q is unresolvable: %s", test.host, got, err)
			} else if !addr.IP.Equal(net.ParseIP(test.wantIP)) || addr.Zone != test.wantZone {
				t.Errorf("HostPort(%q, 8091) = %q resolves to ip %v zone %q, want ip %s zone %q",
					test.host, got, addr.IP, addr.Zone, test.wantIP, test.wantZone)
			}
		}

		uri := (&url.URL{Scheme: "http", Host: got, Path: "/pools"}).String()

		parsed, err := url.Parse(uri)
		if err != nil {
			t.Errorf("HostPort(%q, 8091) = %q is unusable in a URL: %s", test.host, got, err)
			continue
		}

		if parsed.Host != got {
			t.Errorf("HostPort(%q, 8091) = %q became %q through the URL %q",
				test.host, got, parsed.Host, uri)
		}
	}
}

func TestBareHostOnlyUnwrapsBrackets(t *testing.T) {
	tests := map[string]string{
		"[::1]":            "::1",
		"::1":              "::1",
		"127.0.0.1":        "127.0.0.1",
		"node.example.com": "node.example.com",
		"[unterminated":    "[unterminated",
		"unopened]":        "unopened]",
		"fe80::1%25en0":    "fe80::1%25en0",
		"[fe80::1%25en0]":  "fe80::1%25en0",
		"fe80::1%en0":      "fe80::1%en0",
		"fe80::1%2525en0":  "fe80::1%2525en0",
		"fe80::1%12":       "fe80::1%12",
		"[fe80::1%12]":     "fe80::1%12",
		"fe80::1%25":       "fe80::1%25",
		"fe80::1%251":      "fe80::1%251",
		"fe80::1%2512":     "fe80::1%2512",
		"fe80::1%dead":     "fe80::1%dead",
		"node%25name":      "node%25name",
	}

	for host, want := range tests {
		if got := BareHost(host); got != want {
			t.Errorf("BareHost(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestTLSServerNameDropsTheZoneButKeepsEverythingElse(t *testing.T) {
	tests := map[string]string{
		"fe80::1%en0":      "fe80::1",
		"[fe80::1%en0]":    "fe80::1",
		"fe80::1%25en0":    "fe80::1",
		"fe80::1%251":      "fe80::1",
		"fe80::1":          "fe80::1",
		"[::1]":            "::1",
		"127.0.0.1":        "127.0.0.1",
		"node.example.com": "node.example.com",
	}

	for host, want := range tests {
		if got := TLSServerName(host); got != want {
			t.Errorf("TLSServerName(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestHostIsUsableRejectsWhatAURLWouldSilentlyEscape(t *testing.T) {
	tests := map[string]bool{
		"cb1.example.com": true,
		"127.0.0.1":       true,
		"[::1]":           true,
		"fe80::1%en0":     true,
		"[fe80::1%en0]":   true,
		"fe80::1%251":     true,
		"ho%st":           false,
		"ho st":           false,
	}

	for host, want := range tests {
		if got := HostIsUsable(host); got != want {
			t.Errorf("HostIsUsable(%q) = %t, want %t", host, got, want)
		}
	}
}
