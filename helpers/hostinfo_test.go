package helpers

import (
	"os"
	"strings"
	"testing"
)

func TestRedactProxy(t *testing.T) {
	tests := []struct {
		value string
		want  string
	}{
		{"http://proxy.corp:3128", "http://proxy.corp:3128"},
		{"http://user@proxy.corp:3128", "http://user@proxy.corp:3128"},
		{"http://user:hunter2@proxy.corp:3128", "http://user:xxxxx@proxy.corp:3128"},
		{"localhost,127.0.0.1", "localhost,127.0.0.1"},
	}

	for _, test := range tests {
		if got := redactProxy(test.value); got != test.want {
			t.Errorf("redactProxy(%q) = %q, want %q", test.value, got, test.want)
		}
	}
}

func TestGatherHostInfo(t *testing.T) {
	os.Setenv("HTTPS_PROXY", "http://user:hunter2@proxy.corp:3128")
	defer os.Unsetenv("HTTPS_PROXY")

	info := GatherHostInfo()

	if info.OS == "" || info.Arch == "" || len(info.Interfaces) == 0 {
		t.Fatalf("expected a populated host block, got %+v", info)
	}

	if len(info.Proxy) != 1 || !strings.HasPrefix(info.Proxy[0], "HTTPS_PROXY=") {
		t.Fatalf("expected the proxy variable, got %+v", info.Proxy)
	}

	if strings.Contains(info.Proxy[0], "hunter2") {
		t.Fatalf("the proxy password reached the report: %s", info.Proxy[0])
	}
}
