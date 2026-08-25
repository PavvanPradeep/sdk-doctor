package cmd

import (
	"encoding/json"
	"io/ioutil"
	"time"

	"github.com/couchbaselabs/sdk-doctor/helpers"
)

type portResult struct {
	Host       string
	Port       int
	Service    string
	State      string
	Advertised bool
}

type connectResult struct {
	Host string
	Port int
	DNS  string `json:",omitempty"`
	TCP  string
	TLS  string `json:",omitempty"`
	SASL string `json:",omitempty"`
}

type latencyResult struct {
	Host        string
	Port        int
	Samples     int
	Errors      int
	FirstOp     string
	Min         string
	Mean        string
	P50         string
	P90         string
	P99         string
	Max         string
	StdDev      string
	RTOSuspects []string `json:",omitempty"`
}

type tlsResult struct {
	Host string
	Port int
	helpers.TLSChainInfo
}

type diagnosticReport struct {
	StartedAt        time.Time
	FinishedAt       time.Time
	ConnectionString string
	Host             *helpers.HostInfo `json:",omitempty"`
	Bucket           string            `json:",omitempty"`
	Network          string            `json:",omitempty"`
	ConfigSource     string            `json:",omitempty"`
	ClockSkew        string            `json:",omitempty"`
	Nodes            []clusterNode     `json:",omitempty"`
	Ports            []portResult      `json:",omitempty"`
	Connects         []connectResult   `json:",omitempty"`
	Latency          []latencyResult   `json:",omitempty"`
	TLS              []tlsResult       `json:",omitempty"`
	Log              []helpers.LogEntry
}

var gReport diagnosticReport

func writeReport(path string) error {
	gReport.FinishedAt = time.Now()
	gReport.Log = gLog.Entries()

	data, err := json.MarshalIndent(gReport, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(path, append(data, '\n'), 0644)
}

func durs(samples []time.Duration) []string {
	var out []string
	for _, sample := range samples {
		out = append(out, dur(sample))
	}

	return out
}
