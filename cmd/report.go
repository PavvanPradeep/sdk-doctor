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

type idleTestResult struct {
	Host      string
	Port      int
	IdleFor   string
	ReplyTime string `json:",omitempty"`
	Error     string `json:",omitempty"`
}

type tcpCountersResult struct {
	Host             string
	Port             int
	RTT              string
	RTTVar           string
	CongestionWindow uint32
	TotalRetransmits uint32
	Lost             uint32
}

// reportSchemaVersion is bumped whenever a field's meaning changes, so a consumer can tell
const reportSchemaVersion = 1

type diagnosticReport struct {
	SchemaVersion    int
	StartedAt        time.Time
	FinishedAt       time.Time
	ConnectionString string
	Host             *helpers.HostInfo   `json:",omitempty"`
	Bucket           string              `json:",omitempty"`
	Network          string              `json:",omitempty"`
	ConfigSource     string              `json:",omitempty"`
	ClockSkew        string              `json:",omitempty"`
	Nodes            []clusterNode       `json:",omitempty"`
	Attempts         []helpers.Attempt   `json:",omitempty"`
	Ports            []portResult        `json:",omitempty"`
	Latency          []latencyResult     `json:",omitempty"`
	TLS              []tlsResult         `json:",omitempty"`
	IdleTest         []idleTestResult    `json:",omitempty"`
	TCPCounters      []tcpCountersResult `json:",omitempty"`
	Log              []helpers.LogEntry
}

var gReport diagnosticReport

func writeReport(path string) error {
	gReport.SchemaVersion = reportSchemaVersion
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
