package cmd

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/couchbaselabs/gocbconnstr"
	"github.com/couchbaselabs/sdk-doctor/helpers"
	"github.com/couchbaselabs/sdk-doctor/memd"
	"github.com/spf13/cobra"
)

// dur formats a duration for the log, as most connect phases are sub-millisecond
func dur(d time.Duration) string {
	return helpers.Dur(d)
}

const certExpiryWarnDays = 30

func logTLSChainInfo(host string, port int, info helpers.TLSChainInfo) {
	if len(info.Chain) == 0 {
		return
	}

	gReport.TLS = append(gReport.TLS, tlsResult{host, port, info})

	gLog.Log("TLS on `%s:%d`: %s, %s, chain of %d certificate(s):",
		host, port, info.VersionName, info.CipherName, len(info.Chain))

	for i, cert := range info.Chain {
		gLog.Log("  [%d] subject `%s`, issuer `%s`, expires %s",
			i, cert.Subject, cert.Issuer, cert.NotAfter.Format("2006-01-02"))

		// An expiring intermediate breaks the chain just as a leaf does
		if time.Until(cert.NotAfter) < 0 {
			expiry := fmt.Sprintf("expired %d days ago", -cert.DaysToExpiry)
			if cert.DaysToExpiry == 0 {
				expiry = "expired less than a day ago"
			}

			gLog.Error(
				"Certificate `%s` presented by `%s:%d` %s (%s).",
				cert.Subject, host, port, expiry, cert.NotAfter.Format("2006-01-02"))
		} else if cert.DaysToExpiry <= certExpiryWarnDays {
			expiry := fmt.Sprintf("expires in %d days", cert.DaysToExpiry)
			if cert.DaysToExpiry == 0 {
				expiry = "expires in less than a day"
			}

			gLog.Warn(
				"Certificate `%s` presented by `%s:%d` %s (%s).",
				cert.Subject, host, port, expiry, cert.NotAfter.Format("2006-01-02"))
		}
	}

	if !info.HostMatches {
		if len(info.LeafSANs) == 0 {
			gLog.Error(
				"Dialed hostname `%s` cannot be verified: the certificate presented by `%s:%d`"+
					" carries no subject alternative names.",
				info.DialedHost, host, port)
		} else {
			gLog.Error(
				"Dialed hostname `%s` is not present in the certificate's subject alternative"+
					" names %v for `%s:%d`.",
				info.DialedHost, info.LeafSANs, host, port)
		}
	}
}

// probeTLSChain reports the chain after a failed connection, which leaves no handshake state to inspect
func probeTLSChain(host string, port int) bool {
	dialer := &net.Dialer{
		Timeout: 2000 * time.Millisecond,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", helpers.HostPort(host, port),
		&tls.Config{InsecureSkipVerify: true, ServerName: helpers.TLSServerName(host)})
	if err != nil {
		return false
	}
	defer conn.Close()

	state := conn.ConnectionState()
	logTLSChainInfo(host, port, helpers.BuildTLSChainInfo(&state, host, time.Now()))

	return true
}

func reportBootstrapTLSChain(attempts []helpers.Attempt) {
	for _, attempt := range attempts {
		switch helpers.Category(attempt.Category) {
		case helpers.CategoryTLSVerify, helpers.CategoryTLSHandshake:
		default:
			continue
		}

		host, port, err := net.SplitHostPort(attempt.Endpoint)
		if err != nil {
			return
		}

		portNum, err := strconv.Atoi(port)
		if err != nil {
			return
		}

		probeTLSChain(host, portNum)

		return
	}
}

func logConnectPhases(attempt helpers.Attempt, timing memd.ConnectTiming) {
	recordAttempt(attempt)

	if attempt.TCP == "" {
		return
	}

	dns := attempt.DNS
	if dns == "" {
		dns = "-"
	}

	phases := fmt.Sprintf("dns %s, tcp %s", dns, attempt.TCP)

	if attempt.TLS != "" {
		phases += fmt.Sprintf(", tls %s", attempt.TLS)
	}
	if attempt.SASL != "" {
		phases += fmt.Sprintf(", sasl %s", attempt.SASL)
	}

	gLog.Log("Connect phases for `%s`: %s%s", attempt.Endpoint, phases, socketPath(attempt))

	if tcpSlowerThanDNS(timing) {
		gLog.Warn(
			"TCP handshake to `%s` took %s against %s for DNS resolution --"+
				" latency appears to be on the network path, not name resolution.",
			attempt.Endpoint, attempt.TCP, attempt.DNS)
	}
}

func socketPath(attempt helpers.Attempt) string {
	for _, address := range attempt.Addresses {
		if address.Error != "" || address.Local == "" {
			continue
		}

		path := fmt.Sprintf(" (%s -> %s, %s", address.Local, address.Address, address.Family)
		if address.Interface != "" {
			path += fmt.Sprintf(" via %s", address.Interface)
		}

		if len(attempt.Resolved) > 1 {
			path += fmt.Sprintf(", %d addresses resolved", len(attempt.Resolved))
		}

		return path + ")"
	}

	return ""
}

// tcpSlowerThanDNS reports whether the handshake dominated resolution by enough to be worth telling the user about
func tcpSlowerThanDNS(timing memd.ConnectTiming) bool {
	return timing.TCP() > 20*time.Millisecond && timing.DNS() > 0 && timing.TCP() > 5*timing.DNS()
}

type httpTrace struct {
	lock sync.Mutex

	timing           memd.ConnectTiming
	tlsHandshakeDone bool

	resolved  []string
	addresses []memd.AddressResult

	starts map[string]time.Time

	wroteRequest time.Time
	firstByte    time.Time
}

func (t *httpTrace) Timing() memd.ConnectTiming {
	t.lock.Lock()
	defer t.lock.Unlock()

	return t.timing
}

func (t *httpTrace) TLSHandshakeDone() bool {
	t.lock.Lock()
	defer t.lock.Unlock()

	return t.tlsHandshakeDone
}

func (t *httpTrace) Resolved() []string {
	t.lock.Lock()
	defer t.lock.Unlock()

	return append([]string(nil), t.resolved...)
}

func (t *httpTrace) Addresses() []memd.AddressResult {
	t.lock.Lock()
	defer t.lock.Unlock()

	return append([]memd.AddressResult(nil), t.addresses...)
}

func (t *httpTrace) Latency() (time.Duration, bool) {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.wroteRequest.IsZero() || t.firstByte.IsZero() {
		return 0, false
	}

	return t.firstByte.Sub(t.wroteRequest), true
}

func (t *httpTrace) stamp(phase *time.Time) {
	t.lock.Lock()
	*phase = time.Now()
	t.lock.Unlock()
}

func (t *httpTrace) connectStart(_, addr string) {
	t.lock.Lock()
	t.starts[addr] = time.Now()
	t.lock.Unlock()
}

func (t *httpTrace) connectDone(_, addr string, err error) {
	if errors.Is(err, context.Canceled) {
		return
	}

	t.lock.Lock()
	defer t.lock.Unlock()

	now := time.Now()

	start, started := t.starts[addr]
	if !started {
		start = now
	}

	if err == nil && started {
		t.timing.TCPStart = start
		t.timing.TCPDone = now
	}

	t.addresses = append(t.addresses, memd.AddressResult{
		Address: addr,
		Start:   start,
		Done:    now,
		Err:     err,
	})
}

func (t *httpTrace) gotConn(info httptrace.GotConnInfo) {
	if info.Conn == nil {
		return
	}

	remote := info.Conn.RemoteAddr().String()
	local := info.Conn.LocalAddr().String()

	t.lock.Lock()
	defer t.lock.Unlock()
	if _, ok := info.Conn.(*tls.Conn); ok {
		t.tlsHandshakeDone = true
	}

	for i := range t.addresses {
		if t.addresses[i].Address == remote && t.addresses[i].Err == nil {
			t.addresses[i].Local = local
			return
		}
	}

	t.addresses = append(t.addresses, memd.AddressResult{Address: remote, Local: local})
}

func traceRequest(req *http.Request) (*http.Request, *httpTrace) {
	collected := &httpTrace{starts: map[string]time.Time{}}

	trace := &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { collected.stamp(&collected.timing.DNSStart) },
		DNSDone: func(info httptrace.DNSDoneInfo) {
			collected.lock.Lock()
			collected.timing.DNSDone = time.Now()
			for _, addr := range info.Addrs {
				collected.resolved = append(collected.resolved, addr.IP.String())
			}
			collected.lock.Unlock()
		},
		ConnectStart:      collected.connectStart,
		ConnectDone:       collected.connectDone,
		GotConn:           collected.gotConn,
		TLSHandshakeStart: func() { collected.stamp(&collected.timing.TLSStart) },
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			collected.lock.Lock()
			collected.timing.TLSDone = time.Now()
			collected.tlsHandshakeDone = err == nil
			collected.lock.Unlock()
		},
		WroteRequest:         func(httptrace.WroteRequestInfo) { collected.stamp(&collected.wroteRequest) },
		GotFirstResponseByte: func() { collected.stamp(&collected.firstByte) },
	}

	return req.WithContext(httptrace.WithClientTrace(req.Context(), trace)), collected
}

func connectedPhase(trace *httpTrace) helpers.Phase {
	if trace.TLSHandshakeDone() {
		return helpers.PhaseTLS
	}

	return helpers.PhaseTCP
}

func withSocket(builder *helpers.AttemptBuilder, trace *httpTrace) *helpers.AttemptBuilder {
	return builder.WithTiming(trace.Timing(), 0).
		WithResolved(trace.Resolved()).
		WithAddresses(trace.Addresses(), connectedPhase(trace))
}

// httpFailurePhase names the phase a failed request died in, from the trace not the error text
func httpFailurePhase(timing memd.ConnectTiming, tlsHandshakeDone bool, err error) helpers.Phase {
	var dnsErr *net.DNSError

	switch {
	case errors.As(err, &dnsErr):
		return helpers.PhaseDNS
	case !timing.TLSStart.IsZero() && !tlsHandshakeDone:
		return helpers.PhaseTLS
	case !timing.TCPDone.IsZero():
		return helpers.PhaseResponse
	default:
		return helpers.PhaseTCP
	}
}

// diagnoseCmd represents the diagnose command
var diagnoseCmd = &cobra.Command{
	Use:   "diagnose [connection_string]",
	Short: "Diagnose checks for problems with your configuration",
	Long: `Diagnose runs various tests against your network and cluster
to identify any flaws in your configuration that would cause failures
in development or production environments.`,
	RunE: runDiagnose,
}

var (
	tlsCaArg          string
	usernameArg       string
	passwordArg       string
	bucketPasswordArg string
	samplesArg        int
	durationArg       time.Duration
	rtoMinArg         time.Duration
	outArg            string
	idleTestArg       time.Duration
)

func init() {
	RootCmd.AddCommand(diagnoseCmd)

	diagnoseCmd.PersistentFlags().StringVarP(&tlsCaArg, "tls-ca", "a", "", "certificate authority")
	diagnoseCmd.PersistentFlags().StringVarP(&usernameArg, "username", "u", "", "username")
	diagnoseCmd.PersistentFlags().StringVarP(&passwordArg, "password", "p", "", "password")
	diagnoseCmd.PersistentFlags().StringVarP(&bucketPasswordArg, "bucket-password", "z", "", "bucket password (deprecated, use password instead)")
	diagnoseCmd.PersistentFlags().IntVar(&samplesArg, "samples", 10, "number of KV latency samples to collect per node")
	diagnoseCmd.PersistentFlags().DurationVar(&durationArg, "duration", 0, "sample KV latency for this long per node instead of a fixed count (e.g. 60s)")
	diagnoseCmd.PersistentFlags().StringVarP(&outArg, "out", "o", "", "write a structured JSON report of this run to this file")
	diagnoseCmd.PersistentFlags().DurationVar(&rtoMinArg, "rto-min", helpers.DefaultRTOMin, "this client OS's minimum TCP retransmission timeout, used to tell packet loss from latency")
	diagnoseCmd.PersistentFlags().DurationVar(&idleTestArg, "idle-test", 0, "after sampling, idle each node's KV connection this long then NOOP it, to catch idle connections being dropped (e.g. 5m)")
}

const kvSampleInterval = 100 * time.Millisecond
const kvMaxErrorStreak = 10

// sampleKVLatency returns false if it gave up early on a connection that kept failing
func sampleKVLatency(client *helpers.MemdClient, stats *helpers.PingHelper, firstOpFailed bool) bool {
	errStreak := 0
	if firstOpFailed {
		errStreak = 1
	}

	// Returns false once the connection has failed often enough to stop sampling it
	sampleOne := func() bool {
		pingState := stats.StartOne()
		err := client.Ping()
		stats.StopOne(pingState, err)

		if err != nil {
			errStreak++
		} else {
			errStreak = 0
		}

		return errStreak < kvMaxErrorStreak
	}

	if durationArg > 0 {
		deadline := time.Now().Add(durationArg)

		for time.Now().Before(deadline) {
			if !sampleOne() {
				return false
			}

			time.Sleep(kvSampleInterval)
		}

		return true
	}

	for i := 0; i < samplesArg; i++ {
		if !sampleOne() {
			return false
		}

		if i < samplesArg-1 {
			time.Sleep(kvSampleInterval)
		}
	}

	return true
}

type idleTarget struct {
	host string
	port int
}

func runIdleTest(targets []idleTarget, bucket, user, pass string, tlsConfig *tls.Config) {
	if len(targets) == 0 {
		return
	}

	idleFor := idleTestArg
	gLog.Log("Testing %d connection(s) for connection reaping after %s idle...",
		len(targets), dur(idleFor))

	results := make([]struct {
		attempt helpers.Attempt
		idle    idleTestResult
	}, len(targets))
	var wg sync.WaitGroup
	for i, target := range targets {
		wg.Add(1)
		go func(i int, target idleTarget) {
			defer wg.Done()
			client, builder, err := helpers.Dial("idle-kv", target.host, target.port,
				bucket, user, pass, tlsConfig)
			if err != nil {
				results[i].attempt = builder.FromDial(err)
				return
			}
			defer client.Close()
			results[i].attempt = builder.Finish(builder.Reached(), "", nil)

			idleStart := time.Now()
			time.Sleep(idleFor)
			start := time.Now()
			err = client.Ping()
			result := idleTestResult{Host: target.host, Port: target.port, IdleFor: dur(start.Sub(idleStart))}
			if err != nil {
				result.Error = err.Error()
			} else {
				result.ReplyTime = dur(time.Since(start))
			}
			results[i].idle = result
		}(i, target)
	}
	wg.Wait()

	for i, outcome := range results {
		recordAttempt(outcome.attempt)

		if outcome.attempt.Error != "" {
			gLog.Warn(
				"Not idle-testing `%s:%d`, a connection for the test could not be opened even"+
					" though sampling had just succeeded on it (error: %s)",
				targets[i].host, targets[i].port, outcome.attempt.Error)

			continue
		}

		result := outcome.idle
		if result.Error != "" {
			gLog.Error(
				"Connection to `%s:%d` did not survive %s idle (error: %s), which is"+
					" consistent with a stateful firewall or load balancer dropping idle"+
					" connections.",
				result.Host, result.Port, result.IdleFor, result.Error)
		} else {
			gLog.Log("Connection to `%s:%d` survived %s idle, NOOP replied in %s",
				result.Host, result.Port, result.IdleFor, result.ReplyTime)
		}

		gReport.IdleTest = append(gReport.IdleTest, result)
	}
}

var gLog helpers.Logger

func runDiagnose(cmd *cobra.Command, args []string) error {
	fmt.Printf(
		"Note: Diagnostics can only provide accurate results when your cluster\n" +
			" is in a stable state.  Active rebalancing and other cluster configuration\n" +
			" changes can cause the output of the doctor to be inconsistent or in the\n" +
			" worst cases, completely incorrect.\n")
	fmt.Printf("\n")

	if durationArg < 0 || (durationArg == 0 && samplesArg < 1) {
		gLog.Error("Sampling requires --samples of at least 1, or a positive --duration")
		return nil
	}

	if durationArg > 0 && cmd.Flags().Changed("samples") {
		gLog.Warn("Both --duration and --samples were specified, --samples is ignored")
	}

	var connStr string
	if len(args) < 1 {
		connStr = "couchbase://localhost"
		gLog.Warn("No connection string specified, defaulting to `%s`", connStr)
	} else {
		connStr = args[0]
	}

	var tlsConfig *tls.Config
	if tlsCaArg != "" {
		caCertData, err := ioutil.ReadFile(tlsCaArg)
		if err != nil {
			gLog.Error("Failed to read specified TLS certificate authority: %s", err)
			return nil
		}

		rootCAs := x509.NewCertPool()
		rootCAs.AppendCertsFromPEM(caCertData)

		tlsConfig = &tls.Config{}
		tlsConfig.RootCAs = rootCAs
	}

	if passwordArg == "" && bucketPasswordArg != "" {
		passwordArg = bucketPasswordArg
	}
	gReport.StartedAt = time.Now()
	gReport.ConnectionString = connStr

	diagnose(connStr, usernameArg, passwordArg, tlsConfig)

	gLog.Log("Diagnostics completed")

	if outArg != "" {
		if err := writeReport(outArg); err != nil {
			gLog.Error("Failed to write the report to `%s` (error: %s)", outArg, err)
		} else {
			gLog.Log("Wrote a structured report of this run to `%s`", outArg)
		}
	}

	gLog.NewLine()

	gLog.PrintSummary()

	return nil
}

type clusterConfigNode struct {
	OptNode           string         `json:"optNode"`
	ThisNode          bool           `json:"thisNode"`
	CouchAPIBase      string         `json:"couchApiBase"`
	CouchAPIBaseHTTPS string         `json:"couchApiBaseHTTPS"`
	Status            string         `json:"status"`
	Hostname          string         `json:"hostname"`
	Version           string         `json:"version"`
	Os                string         `json:"os"`
	Ports             map[string]int `json:"Ports"`
	Services          []string       `json:"services"`
}

type clusterConfig struct {
	Nodes   []clusterConfigNode `json:"nodes"`
	Buckets struct {
		URI string `json:"uri"`
	} `json:"buckets"`
}

type bucketConfigAlternateNames struct {
	Hostname string         `json:"hostname"`
	Ports    map[string]int `json:"ports"`
}

type bucketConfigNodeExt struct {
	ThisNode       bool                                  `json:"thisNode"`
	Hostname       string                                `json:"hostname"`
	Services       map[string]int                        `json:"services"`
	AlternateNames map[string]bucketConfigAlternateNames `json:"alternateAddresses"`
}

type terseBucketConfig struct {
	SourceHost string
	SourcePort int
	UUID       string                `json:"uuid"`
	Rev        uint                  `json:"rev"`
	NodesExt   []bucketConfigNodeExt `json:"nodesExt"`
}

func (config *terseBucketConfig) GetSourceNodeExt() *bucketConfigNodeExt {
	for i := range config.NodesExt {
		if config.NodesExt[i].ThisNode {
			return &config.NodesExt[i]
		}
	}

	return nil
}

type clusterNode struct {
	Hostname string
	Services map[string]int
}

func clusterNodesFromTerseBucketConfig(config terseBucketConfig, networkType string) []clusterNode {
	var out []clusterNode

	for _, node := range config.NodesExt {
		var newNode clusterNode

		if node.Hostname == "" {
			newNode.Hostname = config.SourceHost
		} else {
			newNode.Hostname = node.Hostname
		}

		newNode.Services = node.Services

		if networkType != "default" {
			netInfo, found := node.AlternateNames[networkType]
			if !found {
				return nil
			}

			if netInfo.Hostname != "" {
				newNode.Hostname = netInfo.Hostname
			}
			if netInfo.Ports != nil {
				newNode.Services = netInfo.Ports
			}
		}

		out = append(out, newNode)
	}

	return out
}

// scanTerseConfigList warns on the configurations the hosts returned and picks the first usable one
func scanTerseConfigList(hosts []gocbconnstr.Address, configs []*terseBucketConfig) *terseBucketConfig {
	if len(hosts) != len(configs) {
		panic(0)
	}

	var masterConfig *terseBucketConfig

	for i, target := range hosts {
		config := configs[i]

		if config == nil {
			continue
		}

		// Reported, not rejected: the network defaults and the node list is built from nodesExt
		thisNodeExt := config.GetSourceNodeExt()
		if thisNodeExt == nil {
			gLog.Warn(
				"Bootstrap host `%s` returned a configuration that does not identify which node"+
					" served it.  Node-specific checks are skipped for it and the `default`"+
					" network is assumed.",
				target.Host)
		}

		if masterConfig == nil {
			masterConfig = config
		} else {
			if config.UUID != masterConfig.UUID {
				gLog.Error(
					"Boostrap host `%s` appears to be pointing to a different cluster.  Tests"+
						" will be running against the first successfully connected node in your"+
						" bootstrap list, as a client would behave.",
					target.Host)
			}
		}

		if thisNodeExt != nil && thisNodeExt.Hostname != "" && target.Host != thisNodeExt.Hostname {
			gLog.Warn(
				"Bootstrap host `%s` is not using the canonical node hostname of `%s`.  This"+
					" is not neccessarily an error, but has been known to result in strange and"+
					" challenging to diagnose errors when DNS entries are reconfigured.",
				target.Host, thisNodeExt.Hostname)
		}
	}

	return masterConfig
}

// nodesFromMasterConfig builds the node list, reporting a node missing the selected network
func nodesFromMasterConfig(config terseBucketConfig, networkType string) []clusterNode {
	nodes := clusterNodesFromTerseBucketConfig(config, networkType)
	if nodes != nil {
		return nodes
	}

	endpoint := helpers.HostPort(config.SourceHost, config.SourcePort)

	// A config listing no nodes at all is a different fault from one missing the chosen network
	if len(config.NodesExt) == 0 {
		gLog.Error(
			"The configuration from `%s` describes no nodes, so no usable node list could"+
				" be built from it.",
			endpoint)

		markAttemptCategory(endpoint, helpers.CategoryConfigEmpty)

		return nil
	}

	gLog.Error(
		"The configuration from `%s` does not describe the `%s` network on every node,"+
			" so no usable node list could be built from it.",
		endpoint, networkType)

	markAttemptCategory(endpoint, helpers.CategoryConfigInvalid)

	return nil
}

func networkFromTerseBucketConfig(config terseBucketConfig) string {
	thisNode := config.GetSourceNodeExt()
	if thisNode == nil {
		return "default"
	}
	sourceHost := helpers.BareHost(config.SourceHost)

	// Check if we connected using any of the ports associated with the default
	// configurations that are available.
	hostname := thisNode.Hostname
	if hostname == "" {
		// The node serving the config advertises no hostname of its own
		hostname = config.SourceHost
	}

	if helpers.BareHost(hostname) == sourceHost {
		for _, svcPort := range thisNode.Services {
			if svcPort == config.SourcePort {
				return "default"
			}
		}
	}

	// Sorted for a deterministic result if more than one alternate network matches
	networkTypes := make([]string, 0, len(thisNode.AlternateNames))
	for networkType := range thisNode.AlternateNames {
		networkTypes = append(networkTypes, networkType)
	}
	sort.Strings(networkTypes)

	for _, networkType := range networkTypes {
		netInfo := thisNode.AlternateNames[networkType]

		// A network that only remaps the port advertises no hostname of its own
		altHostname := netInfo.Hostname
		if altHostname == "" {
			altHostname = hostname
		}

		if helpers.BareHost(altHostname) != sourceHost {
			continue
		}

		ports := netInfo.Ports
		if ports == nil {
			ports = thisNode.Services
		}

		for _, svcPort := range ports {
			if svcPort == config.SourcePort {
				return networkType
			}
		}
	}

	return "default"
}

// httpConfigBudget bounds a single config fetch over HTTP
const httpConfigBudget = 2000 * time.Millisecond

// serviceProbeBudget bounds a service probe, and is what its attempt record reports
const serviceProbeBudget = 2000 * time.Millisecond

type httpProbeVerdict int

const (
	probeReachable httpProbeVerdict = iota
	probeHealthy
	probeHealthUntested
	probeUnhealthy
)

var healthPaths = map[string]string{
	"mgmt": "/pools", "n1ql": "/admin/ping",
	"cbas": "/admin/ping", "fts": "/api/ping",
}

func probeNeedsCredentials(svcKeyPlain string) bool {
	return svcKeyPlain == "mgmt"
}

func verdictForStatus(healthEndpoint bool, status int) httpProbeVerdict {
	switch {
	case status >= 500:
		return probeUnhealthy
	case !healthEndpoint:
		return probeReachable
	case status >= 400 && status != http.StatusNotFound:
		return probeUnhealthy
	case status/100 != 2:
		return probeHealthUntested
	default:
		return probeHealthy
	}
}

func tlsConfigForHost(tlsConfig *tls.Config, host string) *tls.Config {
	if tlsConfig == nil {
		return nil
	}

	hostConfig := tlsConfig.Clone()
	hostConfig.ServerName = helpers.TLSServerName(host)
	return hostConfig
}

func newServiceProbeClient(tlsConfig *tls.Config) *http.Client {
	return &http.Client{
		Transport:     &http.Transport{TLSClientConfig: tlsConfig},
		Timeout:       serviceProbeBudget,
		CheckRedirect: refuseRedirect,
	}
}

func refuseRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

const maxProbeBody = 256

func boundedBody(body io.Reader) string {
	data, _ := ioutil.ReadAll(io.LimitReader(body, maxProbeBody))

	return strings.ToValidUTF8(strings.Join(strings.Fields(string(data)), " "), "")
}

func bodyClause(body string) string {
	if body == "" {
		return ""
	}

	return fmt.Sprintf(" (response: %s)", body)
}

func latencyClause(latency string) string {
	if latency == "" {
		return ""
	}

	return fmt.Sprintf(" in %s", latency)
}

func redirectClause(destination string) string {
	if destination == "" {
		return ""
	}

	return fmt.Sprintf(" redirecting to `%s`", destination)
}

func fetchHTTPTerseBucketConfig(host string, port int, bucket, user, pass string, tlsConfig *tls.Config) (terseBucketConfig, helpers.Attempt, error) {
	if user == "" {
		user = bucket
	}

	httpTransport := &http.Transport{
		TLSClientConfig: tlsConfigForHost(tlsConfig, host),
	}
	httpClient := &http.Client{
		Transport:     httpTransport,
		Timeout:       httpConfigBudget,
		CheckRedirect: refuseRedirect,
	}

	scheme := "http"
	if tlsConfig != nil {
		scheme = "https"
	}

	endpoint := helpers.HostPort(host, port)
	builder := helpers.NewAttempt("bootstrap-http-terse", endpoint, httpConfigBudget)

	uri := (&url.URL{Scheme: scheme, Host: endpoint, Path: "/pools/default/b/" + bucket}).String()

	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return terseBucketConfig{}, builder.Finish(helpers.PhaseNone, helpers.CategoryUnknown, err), err
	}

	req.SetBasicAuth(user, pass)

	// The same tracer the HTTP service probe uses, so both paths report the same phases
	req, trace := traceRequest(req)

	resp, err := httpClient.Do(req)
	if err != nil {
		phase := httpFailurePhase(trace.Timing(), trace.TLSHandshakeDone(), err)

		attempt := withSocket(builder, trace).Finish(phase, helpers.Classify(phase, err), err)

		return terseBucketConfig{}, attempt, err
	}
	defer resp.Body.Close()

	withSocket(builder, trace)

	if resp.StatusCode != 200 {
		category := helpers.CategoryForHTTPStatus(resp.StatusCode)

		statusErr := fmt.Errorf("http error (status code: %d)", resp.StatusCode)
		if resp.StatusCode == 401 {
			statusErr = errors.New("incorrect bucket/password")
		}

		return terseBucketConfig{}, builder.Finish(helpers.PhaseResponse, category, statusErr), statusErr
	}

	configBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return terseBucketConfig{}, builder.Finish(helpers.PhaseResponse, helpers.Classify(helpers.PhaseResponse, err), err), err
	}

	configBytes = bytes.Replace(configBytes, []byte("$HOST"), []byte(host), -1)

	var config terseBucketConfig
	err = json.Unmarshal(configBytes, &config)
	if err != nil {
		return terseBucketConfig{}, builder.Finish(helpers.PhaseConfig, helpers.CategoryConfigInvalid, err), err
	}

	config.SourceHost = host
	config.SourcePort = port

	return config, builder.Finish(helpers.PhaseConfig, "", nil), nil
}

func fetchCccpTerseBucketConfig(host string, port int, bucket, user, pass string, tlsConfig *tls.Config) (terseBucketConfig, helpers.Attempt, error) {
	if user == "" {
		user = bucket
	}

	client, builder, err := helpers.Dial("bootstrap-cccp", host, port, bucket, user, pass, tlsConfig)
	if err != nil {
		return terseBucketConfig{}, builder.FromDial(err), err
	}
	defer client.Close()

	// GetConfig runs after the dial deadline is cleared and carries its own, so the attempt's
	// reported budget must cover it or Elapsed can exceed a Timeout that never applied
	builder.AddBudget(helpers.OpTimeout)

	configBytes, err := client.GetConfig()
	if err != nil {
		return terseBucketConfig{}, builder.FromDial(err), err
	}

	configBytes = bytes.Replace(configBytes, []byte("$HOST"), []byte(host), -1)

	var config terseBucketConfig
	err = json.Unmarshal(configBytes, &config)
	if err != nil {
		return terseBucketConfig{}, builder.Finish(helpers.PhaseConfig, helpers.CategoryConfigInvalid, err), err
	}

	config.SourceHost = host
	config.SourcePort = port

	return config, builder.Finish(helpers.PhaseConfig, "", nil), nil
}

type portDef struct {
	Port int
	Name string
}

var couchbasePorts = []portDef{
	{8091, "mgmt"}, {8092, "views"}, {8093, "query"}, {8094, "search"},
	{8095, "analytics"}, {8096, "eventing"}, {8097, "backup"}, {11210, "kv"},
	{18091, "mgmtSSL"}, {18092, "viewsSSL"}, {18093, "querySSL"}, {18094, "searchSSL"},
	{18095, "analyticsSSL"}, {18096, "eventingSSL"}, {18097, "backupSSL"}, {11207, "kvSSL"},
}

// Services an SDK connects to; a cluster also advertises node-internal ports no client ever uses
var sdkServices = map[string]bool{
	"kv": true, "mgmt": true, "capi": true, "n1ql": true, "fts": true, "cbas": true,
	"kvSSL": true, "mgmtSSL": true, "capiSSL": true, "n1qlSSL": true, "ftsSSL": true, "cbasSSL": true,
}

func isSDKService(name string, useTLS bool) bool {
	return sdkServices[name] && strings.HasSuffix(name, "SSL") == useTLS
}

func nodeAdvertisesPort(node clusterNode, port int, useTLS bool) bool {
	if port == 0 {
		return false
	}

	for name, servicePort := range node.Services {
		if servicePort == port && isSDKService(name, useTLS) {
			return true
		}
	}

	return false
}

func countAdvertisingNodes(nodes []clusterNode, port int, useTLS bool) int {
	count := 0
	for _, node := range nodes {
		if nodeAdvertisesPort(node, port, useTLS) {
			count++
		}
	}
	return count
}

func matrixPorts(nodes []clusterNode, useTLS bool) []portDef {
	names := map[int]string{}
	for _, p := range couchbasePorts {
		names[p.Port] = p.Name
	}

	for _, node := range nodes {
		for name, port := range node.Services {
			if port == 0 {
				continue
			}

			currentName, found := names[port]
			if !found || (!isSDKService(currentName, useTLS) && isSDKService(name, useTLS)) {
				names[port] = name
			}
		}
	}

	ports := make([]portDef, 0, len(names))
	for port, name := range names {
		ports = append(ports, portDef{port, name})
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i].Port < ports[j].Port })

	return ports
}

func probePort(host string, port int, timeout time.Duration) string {
	conn, err := net.DialTimeout("tcp", helpers.HostPort(host, port), timeout)
	if err == nil {
		conn.Close()
		return "open"
	}

	if helpers.IsConnRefused(err) {
		return "refused"
	}

	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return "filtered"
	}

	return "error"
}

// isDialFailure reports whether err is a connect failure rather than a TLS or auth rejection
func isDialFailure(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}

	var opErr *net.OpError
	return errors.As(err, &opErr) && opErr.Op == "dial"
}

// httpProbeUnreachable reports whether a failed HTTP service probe never reached the service at all; the client timeout cancels the whole request, so a host that drops packets fails with a context deadline rather than a dial error
func httpProbeUnreachable(err error, timing memd.ConnectTiming) bool {
	return isDialFailure(err) || timing.TCPDone.IsZero()
}

func scanPortMatrix(nodes []clusterNode, useTLS bool) {
	ports := matrixPorts(nodes, useTLS)
	var displayedPorts []int
	for j, p := range ports {
		for _, node := range nodes {
			if nodeAdvertisesPort(node, p.Port, useTLS) {
				displayedPorts = append(displayedPorts, j)
				break
			}
		}
	}

	gLog.Log("Scanning %d Couchbase ports across all %d node(s); showing %d advertised client-facing port(s), n/a means the port is not advertised on that node",
		len(ports), len(nodes), len(displayedPorts))

	results := make([][]string, len(nodes))

	// Reused by every port probe; a node behind several A records is probed at the first only
	addrs := make([]string, len(nodes))
	for i, node := range nodes {
		results[i] = make([]string, len(ports))

		ips, err := net.LookupHost(helpers.BareHost(node.Hostname))
		if err == nil && len(ips) == 0 {
			err = fmt.Errorf("no addresses found")
		}
		if err != nil {
			for j := range ports {
				results[i][j] = "dns"
			}

			gLog.Error(
				"Node `%s` advertised by the cluster does not resolve from this host (error: %s)."+
					"  None of its ports can be probed.",
				node.Hostname, err)

			continue
		}

		addrs[i] = ips[0]
	}

	sem := make(chan struct{}, 32)
	var wg sync.WaitGroup

	for i := range nodes {
		if addrs[i] == "" {
			continue
		}

		for j := range ports {
			wg.Add(1)

			go func(i, j int) {
				defer wg.Done()

				sem <- struct{}{}
				defer func() { <-sem }()

				results[i][j] = probePort(addrs[i], ports[j].Port,
					2000*time.Millisecond)
			}(i, j)
		}
	}
	wg.Wait()

	for i, node := range nodes {
		for j, p := range ports {
			gReport.Ports = append(gReport.Ports,
				portResult{node.Hostname, p.Port, p.Name, results[i][j],
					nodeAdvertisesPort(node, p.Port, useTLS)})
		}
	}

	nameWidth := len("PORT MATRIX")
	for _, node := range nodes {
		if len(node.Hostname) > nameWidth {
			nameWidth = len(node.Hostname)
		}
	}

	const portsPerRow = 8
	for start := 0; start < len(displayedPorts); start += portsPerRow {
		end := start + portsPerRow
		if end > len(displayedPorts) {
			end = len(displayedPorts)
		}

		header := fmt.Sprintf("%-*s", nameWidth, "PORT MATRIX")
		for _, j := range displayedPorts[start:end] {
			header += fmt.Sprintf(" %8d", ports[j].Port)
		}
		gLog.Log("%s", header)

		for i, node := range nodes {
			row := fmt.Sprintf("%-*s", nameWidth, node.Hostname)
			for _, j := range displayedPorts[start:end] {
				state := "n/a"
				if nodeAdvertisesPort(node, ports[j].Port, useTLS) {
					state = results[i][j]
				}
				row += fmt.Sprintf(" %8s", state)
			}
			gLog.Log("%s", row)
		}
	}

	refusedAdvertised := map[string][]string{}

	for j, p := range ports {
		var filtered, refused, open []string
		advertisedNodes := countAdvertisingNodes(nodes, p.Port, useTLS)

		for i, node := range nodes {
			if addrs[i] == "" || !nodeAdvertisesPort(node, p.Port, useTLS) {
				continue
			}

			switch results[i][j] {
			case "filtered":
				filtered = append(filtered, node.Hostname)
			case "refused":
				refused = append(refused, node.Hostname)
			case "open":
				open = append(open, node.Hostname)
			}
		}

		if len(filtered) > 0 && len(filtered) == advertisedNodes {
			gLog.Error(
				"Port %d (%s) is filtered on all %d node(s) advertising it.  Packets are being"+
					" dropped rather than refused, which indicates a firewall or network policy"+
					" rather than a stopped service.",
				p.Port, p.Name, advertisedNodes)
		} else if len(filtered) > 0 {
			gLog.Warn(
				"Port %d (%s) is filtered on `%s` but not confirmed on every node advertising it."+
					"  This can indicate a per-host firewall rule; review the other node results above.",
				p.Port, p.Name, strings.Join(filtered, ", "))
		}

		if len(refused) > 0 {
			hosts := strings.Join(refused, ", ")
			refusedAdvertised[hosts] = append(refusedAdvertised[hosts],
				fmt.Sprintf("%d (%s)", p.Port, p.Name))
		}

		if len(refused) > 0 && len(open) > 0 {
			gLog.Warn(
				"Port %d (%s) is refused on `%s` but open on %d other node(s).  Either nothing"+
					" is listening there, or a firewall is rejecting the connection rather than"+
					" dropping it.",
				p.Port, p.Name, strings.Join(refused, ", "), len(open))
		}
	}

	hostGroups := make([]string, 0, len(refusedAdvertised))
	for hosts := range refusedAdvertised {
		hostGroups = append(hostGroups, hosts)
	}
	sort.Strings(hostGroups)

	for _, hosts := range hostGroups {
		gLog.Warn(
			"Cluster advertises %d client-facing port(s) on `%s` which refuse connections: %s."+
				"  Either nothing is listening on them, or a firewall is rejecting the"+
				" connections; either way clients using those services will fail to connect.",
			len(refusedAdvertised[hosts]), hosts, strings.Join(refusedAdvertised[hosts], ", "))
	}
}

// A client opens a connection per node per service, and the runtime needs headroom besides
const minFDLimit = 1024

func logHostInfo() {
	info := helpers.GatherHostInfo()
	gReport.Host = &info

	gLog.Log("Running on %s/%s (%s)", info.OS, info.Arch, info.GoVersion)

	if info.FDLimit > 0 {
		gLog.Log("Open file limit for this process is %d", info.FDLimit)

		if info.FDLimit < minFDLimit {
			gLog.Warn(
				"This host allows only %d open files per process.  An application holding"+
					" connections to every node and service can exhaust that and fail with"+
					" `too many open files` under load.",
				info.FDLimit)
		}
	}

	gLog.Log("Network interfaces that are up:")
	for _, iface := range info.Interfaces {
		if !iface.Up || len(iface.Addresses) == 0 {
			continue
		}

		gLog.Log("  %s: mtu %d, %s", iface.Name, iface.MTU, strings.Join(iface.Addresses, ", "))
	}

	if len(info.Proxy) > 0 {
		gLog.Warn(
			"Proxy environment variables are set on this host (%s).  The doctor connects"+
				" directly and ignores them, so an application whose HTTP client honours them"+
				" reaches the cluster by a different path than the one diagnosed here.",
			strings.Join(info.Proxy, ", "))
	}
}

func diagnose(connStr, username, password string, tlsConfig *tls.Config) {
	//======================================================================
	//  HOST ENVIRONMENT
	//======================================================================
	logHostInfo()

	//======================================================================
	//  CONNECTION STRING
	//======================================================================
	gLog.Log("Parsing connection string `%s`", connStr)

	connSpec, err := gocbconnstr.Parse(connStr)
	if err != nil {
		gLog.Error("Failed to parse connection string of `%s` (error: %s)",
			connStr, err.Error())
	}

	connSpecSrv := connSpec.SrvRecordName()
	if connSpecSrv != "" {
		gLog.Log("Connection string was parsed as a potential DNS SRV record")
	}

	if connSpec.Scheme == "http" {
		gLog.Warn(
			"Connection string is using the deprecated `http://` scheme.  Use" +
				" the `couchbase://` scheme instead!")
	}

	resConnSpec, err := gocbconnstr.Resolve(connSpec)
	if err != nil {
		gLog.Error("Failed to properly resolve connection string `%s` (error: %s)",
			connStr, err.Error())
	}

	if resConnSpec.UseSsl {
		gLog.Log("Connection string specifies to use secured connections")
	}

	gLog.Log("Connection string identifies the following CCCP endpoints:")
	for i, host := range resConnSpec.MemdHosts {
		gLog.Log("  %d. %s:%d", i+1, host.Host, host.Port)
	}

	gLog.Log("Connection string identifies the following HTTP endpoints:")
	for i, host := range resConnSpec.HttpHosts {
		gLog.Log("  %d. %s:%d", i+1, host.Host, host.Port)
	}

	gLog.Log("Connection string specifies bucket `%s`", resConnSpec.Bucket)

	gReport.Bucket = resConnSpec.Bucket

	//======================================================================
	//  SSL
	//======================================================================
	if resConnSpec.UseSsl {
		if tlsConfig == nil {
			gLog.Warn("No certificate authority file specified (--tls-ca), skipping" +
				" server certificate verification for this run.")

			tlsConfig = &tls.Config{
				InsecureSkipVerify: true,
			}
		}
	} else {
		tlsConfig = nil
	}

	//======================================================================
	//  DNS
	//======================================================================
	warnSingleHost := false
	if len(connSpec.Addresses) == 1 {
		warnSingleHost = true
	}

	dnsHosts := connSpec.Addresses
	if connSpecSrv != "" {
		_, srvAddrs, _ := net.LookupSRV("", "", connSpecSrv)
		aAddrs, _ := net.LookupHost(connSpec.Addresses[0].Host)

		if len(srvAddrs) > 0 {
			// Don't warn for single-hosts if using DNS SRV
			warnSingleHost = false

			// Replace the hosts for DNS testing with the values from the DNS SRV record
			dnsHosts = []gocbconnstr.Address{}
			for _, addr := range srvAddrs {
				addrTarget := addr.Target
				addrPort := int(addr.Port)

				if !strings.HasSuffix(addrTarget, ".") {
					gLog.Warn(
						"The hostname specified in one of the SRV records was missing the trailing" +
							" dot which is expected to make a valid SRV record entry.")
				}

				addrTarget = strings.TrimSuffix(addrTarget, ".")

				dnsHosts = append(dnsHosts, gocbconnstr.Address{
					Host: addrTarget,
					Port: addrPort,
				})
			}
		}

		if len(srvAddrs) > 0 && len(aAddrs) > 0 {
			gLog.Warn(
				"The hostname specified in your connection string resolves both for SRV" +
					" records, as well as A records.  This is not suggested as later DNS" +
					" configuration changes could cause the wrong servers to be contacted")
		}
	}

	if warnSingleHost {
		gLog.Warn(
			"Your connection string specifies only a single host.  You should" +
				" consider adding additional static nodes from your cluster to this" +
				" list to improve your applications fault-tolerance")
	}

	for _, target := range dnsHosts {
		strippedHost := helpers.BareHost(target.Host)

		gLog.Log("Performing DNS lookup for host `%s`", strippedHost)

		addrs, err := net.LookupHost(strippedHost)

		if err != nil {
			if dnsErr, ok := err.(*net.DNSError); ok {
				if dnsErr.Err == "no such host" {
					err = nil
					addrs = nil
				}
			} else {
				gLog.Error(
					"Failed to perform DNS lookup for bootstrap entry `%s` (error: %s)",
					strippedHost, err)
				continue
			}
		}

		if err != nil || len(addrs) == 0 {
			gLog.Error(
				"Bootstrap host `%s` does not have a valid DNS entry.",
				strippedHost)
			continue
		} else if len(addrs) > 1 {
			gLog.Warn(
				"Bootstrap host `%s` has more than one single DNS entry associated.  While this"+
					" is not neccessarily an error, it has been known to cause difficult-to-diagnose"+
					" problems in the future when routing is changed or the cluster layout is updated.",
				strippedHost)
		} else if addrs[0] != strippedHost {
			gLog.Log(
				"Bootstrap host `%s` refers to a server with the address `%s`",
				strippedHost, addrs[0])
		}

		// Check for any IPv6 addresses
		ips, _ := net.LookupIP(strippedHost)

		hasIPv6 := false
		for _, ip := range ips {
			if ip.To4() == nil {
				hasIPv6 = true
			}
		}
		if hasIPv6 {
			gLog.Log(
				"Bootstrap host `%s` has IPv6 addresses associated. This is only supported"+
					" in Couchbase Server 5.5 or later, and must be specifically enabled on"+
					" the cluster.",
				strippedHost)
		}
	}

	//======================================================================
	//  BOOTSTRAP
	//======================================================================
	var nodesList []clusterNode
	var selectedNetwork string
	var configSource string

	// Attempt to bootstrap via CCCP
	if nodesList == nil {
		if len(resConnSpec.MemdHosts) == 0 {
			gLog.Log("Not attempting CCCP, as the connection string does not support it")
		} else {
			gLog.Log("Attempting to connect to cluster via CCCP")

			configs := make([]*terseBucketConfig, len(resConnSpec.MemdHosts))

			for i, target := range resConnSpec.MemdHosts {
				gLog.Log("Attempting to fetch config via cccp from `%s:%d`", target.Host, target.Port)

				// Query the host
				config, attempt, err := fetchCccpTerseBucketConfig(target.Host, target.Port, resConnSpec.Bucket, username, password, tlsConfig)
				recordAttempt(attempt)
				if err != nil {
					gLog.Error(
						"Failed to fetch configuration via cccp from `%s:%d` (error: %s)",
						target.Host, target.Port, err.Error())

					continue
				}

				configs[i] = &config
			}

			masterConfig := scanTerseConfigList(resConnSpec.MemdHosts, configs)
			if masterConfig != nil {
				if selectedNetwork == "" {
					selectedNetwork = networkFromTerseBucketConfig(*masterConfig)
				}
				nodesList = nodesFromMasterConfig(*masterConfig, selectedNetwork)
				configSource = "cccp"
			}
		}
	}

	// Attempt to bootstrap via Terse HTTP endpoints
	if nodesList == nil {
		if len(resConnSpec.HttpHosts) == 0 {
			gLog.Log("Not attempting HTTP (Terse), as the connection string does not support it")
		} else {
			gLog.Log("Attempting to connect to cluster via HTTP (Terse)")

			configs := make([]*terseBucketConfig, len(resConnSpec.HttpHosts))

			for i, target := range resConnSpec.HttpHosts {
				gLog.Log("Attempting to fetch terse config via http from `%s:%d`", target.Host, target.Port)

				// Query the host
				config, attempt, err := fetchHTTPTerseBucketConfig(target.Host, target.Port, resConnSpec.Bucket, username, password, tlsConfig)
				recordAttempt(attempt)
				if err != nil {
					gLog.Error(
						"Failed to fetch terse configuration via http from `%s:%d` (error: %s)",
						target.Host, target.Port, err.Error())

					continue
				}

				configs[i] = &config
			}

			masterConfig := scanTerseConfigList(resConnSpec.HttpHosts, configs)
			if masterConfig != nil {
				if selectedNetwork == "" {
					selectedNetwork = networkFromTerseBucketConfig(*masterConfig)
				}
				nodesList = nodesFromMasterConfig(*masterConfig, selectedNetwork)
				configSource = "http-terse"
			}
		}
	}

	// Attempt to bootstrap via full HTTP endpoints
	if nodesList == nil {
		if len(resConnSpec.HttpHosts) == 0 {
			gLog.Log("Not attempting HTTP (Full), as the connection string does not support it")
		} else {
			gLog.Log("Attempting to connect to cluster via HTTP (Full)")

			// TODO: Add support for full HTTP configuration fetching

			gLog.Log("Failed to connect via HTTP (Full), as it is not yet supported by the doctor")
		}
	}

	// Failed to bootstrap
	if nodesList == nil {
		if len(gReport.Attempts) > 0 {
			gLog.NewLine()
			fmt.Fprint(gLog.Writer(), "Bootstrap attempts:\n")
			fmt.Fprint(gLog.Writer(), renderAttemptTable(gReport.Attempts))
			gLog.NewLine()
		}

		reportBootstrapTLSChain(gReport.Attempts)

		gLog.Error("%s", bootstrapSummary(gReport.Attempts, resConnSpec.Bucket))

		return
	}

	// Print out information about which network type was selected
	gLog.Log("Selected the following network type: %s", selectedNetwork)

	gReport.Network = selectedNetwork
	gReport.ConfigSource = configSource
	gReport.Nodes = nodesList

	gLog.Log("Identified the following nodes:")
	for i, target := range nodesList {
		gLog.Log("  [%d] %s", i, target.Hostname)

		serviceStr := ""
		serviceNum := 0
		for service, port := range target.Services {
			if serviceStr != "" {
				serviceStr += ", "
			}

			serviceStr += fmt.Sprintf("%20s:% 6d", service, port)

			if serviceNum%3 == 2 {
				gLog.Log("    %s", serviceStr)
				serviceStr = ""
			}

			serviceNum++
		}

		if serviceStr != "" {
			gLog.Log("    %s", serviceStr)
		}
	}

	if configSource != "cccp" {
		gLog.Warn(
			"Your configuration was fetched via a non-optimal path, you should update your" +
				" connection string and/or cluster configuration to allow CCCP config fetch")
	}

	//======================================================================
	//  CLUSTER INFORMATION
	//======================================================================
	{
		var infoSourceTarget *clusterNode

		infoSourceSvcKey := "mgmt"
		infoSourceScheme := "http"
		if tlsConfig != nil {
			infoSourceSvcKey = "mgmtSSL"
			infoSourceScheme = "https"
		}

		for i := range nodesList {
			if nodesList[i].Services[infoSourceSvcKey] != 0 {
				infoSourceTarget = &nodesList[i]
				break
			}
		}

		if infoSourceTarget == nil {
			gLog.Log("Failed to retrieve cluster information as we couldn't find a node with management services")
		} else {
			infoSourceHost := infoSourceTarget.Hostname
			infoSourcePort := infoSourceTarget.Services[infoSourceSvcKey]

			gLog.Log("Fetching config from `%s://%s:%d`",
				infoSourceScheme,
				infoSourceHost,
				infoSourcePort)

			httpTransport := &http.Transport{
				TLSClientConfig: tlsConfigForHost(tlsConfig, infoSourceHost),
			}
			httpClient := &http.Client{
				Transport:     httpTransport,
				Timeout:       2000 * time.Millisecond,
				CheckRedirect: refuseRedirect,
			}

			uri := (&url.URL{
				Scheme: infoSourceScheme,
				Host:   helpers.HostPort(infoSourceHost, infoSourcePort),
				Path:   "/pools/default",
			}).String()

			var resp *http.Response

			req, err := http.NewRequest("GET", uri, nil)
			if err == nil {
				req.SetBasicAuth(username, password)

				resp, err = httpClient.Do(req)
			}

			if err != nil {
				gLog.Log("Failed to retreive cluster information (error: %s)", err.Error())
			} else if resp.StatusCode != 200 {
				resp.Body.Close()
				gLog.Log("Failed to retreive cluster information (status code: %d)", resp.StatusCode)
			} else {
				if serverTime, dateErr := http.ParseTime(resp.Header.Get("Date")); dateErr == nil {
					skew := time.Since(serverTime)

					direction := "ahead of"
					if skew < 0 {
						skew = -skew
						direction = "behind"
					}

					if skew < 2*time.Second {
						gLog.Log("Local clock is in sync with node `%s`", infoSourceHost)
					} else {
						gReport.ClockSkew = fmt.Sprintf("%s %s the cluster",
							skew.Round(time.Second), direction)

						gLog.Log("Local clock is %s %s node `%s`",
							skew.Round(time.Second), direction, infoSourceHost)
					}

					if skew >= 30*time.Second {
						gLog.Error(
							"Local clock is %s %s node `%s`.  Clock skew breaks certificate"+
								" validation and makes correlating client and cluster logs unreliable.",
							skew.Round(time.Second), direction, infoSourceHost)
					}
				}

				var clusterConfig map[string]interface{}
				json.NewDecoder(resp.Body).Decode(&clusterConfig)
				resp.Body.Close()

				fmtdConfigNodes, _ := json.MarshalIndent(clusterConfig["nodes"], "", "  ")
				gLog.Log("Received cluster configuration, nodes list:\n%s", fmtdConfigNodes)
			}
		}
	}

	//======================================================================
	//  PORT MATRIX
	//======================================================================
	scanPortMatrix(nodesList, tlsConfig != nil)

	//======================================================================
	//  SERVICES
	//======================================================================
	var svcOk, svcFailed, svcUnreachable, svcRefused, svcStatus, svcMalformed int

	// One cert covers every service on a node
	tlsReported := map[string]bool{}

	var testHTTPClient *http.Client

	testMemdService := func(node clusterNode, svcName, svcKeyPlain, svcKeySSL string) {
		svcKey := svcKeyPlain
		if tlsConfig != nil {
			svcKey = svcKeySSL
		}

		svcPort := node.Services[svcKey]
		if svcPort != 0 {
			client, builder, err := helpers.Dial("service-"+svcKeyPlain, node.Hostname, svcPort,
				resConnSpec.Bucket, username, password, tlsConfig)
			if err != nil {
				recordAttempt(builder.FromDial(err))

				svcFailed++
				if helpers.IsConnRefused(err) {
					svcRefused++
				} else if isDialFailure(err) {
					svcUnreachable++
				} else if tlsConfig != nil && !tlsReported[node.Hostname] {
					tlsReported[node.Hostname] = probeTLSChain(node.Hostname, svcPort)
				}

				gLog.Error("Failed to connect to %s service at `%s:%d` (error: %s)",
					svcName, node.Hostname, node.Services[svcKey], err.Error())
			} else {
				svcOk++
				gLog.Log("Successfully connected to %s service at `%s:%d`",
					svcName, node.Hostname, node.Services[svcKey])

				recordAttempt(builder.Finish(builder.Reached(), "", nil))
				client.Close()
			}
		} else {
			gLog.Log("Not testing %s service on `%s`, the node does not run it", svcName, node.Hostname)
		}
	}

	testHTTPService := func(node clusterNode, svcName, svcKeyPlain, svcKeySSL string) {
		svcScheme := "http"
		svcKey := svcKeyPlain
		if tlsConfig != nil {
			svcScheme = "https"
			svcKey = svcKeySSL
		}

		svcPort := node.Services[svcKey]
		if svcPort == 0 {
			gLog.Log("Not testing %s service on `%s`, the node does not run it", svcName, node.Hostname)
			return
		}

		path, healthEndpoint := healthPaths[svcKeyPlain], true
		if path == "" {
			path, healthEndpoint = "/", false
		}

		endpoint := helpers.HostPort(node.Hostname, svcPort)

		builder := helpers.NewAttempt("service-"+svcKeyPlain, endpoint, serviceProbeBudget)

		if !helpers.HostIsUsable(node.Hostname) {
			err := fmt.Errorf("advertised hostname `%s` is not a usable host or IP literal", node.Hostname)

			recordAttempt(builder.Finish(helpers.PhaseNone, helpers.CategoryUnknown, err))

			svcFailed++
			svcMalformed++

			gLog.Error("Cannot probe %s service at `%s`, the cluster advertises an address"+
				" that cannot be used in a URL (error: %s)", svcName, endpoint, err)

			return
		}

		uri := (&url.URL{Scheme: svcScheme, Host: endpoint, Path: path}).String()

		req, err := http.NewRequest("GET", uri, nil)
		if err != nil {
			recordAttempt(builder.Finish(helpers.PhaseNone, helpers.CategoryUnknown, err))

			svcFailed++
			svcMalformed++

			gLog.Error("Cannot probe %s service at `%s`, the cluster advertises an address"+
				" that cannot be used in a URL (error: %s)", svcName, endpoint, err)

			return
		}

		if probeNeedsCredentials(svcKeyPlain) && username != "" {
			req.SetBasicAuth(username, password)
		}

		req, trace := traceRequest(req)

		resp, err := testHTTPClient.Do(req)
		if err != nil {
			timing := trace.Timing()
			phase := httpFailurePhase(timing, trace.TLSHandshakeDone(), err)

			recordAttempt(withSocket(builder, trace).
				WithHTTP(helpers.HTTPProbe{Path: path, HealthEndpoint: healthEndpoint}).
				Finish(phase, helpers.Classify(phase, err), err))

			svcFailed++
			if helpers.IsConnRefused(err) {
				svcRefused++
			} else if httpProbeUnreachable(err, timing) {
				svcUnreachable++
			} else if tlsConfig != nil && !tlsReported[node.Hostname] {
				tlsReported[node.Hostname] = probeTLSChain(node.Hostname, svcPort)
			}

			gLog.Error("Failed to connect to %s service at `%s:%d` (error: %s)",
				svcName, node.Hostname, svcPort, err.Error())

			return
		}
		defer resp.Body.Close()

		probe := helpers.HTTPProbe{
			Path:           path,
			HealthEndpoint: healthEndpoint,
			Status:         resp.StatusCode,
			Server:         resp.Header.Get("Server"),
		}
		if resp.StatusCode/100 == 3 {
			probe.Redirect = resp.Header.Get("Location")
		}
		if latency, ok := trace.Latency(); ok {
			probe.Latency = dur(latency)
		}

		if resp.TLS != nil && !tlsReported[node.Hostname] {
			tlsReported[node.Hostname] = true

			logTLSChainInfo(node.Hostname, svcPort,
				helpers.BuildTLSChainInfo(resp.TLS, node.Hostname, time.Now()))
		}

		if resp.StatusCode >= 400 {
			probe.Body = boundedBody(resp.Body)
		}

		verdict := verdictForStatus(healthEndpoint, resp.StatusCode)

		if verdict == probeUnhealthy {
			statusErr := fmt.Errorf("http status %d", resp.StatusCode)
			recordAttempt(withSocket(builder, trace).WithHTTP(probe).
				Finish(helpers.PhaseResponse, helpers.CategoryForServiceHTTPStatus(resp.StatusCode), statusErr))

			svcFailed++
			svcStatus++

			gLog.Error(
				"%s service at `%s:%d` answered `%s` with HTTP %d%s.  The endpoint was reached,"+
					" so this is the service's own answer rather than a network fault.",
				svcName, node.Hostname, svcPort, path, resp.StatusCode, bodyClause(probe.Body))

			return
		}

		timing := trace.Timing()
		logConnectPhases(withSocket(builder, trace).WithHTTP(probe).
			Finish(helpers.PhaseResponse, "", nil), timing)

		svcOk++

		switch verdict {
		case probeReachable:
			gLog.Log(
				"Successfully connected to %s service at `%s:%d` (HTTP %d%s).  No documented"+
					" health endpoint exists for this service, so its reachability was tested"+
					" but its application health was not.",
				svcName, node.Hostname, svcPort, resp.StatusCode, latencyClause(probe.Latency))
		case probeHealthUntested:
			gLog.Warn(
				"%s service at `%s:%d` answered `%s` with HTTP %d%s rather than serving the"+
					" documented health endpoint.  The service was reached, but its application"+
					" health was not tested; an older server version or a proxy in front of the"+
					" port would both produce this.",
				svcName, node.Hostname, svcPort, path, resp.StatusCode, redirectClause(probe.Redirect))
		default:
			gLog.Log("%s service at `%s:%d` reported healthy on `%s` (HTTP %d%s)",
				svcName, node.Hostname, svcPort, path, resp.StatusCode, latencyClause(probe.Latency))
		}
	}

	for _, node := range nodesList {
		testHTTPClient = newServiceProbeClient(tlsConfigForHost(tlsConfig, node.Hostname))
		testMemdService(node, "Key Value", "kv", "kvSSL")
		testHTTPService(node, "Management", "mgmt", "mgmtSSL")
		testHTTPService(node, "Views", "capi", "capiSSL")
		testHTTPService(node, "Query", "n1ql", "n1qlSSL")
		testHTTPService(node, "Search", "fts", "ftsSSL")
		testHTTPService(node, "Analytics", "cbas", "cbasSSL")
	}

	if svcOk == 0 && svcFailed == 0 {
		gLog.Error(
			"No node advertises any client service port on the `%s` network, so no service could"+
				" be tested.  Check that the cluster is configured for the scheme in your"+
				" connection string, and that alternate addresses, if used, map the service ports.",
			selectedNetwork)
	} else if svcOk == 0 && svcFailed > 0 && svcUnreachable == svcFailed {
		gLog.Error(
			"Bootstrap succeeded but every one of the %d advertised service endpoints was"+
				" unreachable.  This is the signature of a client sitting outside the cluster's"+
				" network: the nodes are advertising hostnames on the `%s` network that do not"+
				" resolve or route from here.  Configure alternate addresses on the cluster so"+
				" it advertises externally reachable hostnames to clients like this one.",
			svcFailed, selectedNetwork)
	} else if svcOk == 0 && svcFailed > 0 && svcRefused == svcFailed {
		gLog.Error(
			"Bootstrap succeeded but every one of the %d advertised service endpoints refused"+
				" the connection.  The nodes are reachable and answered, so this is not a network"+
				" problem: the services are not running, or they are not listening on the ports"+
				" the cluster advertises on the `%s` network.",
			svcFailed, selectedNetwork)
	} else if svcOk == 0 && svcFailed > 0 && svcStatus == svcFailed {
		gLog.Error(
			"Bootstrap succeeded and every one of the %d advertised service endpoints answered,"+
				" but each one reported an error status rather than health.  The network path and"+
				" the handshake are both fine, so the fault is in the services themselves or in"+
				" the credentials' access to them.  The per-service errors above name the status.",
			svcFailed)
	} else if svcOk == 0 && svcFailed > 0 && svcMalformed == svcFailed {
		gLog.Error(
			"Bootstrap succeeded but none of the %d advertised service endpoints could be"+
				" probed, because the addresses the cluster advertises on the `%s` network"+
				" cannot be used in a URL.  The per-endpoint errors above name each one.  This"+
				" is a cluster configuration fault rather than a network one: fix the node"+
				" hostnames, or the alternate addresses, that the cluster hands to clients.",
			svcFailed, selectedNetwork)
	} else if svcOk == 0 && svcFailed > 0 && svcUnreachable == 0 && svcRefused == 0 &&
		svcStatus == 0 && svcMalformed == 0 {
		checks := "that the credentials are valid"
		if tlsConfig != nil {
			checks = fmt.Sprintf("that the certificate authority you passed signs the cluster's"+
				" certificates, that those certificates cover the hostnames the cluster"+
				" advertises on the `%s` network, and that the credentials are valid",
				selectedNetwork)
		}

		gLog.Error(
			"Bootstrap succeeded and every one of the %d advertised service endpoints accepted"+
				" the connection, but none of them completed it.  The network path is fine, so"+
				" the fault is in the handshake itself: check %s.  The per-service errors above"+
				" name the specific failure.",
			svcFailed, checks)
	}

	//======================================================================
	//  CONNECTION PERFORMANCE
	//======================================================================
	var idlers []idleTarget

	for _, node := range nodesList {
		kvPort := node.Services["kv"]
		if tlsConfig != nil {
			kvPort = node.Services["kvSSL"]
		}

		if kvPort != 0 {
			client, builder, err := helpers.Dial("perf-kv", node.Hostname, kvPort,
				resConnSpec.Bucket, username, password, tlsConfig)
			if err != nil {
				recordAttempt(builder.FromDial(err))

				gLog.Warn(
					"Failed to perform KV connection performance analysis on `%s:%d` (error: %s)",
					node.Hostname, kvPort, err.Error())
				continue
			}

			attempt := builder.Finish(builder.Reached(), "", nil)
			logConnectPhases(attempt, client.Timing())

			firstOpStart := time.Now()
			firstOpErr := client.Ping()
			firstOpDuration := time.Since(firstOpStart)
			if firstOpErr != nil {
				gLog.Error("First operation on `%s:%d` failed after %s (error: %s)",
					node.Hostname, kvPort, dur(firstOpDuration), firstOpErr)
			} else {
				gLog.Log("First operation on `%s:%d` completed in %s",
					node.Hostname, kvPort, dur(firstOpDuration))
			}

			if client.TLSState() != nil && !tlsReported[node.Hostname] {
				tlsReported[node.Hostname] = true

				logTLSChainInfo(node.Hostname, kvPort,
					helpers.BuildTLSChainInfo(client.TLSState(), node.Hostname, time.Now()))
			}

			var stats helpers.PingHelper
			sampleSurvived := sampleKVLatency(client, &stats, firstOpErr != nil)
			if !sampleSurvived {
				gLog.Error(
					"Sampling of `%s:%d` stopped early after %d consecutive failed pings, the"+
						" connection did not survive the run.",
					node.Hostname, kvPort, kvMaxErrorStreak)
			}

			// Read before the possible early exit below, as a failing connection is exactly
			// when retransmit/loss counts are most useful for explaining why
			if counters, ok := client.TCPCounters(); ok {
				gLog.Log(
					"TCP counters for `%s:%d`: rtt %s, rttvar %s, cwnd %d, retransmits %d, lost %d",
					node.Hostname, kvPort,
					dur(counters.RTT), dur(counters.RTTVar),
					counters.CongestionWindow, counters.TotalRetransmits, counters.Lost)

				gReport.TCPCounters = append(gReport.TCPCounters, tcpCountersResult{
					Host: node.Hostname, Port: kvPort,
					RTT: dur(counters.RTT), RTTVar: dur(counters.RTTVar),
					CongestionWindow: counters.CongestionWindow,
					TotalRetransmits: counters.TotalRetransmits,
					Lost:             counters.Lost,
				})
			}

			if stats.Successes() == 0 {
				gLog.Error("All %d pings to `%s:%d` failed, no latency statistics are available",
					stats.Count(), node.Hostname, kvPort)

				client.Close()
				continue
			}

			latencies := fmt.Sprintf("min %s, p50 %s, p90 %s",
				dur(stats.Min()), dur(stats.Percentile(50)), dur(stats.Percentile(90)))

			// Below 100 samples the 99th percentile is simply the max, so it is not worth a column
			if stats.Successes() >= 100 {
				latencies += fmt.Sprintf(", p99 %s", dur(stats.Percentile(99)))
			}

			gLog.Log(
				"Memd Nop Pinged `%s:%d` %d times, %d errors: %s, max %s, stddev %s",
				node.Hostname, kvPort,
				stats.Count(), stats.Errors(),
				latencies, dur(stats.Max()), dur(stats.StdDev()))

			suspects := helpers.RTOSuspects(stats.Samples(), rtoMinArg)

			gReport.Latency = append(gReport.Latency, latencyResult{
				Host: node.Hostname, Port: kvPort,
				Samples: stats.Count(), Errors: stats.Errors(),
				FirstOp: dur(firstOpDuration),
				Min:     dur(stats.Min()), Mean: dur(stats.Mean()),
				P50: dur(stats.Percentile(50)), P90: dur(stats.Percentile(90)),
				P99: dur(stats.Percentile(99)), Max: dur(stats.Max()),
				StdDev:      dur(stats.StdDev()),
				RTOSuspects: durs(suspects),
			})

			if len(suspects) > 0 {
				gLog.Error(
					"%d of %d samples on `%s:%d` landed on a TCP retransmission timeout"+
						" multiple (slowest: %s).  This is the signature of packet loss on"+
						" this path rather than of general latency.",
					len(suspects), stats.Successes(), node.Hostname, kvPort,
					dur(suspects[len(suspects)-1]))
			}

			allowedMeanMs := 10
			if stats.Mean() >= time.Duration(allowedMeanMs)*time.Millisecond {
				gLog.Warn(
					"Memcached service on `%s:%d` on average took longer than %dms (was: %s) to"+
						" reply.  This is usually due to network-related issues, and could significantly"+
						" affect application performance.",
					node.Hostname, kvPort,
					allowedMeanMs, dur(stats.Mean()))
			}

			tailName := "at its slowest"
			if stats.Successes() >= 100 {
				tailName = "at the 99th percentile"
			}

			allowedMaxMs := 20
			tail := stats.Percentile(99)
			if tail >= time.Duration(allowedMaxMs)*time.Millisecond {
				gLog.Warn(
					"Memcached service on `%s:%d` %s took longer than %dms (was: %s) to reply."+
						"  This is usually due to network-related issues, and could significantly"+
						" affect application performance.",
					node.Hostname, kvPort,
					tailName, allowedMaxMs, dur(tail))
			}

			if idleTestArg > 0 && sampleSurvived {
				idlers = append(idlers, idleTarget{node.Hostname, kvPort})
			}

			client.Close()
		}
	}

	runIdleTest(idlers, resConnSpec.Bucket, username, password, tlsConfig)
}
