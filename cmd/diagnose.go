package cmd

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptrace"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/couchbaselabs/gocbconnstr"
	"github.com/couchbaselabs/sdk-doctor/helpers"
	"github.com/couchbaselabs/sdk-doctor/memd"
	"github.com/spf13/cobra"
)

func stripIPv6Address(address string) string {
	if strings.HasPrefix(address, "[") && strings.HasSuffix(address, "]") {
		return address[1 : len(address)-1]
	}
	return address
}

const certExpiryWarnDays = 30

func logTLSChainInfo(host string, port int, info helpers.TLSChainInfo) {
	if len(info.Chain) == 0 {
		return
	}

	leaf := info.Chain[0]

	gLog.Log(
		"TLS on `%s:%d`: %s, %s, subject `%s`",
		host, port, info.VersionName, info.CipherName, leaf.Subject)

	if leaf.DaysToExpiry < 0 {
		gLog.Warn(
			"Certificate for `%s:%d` expired %d days ago (%s).",
			host, port, -leaf.DaysToExpiry, leaf.NotAfter.Format("2006-01-02"))
	} else if leaf.DaysToExpiry <= certExpiryWarnDays {
		gLog.Warn(
			"Certificate for `%s:%d` expires in %d days (%s).",
			host, port, leaf.DaysToExpiry, leaf.NotAfter.Format("2006-01-02"))
	}

	if !info.HostMatches {
		gLog.Error(
			"Dialed hostname `%s` is not present in the certificate's subject alternative"+
				" names %v for `%s:%d`.",
			info.DialedHost, info.LeafSANs, host, port)
	}
}

func logConnectPhases(host string, port int, timing memd.ConnectTiming, sasl time.Duration) {
	if timing.TCPStart.IsZero() {
		return
	}

	phases := fmt.Sprintf("dns %dms, tcp %dms",
		timing.DNS()/time.Millisecond, timing.TCP()/time.Millisecond)

	if !timing.TLSStart.IsZero() {
		phases += fmt.Sprintf(", tls %dms", timing.TLS()/time.Millisecond)
	}
	if sasl > 0 {
		phases += fmt.Sprintf(", sasl %dms", sasl/time.Millisecond)
	}

	gLog.Log("Connect phases for `%s:%d`: %s", host, port, phases)

	if timing.TCP() > 20*time.Millisecond && timing.TCP() > 5*timing.DNS() {
		gLog.Warn(
			"TCP handshake to `%s:%d` took %dms against %dms for DNS resolution --"+
				" latency appears to be on the network path, not name resolution.",
			host, port, timing.TCP()/time.Millisecond, timing.DNS()/time.Millisecond)
	}
}

func traceRequest(req *http.Request) (*http.Request, func() memd.ConnectTiming) {
	var lock sync.Mutex
	var timing memd.ConnectTiming

	stamp := func(phase *time.Time) {
		lock.Lock()
		*phase = time.Now()
		lock.Unlock()
	}

	trace := &httptrace.ClientTrace{
		DNSStart:          func(httptrace.DNSStartInfo) { stamp(&timing.DNSStart) },
		DNSDone:           func(httptrace.DNSDoneInfo) { stamp(&timing.DNSDone) },
		ConnectStart:      func(string, string) { stamp(&timing.TCPStart) },
		ConnectDone:       func(string, string, error) { stamp(&timing.TCPDone) },
		TLSHandshakeStart: func() { stamp(&timing.TLSStart) },
		TLSHandshakeDone:  func(tls.ConnectionState, error) { stamp(&timing.TLSDone) },
	}

	read := func() memd.ConnectTiming {
		lock.Lock()
		defer lock.Unlock()

		return timing
	}

	return req.WithContext(httptrace.WithClientTrace(req.Context(), trace)), read
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
)

func init() {
	RootCmd.AddCommand(diagnoseCmd)

	diagnoseCmd.PersistentFlags().StringVarP(&tlsCaArg, "tls-ca", "a", "", "certificate authority")
	diagnoseCmd.PersistentFlags().StringVarP(&usernameArg, "username", "u", "", "username")
	diagnoseCmd.PersistentFlags().StringVarP(&passwordArg, "password", "p", "", "password")
	diagnoseCmd.PersistentFlags().StringVarP(&bucketPasswordArg, "bucket-password", "z", "", "bucket password (deprecated, use password instead)")
	diagnoseCmd.PersistentFlags().IntVar(&samplesArg, "samples", 10, "number of KV latency samples to collect per node")
	diagnoseCmd.PersistentFlags().DurationVar(&durationArg, "duration", 0, "sample KV latency for this long per node instead of a fixed count (e.g. 60s)")
}

const kvSampleInterval = 100 * time.Millisecond
const kvMaxErrorStreak = 10

func sampleKVLatency(client *helpers.MemdClient, stats *helpers.PingHelper) {
	var errStreak int

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
				return
			}

			time.Sleep(kvSampleInterval)
		}

		return
	}

	for i := 0; i < samplesArg; i++ {
		if !sampleOne() {
			return
		}
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
	diagnose(connStr, usernameArg, passwordArg, tlsConfig)

	gLog.Log("Diagnostics completed")
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

func networkFromTerseBucketConfig(config terseBucketConfig) string {
	// Check if we connected using any of the ports associated with the default
	// configurations that are available.
	for _, node := range config.NodesExt {
		for _, svcPort := range node.Services {
			if fmt.Sprintf("%s:%d", node.Hostname, svcPort) == config.SourceHost {
				return "default"
			}
		}
	}

	for _, node := range config.NodesExt {
		if _, found := node.AlternateNames["external"]; found {
			return "external"
		}
	}

	return "default"
}

func fetchHTTPTerseBucketConfig(host string, port int, bucket, user, pass string, tlsConfig *tls.Config) (terseBucketConfig, error) {
	if user == "" {
		user = bucket
	}

	httpTransport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	httpClient := &http.Client{
		Transport: httpTransport,
		Timeout:   2000 * time.Millisecond,
	}

	scheme := "http"
	if tlsConfig != nil {
		scheme = "https"
	}

	uri := fmt.Sprintf("%s://%s:%d/pools/default/b/%s", scheme, host, port, bucket)
	req, _ := http.NewRequest("GET", uri, nil)
	req.SetBasicAuth(user, pass)

	resp, err := httpClient.Do(req)
	if err != nil {
		return terseBucketConfig{}, err
	}

	if resp.StatusCode != 200 {
		if resp.StatusCode == 401 {
			return terseBucketConfig{}, errors.New("incorrect bucket/password")
		}

		return terseBucketConfig{}, fmt.Errorf("http error (status code: %d)", resp.StatusCode)
	}

	configBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return terseBucketConfig{}, err
	}

	configBytes = bytes.Replace(configBytes, []byte("$HOST"), []byte(host), -1)

	var config terseBucketConfig
	err = json.Unmarshal(configBytes, &config)
	if err != nil {
		return terseBucketConfig{}, err
	}

	config.SourceHost = host

	return config, nil
}

func fetchCccpTerseBucketConfig(host string, port int, bucket, user, pass string, tlsConfig *tls.Config) (terseBucketConfig, error) {
	if user == "" {
		user = bucket
	}

	client, err := helpers.Dial(host, port, bucket, user, pass, tlsConfig)
	if err != nil {
		return terseBucketConfig{}, err
	}

	configBytes, err := client.GetConfig()
	if err != nil {
		return terseBucketConfig{}, err
	}

	configBytes = bytes.Replace(configBytes, []byte("$HOST"), []byte(host), -1)

	var config terseBucketConfig
	err = json.Unmarshal(configBytes, &config)
	if err != nil {
		return terseBucketConfig{}, err
	}

	config.SourceHost = host

	return config, nil
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

func matrixPorts(nodes []clusterNode) []portDef {
	names := map[int]string{}
	for _, p := range couchbasePorts {
		names[p.Port] = p.Name
	}

	for _, node := range nodes {
		for name, port := range node.Services {
			if port != 0 {
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

// Windows reports refusals as WSAECONNREFUSED, which does not match syscall.ECONNREFUSED.
const wsaeConnRefused = syscall.Errno(10061)

func probePort(host string, port int, timeout time.Duration) string {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err == nil {
		conn.Close()
		return "open"
	}

	var errno syscall.Errno
	if errors.As(err, &errno) && (errno == syscall.ECONNREFUSED || errno == wsaeConnRefused) {
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

func scanPortMatrix(nodes []clusterNode) {
	ports := matrixPorts(nodes)

	gLog.Log("Scanning %d Couchbase ports across all %d node(s)", len(ports), len(nodes))

	results := make([][]string, len(nodes))
	resolved := make([]bool, len(nodes))
	resolvedCount := 0

	for i, node := range nodes {
		results[i] = make([]string, len(ports))

		if _, err := net.LookupHost(node.Hostname); err != nil {
			for j := range ports {
				results[i][j] = "dns"
			}

			gLog.Error(
				"Node `%s` advertised by the cluster does not resolve from this host (error: %s)."+
					"  None of its ports can be probed.",
				node.Hostname, err)

			continue
		}

		resolved[i] = true
		resolvedCount++
	}

	sem := make(chan struct{}, 32)
	var wg sync.WaitGroup

	for i := range nodes {
		if !resolved[i] {
			continue
		}

		for j := range ports {
			wg.Add(1)

			go func(i, j int) {
				defer wg.Done()

				sem <- struct{}{}
				defer func() { <-sem }()

				results[i][j] = probePort(nodes[i].Hostname, ports[j].Port,
					2000*time.Millisecond)
			}(i, j)
		}
	}
	wg.Wait()

	nameWidth := len("PORT MATRIX")
	for _, node := range nodes {
		if len(node.Hostname) > nameWidth {
			nameWidth = len(node.Hostname)
		}
	}

	const portsPerRow = 8
	for start := 0; start < len(ports); start += portsPerRow {
		end := start + portsPerRow
		if end > len(ports) {
			end = len(ports)
		}

		header := fmt.Sprintf("%-*s", nameWidth, "PORT MATRIX")
		for _, p := range ports[start:end] {
			header += fmt.Sprintf(" %8d", p.Port)
		}
		gLog.Log("%s", header)

		for i, node := range nodes {
			row := fmt.Sprintf("%-*s", nameWidth, node.Hostname)
			for j := start; j < end; j++ {
				row += fmt.Sprintf(" %8s", results[i][j])
			}
			gLog.Log("%s", row)
		}
	}

	for j, p := range ports {
		var filtered, refused, open []string

		for i, node := range nodes {
			switch results[i][j] {
			case "filtered":
				filtered = append(filtered, node.Hostname)
			case "refused":
				refused = append(refused, node.Hostname)
			case "open":
				open = append(open, node.Hostname)
			}
		}

		if len(filtered) > 0 && len(filtered) == resolvedCount {
			gLog.Error(
				"Port %d (%s) is filtered on all %d node(s).  Packets are being dropped rather"+
					" than refused, and the behaviour is consistent across nodes, which indicates"+
					" a firewall rule rather than a stopped service.",
				p.Port, p.Name, resolvedCount)
		} else if len(filtered) > 0 {
			gLog.Warn(
				"Port %d (%s) is filtered on `%s` but not on every node.  Packets are being"+
					" dropped on those hosts specifically, which indicates a per-host firewall"+
					" rule rather than a cluster-wide one.",
				p.Port, p.Name, strings.Join(filtered, ", "))
		}

		if len(refused) > 0 && len(open) > 0 {
			gLog.Warn(
				"Port %d (%s) is refused on `%s` but open on %d other node(s).  Nothing is"+
					" listening there, which indicates the service is down on those nodes rather"+
					" than a network problem.",
				p.Port, p.Name, strings.Join(refused, ", "), len(open))
		}
	}
}

func diagnose(connStr, username, password string, tlsConfig *tls.Config) {
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
		strippedHost := stripIPv6Address(target.Host)

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

	// Scans a list of hosts and configurations and logs any appropriate warnings then returns
	//  the first good configuration that it actually encounters (or nil if none are found).
	scanTerseConfigList := func(hosts []gocbconnstr.Address, configs []*terseBucketConfig) *terseBucketConfig {
		if len(hosts) != len(configs) {
			panic(0)
		}

		var masterConfig *terseBucketConfig

		for i, target := range hosts {
			config := configs[i]

			if config == nil {
				continue
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

			thisNodeExt := config.GetSourceNodeExt()
			if thisNodeExt == nil {
				continue
			}

			if thisNodeExt.Hostname != "" && target.Host != thisNodeExt.Hostname {
				gLog.Warn(
					"Bootstrap host `%s` is not using the canonical node hostname of `%s`.  This"+
						" is not neccessarily an error, but has been known to result in strange and"+
						" challenging to diagnose errors when DNS entries are reconfigured.",
					target.Host, thisNodeExt.Hostname)
			}
		}

		return masterConfig
	}

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
				config, err := fetchCccpTerseBucketConfig(target.Host, target.Port, resConnSpec.Bucket, username, password, tlsConfig)
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
				nodesList = clusterNodesFromTerseBucketConfig(*masterConfig, selectedNetwork)
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
				config, err := fetchHTTPTerseBucketConfig(target.Host, target.Port, resConnSpec.Bucket, username, password, tlsConfig)
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
				nodesList = clusterNodesFromTerseBucketConfig(*masterConfig, selectedNetwork)
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

	// Print out information about which network type was selected
	gLog.Log("Selected the following network type: %s", selectedNetwork)

	// Failed to bootstrap
	if nodesList == nil {
		gLog.Error(
			"All endpoints specified by your connection string were unreachable, further" +
				" cluster diagnostics are not possible")
		return
	}

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
				TLSClientConfig: tlsConfig,
			}
			httpClient := &http.Client{
				Transport: httpTransport,
				Timeout:   2000 * time.Millisecond,
			}

			uri := fmt.Sprintf("%s://%s:%d/pools/default", infoSourceScheme, infoSourceHost, infoSourcePort)
			req, _ := http.NewRequest("GET", uri, nil)
			req.SetBasicAuth(username, password)

			resp, err := httpClient.Do(req)
			if err != nil {
				gLog.Log("Failed to retreive cluster information (error: %s)", err.Error())
			} else if resp.StatusCode != 200 {
				gLog.Log("Failed to retreive cluster information (status code: %d)", resp.StatusCode)
			} else {
				if serverTime, dateErr := http.ParseTime(resp.Header.Get("Date")); dateErr == nil {
					skew := time.Since(serverTime)

					direction := "ahead of"
					if skew < 0 {
						skew = -skew
						direction = "behind"
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

				fmtdConfigNodes, _ := json.MarshalIndent(clusterConfig["nodes"], "", "  ")
				gLog.Log("Received cluster configuration, nodes list:\n%s", fmtdConfigNodes)
			}
		}
	}

	//======================================================================
	//  PORT MATRIX
	//======================================================================
	scanPortMatrix(nodesList)

	//======================================================================
	//  SERVICES
	//======================================================================
	var svcOk, svcFailed, svcUnreachable int

	// One cert covers every service on a node
	tlsReported := map[string]bool{}

	testHTTPTransport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	testHTTPClient := &http.Client{
		Transport: testHTTPTransport,
		Timeout:   2000 * time.Millisecond,
	}

	testMemdService := func(node clusterNode, svcName, svcKeyPlain, svcKeySSL string) {
		svcKey := svcKeyPlain
		if tlsConfig != nil {
			svcKey = svcKeySSL
		}

		svcPort := node.Services[svcKey]
		if svcPort != 0 {
			client, err := helpers.Dial(node.Hostname, svcPort,
				resConnSpec.Bucket, username, password, tlsConfig)
			if err != nil {
				svcFailed++
				if isDialFailure(err) {
					svcUnreachable++
				}

				gLog.Error("Failed to connect to %s service at `%s:%d` (error: %s)",
					svcName, node.Hostname, node.Services[svcKey], err.Error())
			} else {
				svcOk++
				gLog.Log("Successfully connected to %s service at `%s:%d`",
					svcName, node.Hostname, node.Services[svcKey])

				client.Close()
			}
		} else {
			gLog.Warn("Could not test %s service on `%s` as it was not in the config", svcName, node.Hostname)
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
		if svcPort != 0 {
			uri := fmt.Sprintf("%s://%s:%d/", svcScheme, node.Hostname, svcPort)
			req, _ := http.NewRequest("GET", uri, nil)
			// No credentials are set here since we only care that the service responds,
			//  not that it responds with anything in particular.

			req, phases := traceRequest(req)

			resp, err := testHTTPClient.Do(req)
			if err != nil {
				svcFailed++
				if isDialFailure(err) {
					svcUnreachable++
				}

				gLog.Error("Failed to connect to %s service at `%s:%d` (error: %s)",
					svcName, node.Hostname, node.Services[svcKey], err.Error())
			} else {
				resp.Body.Close()

				svcOk++
				gLog.Log("Successfully connected to %s service at `%s:%d`",
					svcName, node.Hostname, node.Services[svcKey])

				logConnectPhases(node.Hostname, svcPort, phases(), 0)

				if resp.TLS != nil && !tlsReported[node.Hostname] {
					tlsReported[node.Hostname] = true

					logTLSChainInfo(node.Hostname, svcPort,
						helpers.BuildTLSChainInfo(resp.TLS, node.Hostname, time.Now()))
				}
			}
		} else {
			gLog.Warn("Could not test %s service on `%s` as it was not in the config", svcName, node.Hostname)
		}
	}

	for _, node := range nodesList {
		testMemdService(node, "Key Value", "kv", "kvSSL")
		testHTTPService(node, "Management", "mgmt", "mgmtSSL")
		testHTTPService(node, "Views", "capi", "capiSSL")
		testHTTPService(node, "Query", "n1ql", "n1qlSSL")
		testHTTPService(node, "Search", "fts", "ftsSSL")
		testHTTPService(node, "Analytics", "cbas", "cbasSSL")
	}

	if svcOk == 0 && svcFailed > 0 && svcUnreachable == svcFailed {
		gLog.Error(
			"Bootstrap succeeded but every one of the %d advertised service endpoints was"+
				" unreachable.  This is the signature of a client sitting outside the cluster's"+
				" network: the nodes are advertising hostnames on the `%s` network that do not"+
				" resolve or route from here.  Configure alternate addresses on the cluster so"+
				" it advertises externally reachable hostnames to clients like this one.",
			svcFailed, selectedNetwork)
	}

	//======================================================================
	//  CONNECTION PERFORMANCE
	//======================================================================
	for _, node := range nodesList {
		kvPort := node.Services["kv"]
		if tlsConfig != nil {
			kvPort = node.Services["kvSSL"]
		}

		if kvPort != 0 {
			client, err := helpers.Dial(node.Hostname, kvPort,
				resConnSpec.Bucket, username, password, tlsConfig)
			if err != nil {
				gLog.Warn(
					"Failed to perform KV connection performance analysis on `%s:%d` (error: %s)",
					node.Hostname, kvPort, err.Error())
				continue
			}

			logConnectPhases(node.Hostname, kvPort, client.Timing(), client.SASLDuration())

			firstOpStart := time.Now()
			firstOpErr := client.Ping()
			firstOpDuration := time.Since(firstOpStart)
			gLog.Log(
				"First operation on `%s:%d` completed in %dms (error: %v)",
				node.Hostname, kvPort, firstOpDuration/time.Millisecond, firstOpErr)

			if client.TLSState() != nil && !tlsReported[node.Hostname] {
				tlsReported[node.Hostname] = true

				logTLSChainInfo(node.Hostname, kvPort,
					helpers.BuildTLSChainInfo(client.TLSState(), node.Hostname, time.Now()))
			}

			var stats helpers.PingHelper
			sampleKVLatency(client, &stats)

			gLog.Log("Memd Nop Pinged `%s:%d` %d times, %d errors, %dms min, %dms max, %dms mean",
				node.Hostname, kvPort,
				stats.Count(), stats.Errors(),
				stats.Min()/time.Millisecond,
				stats.Max()/time.Millisecond,
				stats.Mean()/time.Millisecond)

			if stats.Successes() > 0 {
				gLog.Log(
					"KV latency distribution on `%s:%d` over %d samples:"+
						" p50 %dms, p90 %dms, p99 %dms, stddev %dms",
					node.Hostname, kvPort, stats.Successes(),
					stats.Percentile(50)/time.Millisecond,
					stats.Percentile(90)/time.Millisecond,
					stats.Percentile(99)/time.Millisecond,
					stats.StdDev()/time.Millisecond)
			}

			if suspects := helpers.RTOSuspects(stats.Samples()); len(suspects) > 0 {
				gLog.Error(
					"%d of %d samples on `%s:%d` landed on a TCP retransmission timeout"+
						" multiple (slowest: %dms).  This is the signature of packet loss on"+
						" this path rather than of general latency.",
					len(suspects), stats.Successes(), node.Hostname, kvPort,
					suspects[len(suspects)-1]/time.Millisecond)
			}

			allowedMeanMs := 10
			if stats.Mean() >= time.Duration(allowedMeanMs)*time.Millisecond {
				gLog.Warn(
					"Memcached service on `%s:%d` on average took longer than %dms (was: %dms) to"+
						" reply.  This is usually due to network-related issues, and could significantly"+
						" affect application performance.",
					node.Hostname, kvPort,
					allowedMeanMs, stats.Mean()/time.Millisecond)
			}

			// Below 100 samples p99 is the max, so short runs are unchanged.
			allowedMaxMs := 20
			tail := stats.Percentile(99)
			if tail >= time.Duration(allowedMaxMs)*time.Millisecond {
				gLog.Warn(
					"Memcached service on `%s:%d` at the 99th percentile took longer than %dms"+
						" (was: %dms) to reply.  This is usually due to network-related issues,"+
						" and could significantly affect application performance.",
					node.Hostname, kvPort,
					allowedMaxMs, tail/time.Millisecond)
			}

			client.Close()
		}
	}
}
