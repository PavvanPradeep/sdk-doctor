package helpers

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/couchbaselabs/sdk-doctor/memd"
)

// MemdClient provides a memcached client
type MemdClient struct {
	conn         memd.ReadWriteCloser
	timing       memd.ConnectTiming
	tlsState     *tls.ConnectionState
	saslDuration time.Duration
}

// dialBudget bounds connect and authentication together
const dialBudget = 2000 * time.Millisecond

// Dial will dial a particular host, tagging the attempt it records with kind, and return
//
//	a MemdClient along with the builder that has been accumulating that attempt's record
//	throughout. The builder is always non-nil, whether the dial succeeded or failed, so
//	the caller seals it themselves with builder.Finish once it knows the phase and
//	category the outcome belongs to: on success that is builder.Reached() unless a later
//	protocol step (a CCCP config fetch, say) decides the real final phase, and on failure
//	it is whatever builder.FromDial(err) derives from err.
func Dial(kind, host string, port int, bucket, user, pass string, tlsConfig *tls.Config) (*MemdClient, *AttemptBuilder, error) {
	if user == "" {
		user = bucket
	}

	address := fmt.Sprintf("%s:%d", host, port)
	builder := NewAttempt(kind, address, dialBudget)

	deadline := time.Now().Add(dialBudget)

	var srvTLSConfig *tls.Config
	if tlsConfig != nil {
		srvTLSConfig = tlsConfig.Clone()
		srvTLSConfig.ServerName = host
	}

	dialResult, err := memd.DialMemdConn(address, srvTLSConfig, deadline)
	if err != nil {
		return nil, builder, err
	}

	var client MemdClient
	client.conn = dialResult.Conn
	client.timing = dialResult.Timing
	client.tlsState = dialResult.TLSState

	// The connected address reached TLS when the dial negotiated it, otherwise only TCP
	connectedPhase := PhaseTCP
	if dialResult.TLSState != nil {
		connectedPhase = PhaseTLS
	}

	// Record what the dial learned before authentication, so a later failure keeps it
	builder.WithTiming(dialResult.Timing, 0).withAddresses(dialResult.Addresses, connectedPhase)

	saslStart := time.Now()
	err = client.auth(user, pass)
	client.saslDuration = time.Since(saslStart)
	builder.WithTiming(dialResult.Timing, client.saslDuration)
	if err != nil {
		client.Close()
		return nil, builder, err
	}

	// Phase reached so far, in case selectBucket is skipped below
	reached := PhaseSASL

	if bucket != user {
		err = client.selectBucket(bucket)
		if err != nil {
			client.Close()
			return nil, builder, err
		}

		// selectBucket ran and succeeded: it is the furthest rung actually reached
		reached = PhaseSelectBucket
	}

	// The dial deadline covered connect and auth, operations from here on carry their own
	client.conn.SetDeadline(time.Time{})

	return &client, builder.withReached(reached), nil
}

// Close closes a connection
func (client *MemdClient) Close() {
	client.conn.Close()
}

// Timing returns the per-phase dial timing
func (client *MemdClient) Timing() memd.ConnectTiming {
	return client.timing
}

// TLSState returns the negotiated TLS state, or nil without TLS
func (client *MemdClient) TLSState() *tls.ConnectionState {
	return client.tlsState
}

// SASLDuration returns how long SASL authentication took
func (client *MemdClient) SASLDuration() time.Duration {
	return client.saslDuration
}

// TCPCounters returns the kernel's TCP statistics for this connection, where supported
func (client *MemdClient) TCPCounters() (TCPCounters, bool) {
	return tcpCounters(client.conn.RawConn())
}

func (client *MemdClient) auth(user, pass string) error {
	var resp memd.Response

	err := client.conn.WritePacket(&memd.Request{
		Magic:  memd.ReqMagic,
		Opcode: memd.CmdSASLListMechs,
	})
	if err != nil {
		return NewPhaseError(PhaseSASL, Classify(PhaseSASL, err), err)
	}

	err = client.conn.ReadPacket(&resp)
	if err != nil {
		return NewPhaseError(PhaseSASL, Classify(PhaseSASL, err), err)
	}

	if resp.Status != 0 {
		return NewPhaseError(PhaseSASL, CategoryUnknown, errors.New("unexpected SASLListMechs status"))
	}

	mechs := strings.Split(string(resp.Value), " ")

	foundPlainMech := false
	for _, mech := range mechs {
		if mech == "PLAIN" {
			foundPlainMech = true
		}
	}

	if !foundPlainMech {
		return NewPhaseError(PhaseSASL, CategoryUnknown, errors.New("server does not support PLAIN SASL"))
	}

	// Build PLAIN auth data
	userBuf := []byte(user)
	passBuf := []byte(pass)
	authData := make([]byte, 1+len(userBuf)+1+len(passBuf))
	authData[0] = 0
	copy(authData[1:], userBuf)
	authData[1+len(userBuf)] = 0
	copy(authData[1+len(userBuf)+1:], passBuf)

	err = client.conn.WritePacket(&memd.Request{
		Magic:  memd.ReqMagic,
		Opcode: memd.CmdSASLAuth,
		Key:    []byte("PLAIN"),
		Value:  authData,
	})
	if err != nil {
		return NewPhaseError(PhaseSASL, Classify(PhaseSASL, err), err)
	}

	err = client.conn.ReadPacket(&resp)
	if err != nil {
		return NewPhaseError(PhaseSASL, Classify(PhaseSASL, err), err)
	}

	if resp.Status != 0 {
		if resp.Status == memd.StatusAuthError {
			return NewPhaseError(PhaseSASL, CategoryForMemdStatus(resp.Status), errors.New("invalid bucket name/password"))
		}

		return NewPhaseError(PhaseSASL, CategoryForMemdStatus(resp.Status),
			fmt.Errorf("SASL auth failed for user `%s` (status: %d)", user, resp.Status))
	}

	return nil
}

func (client *MemdClient) selectBucket(bucket string) error {
	var resp memd.Response

	err := client.conn.WritePacket(&memd.Request{
		Magic:  memd.ReqMagic,
		Opcode: memd.CmdSelectBucket,
		Key:    []byte(bucket),
	})
	if err != nil {
		return NewPhaseError(PhaseSelectBucket, Classify(PhaseSelectBucket, err), err)
	}

	err = client.conn.ReadPacket(&resp)
	if err != nil {
		return NewPhaseError(PhaseSelectBucket, Classify(PhaseSelectBucket, err), err)
	}

	if resp.Status != 0 {
		return NewPhaseError(PhaseSelectBucket, CategoryForMemdStatus(resp.Status),
			fmt.Errorf("failed to select bucket `%s` (status: %d)", bucket, resp.Status))
	}

	return nil
}

// opTimeout bounds a single operation, as a stalled peer would otherwise block the run forever
const opTimeout = 2000 * time.Millisecond

// GetConfig will fetch a config via CCCP
func (client *MemdClient) GetConfig() ([]byte, error) {
	var resp memd.Response

	client.conn.SetDeadline(time.Now().Add(opTimeout))
	defer client.conn.SetDeadline(time.Time{})

	err := client.conn.WritePacket(&memd.Request{
		Magic:  memd.ReqMagic,
		Opcode: memd.CmdGetClusterConfig,
	})
	if err != nil {
		return nil, NewPhaseError(PhaseConfig, Classify(PhaseConfig, err), err)
	}

	err = client.conn.ReadPacket(&resp)
	if err != nil {
		return nil, NewPhaseError(PhaseConfig, Classify(PhaseConfig, err), err)
	}

	if resp.Status != memd.StatusSuccess {
		return nil, NewPhaseError(PhaseConfig, CategoryForConfigStatus(resp.Status),
			fmt.Errorf("failed to get config (status: %d)", resp.Status))
	}

	return resp.Value, nil
}

// Ping will send a ping and wait for a response
func (client *MemdClient) Ping() error {
	var resp memd.Response

	client.conn.SetDeadline(time.Now().Add(opTimeout))
	defer client.conn.SetDeadline(time.Time{})

	err := client.conn.WritePacket(&memd.Request{
		Magic:  memd.ReqMagic,
		Opcode: memd.CmdNop,
	})
	if err != nil {
		return err
	}

	err = client.conn.ReadPacket(&resp)
	if err != nil {
		return err
	}

	// An unexpected packet means the stream is no longer in step, so the timing cannot be trusted
	if resp.Opcode != memd.CmdNop || resp.Status != memd.StatusSuccess {
		return fmt.Errorf("unexpected nop response (opcode: %d, status: %d)", resp.Opcode, resp.Status)
	}

	return nil
}
