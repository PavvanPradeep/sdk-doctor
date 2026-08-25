package memd

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// Request encapsulates a memcached request
type Request struct {
	Magic    CommandMagic
	Opcode   CommandCode
	Datatype uint8
	Vbucket  uint16
	Opaque   uint32
	Cas      uint64
	Key      []byte
	Extras   []byte
	Value    []byte
}

// Response encapsulates a memcached response
type Response struct {
	Magic    CommandMagic
	Opcode   CommandCode
	Datatype uint8
	Status   StatusCode
	Opaque   uint32
	Cas      uint64
	Key      []byte
	Extras   []byte
	Value    []byte
}

// Dialer provides an interface for dialing memcached connections
type Dialer interface {
	Dial(address string) (io.ReadWriteCloser, error)
}

// ReadWriteCloser provides an interface for reading and writing packets
type ReadWriteCloser interface {
	WritePacket(*Request) error
	ReadPacket(*Response) error
	SetDeadline(time.Time) error
	Close() error
}

// ConnectTiming records each dial phase; the TLS fields stay zero without TLS
type ConnectTiming struct {
	DNSStart time.Time
	DNSDone  time.Time
	TCPStart time.Time
	TCPDone  time.Time
	TLSStart time.Time
	TLSDone  time.Time
}

// DNS returns how long DNS resolution took.
func (t ConnectTiming) DNS() time.Duration {
	return t.DNSDone.Sub(t.DNSStart)
}

// TCP returns how long the TCP handshake took.
func (t ConnectTiming) TCP() time.Duration {
	return t.TCPDone.Sub(t.TCPStart)
}

// TLS returns how long the TLS handshake took, or zero without TLS
func (t ConnectTiming) TLS() time.Duration {
	if t.TLSStart.IsZero() {
		return 0
	}
	return t.TLSDone.Sub(t.TLSStart)
}

// DialResult carries a dialed memd connection and its dial diagnostics
type DialResult struct {
	Conn     ReadWriteCloser
	Timing   ConnectTiming
	TLSState *tls.ConnectionState
}

type memdConn struct {
	conn    io.ReadWriteCloser
	recvBuf []byte
}

// attemptDeadline splits the time left evenly, so a filtered address cannot swallow it all
func attemptDeadline(deadline, now time.Time, remainingAddrs int) time.Time {
	remaining := deadline.Sub(now)
	if deadline.IsZero() || remainingAddrs <= 1 || remaining <= 0 {
		return deadline
	}

	return now.Add(remaining / time.Duration(remainingAddrs))
}

// DialMemdConn dials a memcached connection
func DialMemdConn(address string, tlsConfig *tls.Config, deadline time.Time) (*DialResult, error) {
	var timing ConnectTiming

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	var resolveCtx context.Context = context.Background()
	if !deadline.IsZero() {
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		defer cancel()
		resolveCtx = ctx
	}

	// An IP literal is never resolved, so stamping the DNS phase would report a lookup that never happened
	ips := []string{host}
	if net.ParseIP(host) == nil {
		timing.DNSStart = time.Now()
		ips, err = net.DefaultResolver.LookupHost(resolveCtx, host)
		timing.DNSDone = time.Now()
		if err != nil {
			return nil, err
		}

		if len(ips) == 0 {
			return nil, fmt.Errorf("no addresses found for host `%s`", host)
		}
	}

	// Try every resolved address rather than only the first, as the standard dialer does
	var baseConn net.Conn

	for i, ip := range ips {
		d := net.Dialer{
			Deadline: attemptDeadline(deadline, time.Now(), len(ips)-i),
		}

		// Re-stamped per attempt so the reported handshake covers only the one that connected
		timing.TCPStart = time.Now()
		baseConn, err = d.Dial("tcp", net.JoinHostPort(ip, port))
		timing.TCPDone = time.Now()
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, err
	}

	tcpConn := baseConn.(*net.TCPConn)
	tcpConn.SetNoDelay(false)

	// The dialer deadline does not cover the handshake, and a peer that accepts then stalls would hang forever
	tcpConn.SetDeadline(deadline)

	var conn io.ReadWriteCloser
	var tlsState *tls.ConnectionState
	if tlsConfig == nil {
		conn = tcpConn
	} else {
		tlsConn := tls.Client(tcpConn, tlsConfig)

		timing.TLSStart = time.Now()
		err = tlsConn.Handshake()
		timing.TLSDone = time.Now()
		if err != nil {
			tcpConn.Close()
			return nil, err
		}

		state := tlsConn.ConnectionState()
		tlsState = &state

		conn = tlsConn
	}

	return &DialResult{
		Conn: &memdConn{
			conn: conn,
		},
		Timing:   timing,
		TLSState: tlsState,
	}, nil
}

func (s *memdConn) Close() error {
	return s.conn.Close()
}

// SetDeadline bounds every subsequent read and write, or clears the bound with a zero time
func (s *memdConn) SetDeadline(t time.Time) error {
	conn, ok := s.conn.(net.Conn)
	if !ok {
		return nil
	}

	return conn.SetDeadline(t)
}

func (s *memdConn) WritePacket(req *Request) error {
	extLen := len(req.Extras)
	keyLen := len(req.Key)
	valLen := len(req.Value)

	// Go appears to do some clever things in regards to writing data
	//   to the kernel for network dispatch.  Having a write buffer
	//   per-server that is re-used actually hinders performance...
	// For now, we will simply create a new buffer and let it be GC'd.
	buffer := make([]byte, 24+keyLen+extLen+valLen)

	buffer[0] = uint8(req.Magic)
	buffer[1] = uint8(req.Opcode)
	binary.BigEndian.PutUint16(buffer[2:], uint16(keyLen))
	buffer[4] = byte(extLen)
	buffer[5] = req.Datatype
	binary.BigEndian.PutUint16(buffer[6:], uint16(req.Vbucket))
	binary.BigEndian.PutUint32(buffer[8:], uint32(len(buffer)-24))
	binary.BigEndian.PutUint32(buffer[12:], req.Opaque)
	binary.BigEndian.PutUint64(buffer[16:], req.Cas)

	copy(buffer[24:], req.Extras)
	copy(buffer[24+extLen:], req.Key)
	copy(buffer[24+extLen+keyLen:], req.Value)

	_, err := s.conn.Write(buffer)
	return err
}

func (s *memdConn) readBuffered(n int) ([]byte, error) {
	// Make sure our buffer is big enough to hold all our data
	if len(s.recvBuf) < n {
		neededSize := 4096
		if neededSize < n {
			neededSize = n
		}
		newBuf := make([]byte, neededSize)
		copy(newBuf[0:], s.recvBuf[0:])
		s.recvBuf = newBuf[0:len(s.recvBuf)]
	}

	// Loop till we encounter an error or have enough data...
	for {
		// Check if we already have enough data buffered
		if n <= len(s.recvBuf) {
			buf := s.recvBuf[0:n]
			s.recvBuf = s.recvBuf[n:]
			return buf, nil
		}

		// Read data up to the capacity
		recvTgt := s.recvBuf[len(s.recvBuf):cap(s.recvBuf)]
		n, err := s.conn.Read(recvTgt)
		if n <= 0 {
			return nil, err
		}

		// Update the len of our slice to encompass our new data
		s.recvBuf = s.recvBuf[:len(s.recvBuf)+n]
	}
}

func (s *memdConn) ReadPacket(resp *Response) error {
	hdrBuf, err := s.readBuffered(24)
	if err != nil {
		return err
	}

	bodyLen := int(binary.BigEndian.Uint32(hdrBuf[8:]))
	bodyBuf, err := s.readBuffered(bodyLen)
	if err != nil {
		return err
	}

	keyLen := int(binary.BigEndian.Uint16(hdrBuf[2:]))
	extLen := int(hdrBuf[4])

	resp.Magic = CommandMagic(hdrBuf[0])
	resp.Opcode = CommandCode(hdrBuf[1])
	resp.Datatype = hdrBuf[5]
	resp.Status = StatusCode(binary.BigEndian.Uint16(hdrBuf[6:]))
	resp.Opaque = binary.BigEndian.Uint32(hdrBuf[12:])
	resp.Cas = binary.BigEndian.Uint64(hdrBuf[16:])
	resp.Extras = bodyBuf[:extLen]
	resp.Key = bodyBuf[extLen : extLen+keyLen]
	resp.Value = bodyBuf[extLen+keyLen:]
	return nil
}
