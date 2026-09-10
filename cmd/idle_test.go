package cmd

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/couchbaselabs/sdk-doctor/helpers"
	"github.com/couchbaselabs/sdk-doctor/memd"
)

func memdStub(t *testing.T, dropAfter time.Duration) (string, int) {
	t.Helper()
	return memdStubWithStall(t, dropAfter, 0)
}

func memdStubWithStall(t *testing.T, dropAfter time.Duration, stall memd.CommandCode) (string, int) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %s", err)
	}

	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}

			if dropAfter > 0 {
				time.AfterFunc(dropAfter, func() { conn.Close() })
			}

			go func() {
				defer conn.Close()

				header := make([]byte, 24)
				for {
					if _, err := io.ReadFull(conn, header); err != nil {
						return
					}

					opcode := memd.CommandCode(header[1])
					opaque := binary.BigEndian.Uint32(header[12:])

					if bodyLen := binary.BigEndian.Uint32(header[8:]); bodyLen > 0 {
						if _, err := io.CopyN(io.Discard, conn, int64(bodyLen)); err != nil {
							return
						}
					}

					var value []byte
					if opcode == stall {
						io.Copy(io.Discard, conn)
						return
					}
					if opcode == memd.CmdSASLListMechs {
						value = []byte("PLAIN")
					}

					reply := make([]byte, 24+len(value))
					reply[0] = uint8(memd.ResMagic)
					reply[1] = uint8(opcode)
					binary.BigEndian.PutUint32(reply[8:], uint32(len(value)))
					binary.BigEndian.PutUint32(reply[12:], opaque)
					copy(reply[24:], value)

					if _, err := conn.Write(reply); err != nil {
						return
					}
				}
			}()
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)

	return addr.IP.String(), addr.Port
}

func TestIdleWindowIsIndependentOfOtherNodes(t *testing.T) {
	for name, stall := range map[string]memd.CommandCode{"authentication": memd.CmdSASLListMechs, "noop": memd.CmdNop} {
		t.Run(name, func(t *testing.T) {
			defer saveGlobals()()
			gLog = helpers.Logger{}
			gLog.SetOutput(devNull{})
			gReport = diagnosticReport{}
			savedIdle := idleTestArg
			defer func() { idleTestArg = savedIdle }()
			idleTestArg = 100 * time.Millisecond

			host, port := memdStub(t, 700*time.Millisecond)
			healthy := idleTarget{host, port}
			host, port = memdStubWithStall(t, 0, stall)
			stalled := idleTarget{host, port}
			targets := []idleTarget{healthy, stalled}
			if stall == memd.CmdNop {
				targets = []idleTarget{stalled, healthy}
			}
			runIdleTest(targets, "travel", "Administrator", "password", nil)

			wantResults := 2
			if stall == memd.CmdSASLListMechs {
				wantResults = 1
				if len(gReport.Attempts) != 2 || gReport.Attempts[1].Error == "" {
					t.Fatalf("missing failed dial attempt: %+v", gReport.Attempts)
				}
			}
			if len(gReport.IdleTest) != wantResults {
				t.Fatalf("got %d idle results, want %d", len(gReport.IdleTest), wantResults)
			}
			for i, result := range gReport.IdleTest {
				if result.Port != targets[i].port {
					t.Fatalf("results lost target order: %+v", gReport.IdleTest)
				}
				if result.Port == healthy.port && result.Error != "" {
					t.Errorf("another node's timeout caused an idle false alarm: %+v", result)
				}
				if result.Port == stalled.port && result.Error == "" {
					t.Errorf("stalled NOOP was not reported: %+v", result)
				}
				elapsed, err := time.ParseDuration(result.IdleFor)
				if err != nil || elapsed < idleTestArg || elapsed >= 700*time.Millisecond {
					t.Errorf("incorrect measured idle interval: %+v", result)
				}
			}
		})
	}
}

func TestIdleTestSharesOneWaitAndReportsEveryNode(t *testing.T) {
	defer saveGlobals()()

	gLog = helpers.Logger{}
	gLog.SetOutput(devNull{})
	gReport = diagnosticReport{}

	savedIdle := idleTestArg
	defer func() { idleTestArg = savedIdle }()

	idleTestArg = 400 * time.Millisecond

	var targets []idleTarget
	for _, drop := range []time.Duration{0, 150 * time.Millisecond, 0} {
		host, port := memdStub(t, drop)
		targets = append(targets, idleTarget{host, port})
	}

	start := time.Now()
	runIdleTest(targets, "travel", "Administrator", "password", nil)
	elapsed := time.Since(start)

	if elapsed >= 2*idleTestArg {
		t.Errorf("idling %d nodes took %s, which is more than the single %s wait it should share",
			len(targets), elapsed, idleTestArg)
	}

	if len(gReport.IdleTest) != len(targets) {
		t.Fatalf("the report has %d idle results, want one per node (%d): %+v",
			len(gReport.IdleTest), len(targets), gReport.IdleTest)
	}

	for i, result := range gReport.IdleTest {
		reaped := i == 1

		if reaped && result.Error == "" {
			t.Errorf("node %d was reaped during the wait but the report calls it healthy: %+v",
				i, result)
		}

		if !reaped && result.Error != "" {
			t.Errorf("node %d survived the wait but the report calls it failed: %+v", i, result)
		}
	}
}
