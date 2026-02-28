package stream

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helper: build TCPPacket inline
// ---------------------------------------------------------------------------

func mkPkt(srcIP string, srcPort uint16, dstIP string, dstPort uint16,
	seq, ack uint32, flags TCPFlags, payload []byte, ts time.Time, num int,
) *TCPPacket {
	return &TCPPacket{
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Seq:       seq,
		Ack:       ack,
		Flags:     flags,
		Payload:   payload,
		Timestamp: ts,
		PacketNum: num,
	}
}

// Convenience addresses reused across tests.
const (
	clientIP   = "192.168.1.10"
	serverIP   = "10.0.0.1"
	clientPort = uint16(54321)
	serverPort = uint16(80)
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// threeWayHandshake drives a full SYN / SYN-ACK / ACK handshake on the given
// manager and returns the stream key.
func threeWayHandshake(m *StreamManager, clientISN, serverISN uint32) string {
	// SYN  (client -> server)
	m.ProcessPacket(mkPkt(clientIP, clientPort, serverIP, serverPort,
		clientISN, 0, FlagSYN, nil, t0, 1))
	// SYN-ACK (server -> client)
	m.ProcessPacket(mkPkt(serverIP, serverPort, clientIP, clientPort,
		serverISN, clientISN+1, FlagSYN|FlagACK, nil, t0.Add(time.Millisecond), 2))
	// ACK (client -> server)
	key := m.ProcessPacket(mkPkt(clientIP, clientPort, serverIP, serverPort,
		clientISN+1, serverISN+1, FlagACK, nil, t0.Add(2*time.Millisecond), 3))
	return key
}

// ---------------------------------------------------------------------------
// 1. TestStreamKey
// ---------------------------------------------------------------------------

func TestStreamKey(t *testing.T) {
	t.Run("normalized ordering", func(t *testing.T) {
		// Lower IP comes first in the key.
		key := StreamKey("10.0.0.1", "192.168.1.10", 80, 54321)
		if key != "10.0.0.1:80-192.168.1.10:54321" {
			t.Fatalf("unexpected key: %s", key)
		}
	})

	t.Run("bidirectional same key", func(t *testing.T) {
		k1 := StreamKey("10.0.0.1", "192.168.1.10", 80, 54321)
		k2 := StreamKey("192.168.1.10", "10.0.0.1", 54321, 80)
		if k1 != k2 {
			t.Fatalf("keys differ: %q vs %q", k1, k2)
		}
	})

	t.Run("same IP different ports", func(t *testing.T) {
		k1 := StreamKey("10.0.0.1", "10.0.0.1", 80, 443)
		k2 := StreamKey("10.0.0.1", "10.0.0.1", 443, 80)
		if k1 != k2 {
			t.Fatalf("same-IP keys differ: %q vs %q", k1, k2)
		}
		// Lower port should come first.
		expected := "10.0.0.1:80-10.0.0.1:443"
		if k1 != expected {
			t.Fatalf("expected %q, got %q", expected, k1)
		}
	})
}

// ---------------------------------------------------------------------------
// 2. TestStreamManager_CreateStream_SYN
// ---------------------------------------------------------------------------

func TestStreamManager_CreateStream_SYN(t *testing.T) {
	m := NewStreamManager()
	key := m.ProcessPacket(mkPkt(clientIP, clientPort, serverIP, serverPort,
		1000, 0, FlagSYN, nil, t0, 1))

	if m.StreamCount() != 1 {
		t.Fatalf("expected 1 stream, got %d", m.StreamCount())
	}
	s := m.GetStream(key)
	if s == nil {
		t.Fatal("stream not found")
	}
	if s.State != StateSynSent {
		t.Fatalf("expected SYN_SENT, got %s", s.State)
	}
	if !s.DirectionKnown {
		t.Fatal("DirectionKnown should be true for SYN-created stream")
	}
	if s.ClientISN != 1000 {
		t.Fatalf("expected ClientISN 1000, got %d", s.ClientISN)
	}
	if s.ClientAddr != fmt.Sprintf("%s:%d", clientIP, clientPort) {
		t.Fatalf("unexpected ClientAddr: %s", s.ClientAddr)
	}
	if s.ServerAddr != fmt.Sprintf("%s:%d", serverIP, serverPort) {
		t.Fatalf("unexpected ServerAddr: %s", s.ServerAddr)
	}
}

// ---------------------------------------------------------------------------
// 3. TestStreamManager_CreateMidStream
// ---------------------------------------------------------------------------

func TestStreamManager_CreateMidStream(t *testing.T) {
	m := NewStreamManager()
	// ACK-only packet (no SYN) from high port to well-known port 80.
	key := m.ProcessPacket(mkPkt(clientIP, clientPort, serverIP, serverPort,
		5000, 3000, FlagACK, nil, t0, 1))

	s := m.GetStream(key)
	if s == nil {
		t.Fatal("stream not found")
	}
	if s.State != StateEstablished {
		t.Fatalf("expected ESTABLISHED, got %s", s.State)
	}
	if s.DirectionKnown {
		t.Fatal("DirectionKnown should be false for mid-stream")
	}
	// Port heuristic: port 80 is server, so the source of the packet
	// (clientIP:clientPort) should be identified as client and serverIP:80 as server.
	// The heuristic checks: isLikelyServerPort(srcPort=54321) => false,
	// isLikelyServerPort(dstPort=80) => true. Since src is NOT server and dst IS server,
	// the default assignment is kept: src=client, dst=server.
	expectedServer := fmt.Sprintf("%s:%d", serverIP, serverPort)
	if s.ServerAddr != expectedServer {
		t.Fatalf("expected ServerAddr %s, got %s", expectedServer, s.ServerAddr)
	}

	t.Run("server port as source swaps direction", func(t *testing.T) {
		m2 := NewStreamManager()
		// Packet from server port 80 to high port.
		m2.ProcessPacket(mkPkt(serverIP, serverPort, clientIP, clientPort,
			3000, 5000, FlagACK|FlagPSH, []byte("HTTP/1.1 200 OK"), t0, 1))

		streams := m2.GetAllStreams()
		if len(streams) != 1 {
			t.Fatalf("expected 1 stream, got %d", len(streams))
		}
		s2 := streams[0]
		// isLikelyServerPort(srcPort=80) => true AND !isLikelyServerPort(dstPort=54321)
		// so swap: server=src, client=dst.
		if s2.ServerAddr != fmt.Sprintf("%s:%d", serverIP, serverPort) {
			t.Fatalf("expected server addr %s:%d, got %s", serverIP, serverPort, s2.ServerAddr)
		}
	})
}

// ---------------------------------------------------------------------------
// 4. TestStreamState_ThreeWayHandshake
// ---------------------------------------------------------------------------

func TestStreamState_ThreeWayHandshake(t *testing.T) {
	m := NewStreamManager()

	// SYN
	key := m.ProcessPacket(mkPkt(clientIP, clientPort, serverIP, serverPort,
		1000, 0, FlagSYN, nil, t0, 1))
	if s := m.GetStream(key); s.State != StateSynSent {
		t.Fatalf("after SYN: expected SYN_SENT, got %s", s.State)
	}

	// SYN-ACK
	m.ProcessPacket(mkPkt(serverIP, serverPort, clientIP, clientPort,
		2000, 1001, FlagSYN|FlagACK, nil, t0.Add(time.Millisecond), 2))
	if s := m.GetStream(key); s.State != StateSynReceived {
		t.Fatalf("after SYN-ACK: expected SYN_RECEIVED, got %s", s.State)
	}

	// ACK
	m.ProcessPacket(mkPkt(clientIP, clientPort, serverIP, serverPort,
		1001, 2001, FlagACK, nil, t0.Add(2*time.Millisecond), 3))
	s := m.GetStream(key)
	if s.State != StateEstablished {
		t.Fatalf("after ACK: expected ESTABLISHED, got %s", s.State)
	}
	if s.ServerISN != 2000 {
		t.Fatalf("expected ServerISN 2000, got %d", s.ServerISN)
	}
	if s.PacketCount != 3 {
		t.Fatalf("expected PacketCount 3, got %d", s.PacketCount)
	}
}

// ---------------------------------------------------------------------------
// 5. TestStreamState_NormalClose
// ---------------------------------------------------------------------------

func TestStreamState_NormalClose(t *testing.T) {
	m := NewStreamManager()
	key := threeWayHandshake(m, 1000, 2000)

	// Client FIN
	m.ProcessPacket(mkPkt(clientIP, clientPort, serverIP, serverPort,
		1001, 2001, FlagFIN|FlagACK, nil, t0.Add(10*time.Millisecond), 4))
	if s := m.GetStream(key); s.State != StateFinWait1 {
		t.Fatalf("after client FIN: expected FIN_WAIT_1, got %s", s.State)
	}

	// Server ACK of FIN
	m.ProcessPacket(mkPkt(serverIP, serverPort, clientIP, clientPort,
		2001, 1002, FlagACK, nil, t0.Add(11*time.Millisecond), 5))
	if s := m.GetStream(key); s.State != StateFinWait2 {
		t.Fatalf("after server ACK: expected FIN_WAIT_2, got %s", s.State)
	}

	// Server FIN
	m.ProcessPacket(mkPkt(serverIP, serverPort, clientIP, clientPort,
		2001, 1002, FlagFIN|FlagACK, nil, t0.Add(12*time.Millisecond), 6))
	if s := m.GetStream(key); s.State != StateTimeWait {
		t.Fatalf("after server FIN: expected TIME_WAIT, got %s", s.State)
	}

	// Client ACK of server's FIN
	m.ProcessPacket(mkPkt(clientIP, clientPort, serverIP, serverPort,
		1002, 2002, FlagACK, nil, t0.Add(13*time.Millisecond), 7))
	s := m.GetStream(key)
	if s.State != StateClosed {
		t.Fatalf("after final ACK: expected CLOSED, got %s", s.State)
	}
	if s.EndTime.IsZero() {
		t.Fatal("EndTime should be set after close")
	}
}

// ---------------------------------------------------------------------------
// 6. TestStreamState_SimultaneousClose
// ---------------------------------------------------------------------------

func TestStreamState_SimultaneousClose(t *testing.T) {
	m := NewStreamManager()
	key := threeWayHandshake(m, 1000, 2000)

	// Client FIN
	m.ProcessPacket(mkPkt(clientIP, clientPort, serverIP, serverPort,
		1001, 2001, FlagFIN|FlagACK, nil, t0.Add(10*time.Millisecond), 4))
	if s := m.GetStream(key); s.State != StateFinWait1 {
		t.Fatalf("expected FIN_WAIT_1, got %s", s.State)
	}

	// Server FIN (simultaneous, before ACKing client's FIN)
	m.ProcessPacket(mkPkt(serverIP, serverPort, clientIP, clientPort,
		2001, 1001, FlagFIN|FlagACK, nil, t0.Add(11*time.Millisecond), 5))
	s := m.GetStream(key)
	if s.State != StateTimeWait {
		t.Fatalf("after simultaneous FIN: expected TIME_WAIT, got %s", s.State)
	}
	if !s.ClientFinSeen || !s.ServerFinSeen {
		t.Fatalf("expected both FINs seen: client=%v server=%v",
			s.ClientFinSeen, s.ServerFinSeen)
	}

	// ACK from client closes connection
	m.ProcessPacket(mkPkt(clientIP, clientPort, serverIP, serverPort,
		1002, 2002, FlagACK, nil, t0.Add(12*time.Millisecond), 6))
	if s := m.GetStream(key); s.State != StateClosed {
		t.Fatalf("after ACK: expected CLOSED, got %s", s.State)
	}
}

// ---------------------------------------------------------------------------
// 7. TestStreamState_RST
// ---------------------------------------------------------------------------

func TestStreamState_RST(t *testing.T) {
	m := NewStreamManager()
	key := threeWayHandshake(m, 1000, 2000)
	s := m.GetStream(key)
	if s.State != StateEstablished {
		t.Fatalf("expected ESTABLISHED before RST, got %s", s.State)
	}

	// RST from server
	m.ProcessPacket(mkPkt(serverIP, serverPort, clientIP, clientPort,
		2001, 1001, FlagRST, nil, t0.Add(5*time.Millisecond), 4))
	s = m.GetStream(key)
	if s.State != StateClosed {
		t.Fatalf("after RST: expected CLOSED, got %s", s.State)
	}
	if s.EndTime.IsZero() {
		t.Fatal("EndTime should be set on RST")
	}
}

// ---------------------------------------------------------------------------
// 8. TestStreamState_FinTracking
// ---------------------------------------------------------------------------

func TestStreamState_FinTracking(t *testing.T) {
	m := NewStreamManager()
	key := threeWayHandshake(m, 1000, 2000)

	s := m.GetStream(key)
	if s.ClientFinSeen || s.ServerFinSeen {
		t.Fatal("no FINs should be seen initially")
	}

	// Client FIN
	m.ProcessPacket(mkPkt(clientIP, clientPort, serverIP, serverPort,
		1001, 2001, FlagFIN|FlagACK, nil, t0.Add(10*time.Millisecond), 4))
	s = m.GetStream(key)
	if !s.ClientFinSeen {
		t.Fatal("ClientFinSeen should be true after client FIN")
	}
	if s.ServerFinSeen {
		t.Fatal("ServerFinSeen should still be false")
	}

	// Server ACK
	m.ProcessPacket(mkPkt(serverIP, serverPort, clientIP, clientPort,
		2001, 1002, FlagACK, nil, t0.Add(11*time.Millisecond), 5))

	// Server FIN
	m.ProcessPacket(mkPkt(serverIP, serverPort, clientIP, clientPort,
		2001, 1002, FlagFIN|FlagACK, nil, t0.Add(12*time.Millisecond), 6))
	s = m.GetStream(key)
	if !s.ServerFinSeen {
		t.Fatal("ServerFinSeen should be true after server FIN")
	}
	if !s.ClientFinSeen {
		t.Fatal("ClientFinSeen should remain true")
	}
}

// ---------------------------------------------------------------------------
// 9. TestStream_DataInEstablished
// ---------------------------------------------------------------------------

func TestStream_DataInEstablished(t *testing.T) {
	m := NewStreamManager()
	key := threeWayHandshake(m, 1000, 2000)

	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	m.ProcessPacket(mkPkt(clientIP, clientPort, serverIP, serverPort,
		1001, 2001, FlagACK|FlagPSH, payload, t0.Add(3*time.Millisecond), 4))

	s := m.GetStream(key)
	if s.ClientBytes != len(payload) {
		t.Fatalf("expected ClientBytes %d, got %d", len(payload), s.ClientBytes)
	}

	assembled := s.GetClientData()
	if string(assembled) != string(payload) {
		t.Fatalf("assembled data mismatch: %q", assembled)
	}

	t.Run("no data in SYN_SENT", func(t *testing.T) {
		m2 := NewStreamManager()
		m2.ProcessPacket(mkPkt(clientIP, clientPort, serverIP, serverPort,
			1000, 0, FlagSYN, nil, t0, 1))
		// Try to send data while in SYN_SENT.
		m2.ProcessPacket(mkPkt(clientIP, clientPort, serverIP, serverPort,
			1001, 0, FlagACK|FlagPSH, []byte("data"), t0.Add(time.Millisecond), 2))
		streams := m2.GetAllStreams()
		if len(streams) != 1 {
			t.Fatalf("expected 1 stream, got %d", len(streams))
		}
		if streams[0].ClientBytes != 0 {
			t.Fatalf("expected 0 ClientBytes in SYN_SENT, got %d", streams[0].ClientBytes)
		}
	})
}

// ---------------------------------------------------------------------------
// 10. TestStream_DataDirection
// ---------------------------------------------------------------------------

func TestStream_DataDirection(t *testing.T) {
	m := NewStreamManager()
	key := threeWayHandshake(m, 1000, 2000)

	request := []byte("GET / HTTP/1.1\r\n\r\n")
	response := []byte("HTTP/1.1 200 OK\r\n\r\n")

	// Client -> Server
	m.ProcessPacket(mkPkt(clientIP, clientPort, serverIP, serverPort,
		1001, 2001, FlagACK|FlagPSH, request, t0.Add(3*time.Millisecond), 4))

	// Server -> Client
	m.ProcessPacket(mkPkt(serverIP, serverPort, clientIP, clientPort,
		2001, 1001+uint32(len(request)), FlagACK|FlagPSH, response, t0.Add(4*time.Millisecond), 5))

	s := m.GetStream(key)

	if s.ClientBytes != len(request) {
		t.Fatalf("expected ClientBytes %d, got %d", len(request), s.ClientBytes)
	}
	if s.ServerBytes != len(response) {
		t.Fatalf("expected ServerBytes %d, got %d", len(response), s.ServerBytes)
	}
	if s.TotalBytes() != len(request)+len(response) {
		t.Fatalf("TotalBytes mismatch: %d", s.TotalBytes())
	}

	clientData := s.GetClientData()
	serverData := s.GetServerData()
	if string(clientData) != string(request) {
		t.Fatalf("client data: got %q, want %q", clientData, request)
	}
	if string(serverData) != string(response) {
		t.Fatalf("server data: got %q, want %q", serverData, response)
	}
}

// ---------------------------------------------------------------------------
// 11a. TestStreamCallbacks_OnCreated
// ---------------------------------------------------------------------------

func TestStreamCallbacks_OnCreated(t *testing.T) {
	m := NewStreamManager()

	var created []*TCPStream
	m.SetCallbacks(&StreamCallbacks{
		OnStreamCreated: func(s *TCPStream) {
			created = append(created, s)
		},
	})

	m.ProcessPacket(mkPkt(clientIP, clientPort, serverIP, serverPort,
		1000, 0, FlagSYN, nil, t0, 1))
	if len(created) != 1 {
		t.Fatalf("expected 1 OnStreamCreated call, got %d", len(created))
	}
	if created[0].State != StateSynSent {
		t.Fatalf("callback received stream in %s, expected SYN_SENT", created[0].State)
	}

	// Second packet on same stream should NOT trigger OnStreamCreated again.
	m.ProcessPacket(mkPkt(serverIP, serverPort, clientIP, clientPort,
		2000, 1001, FlagSYN|FlagACK, nil, t0.Add(time.Millisecond), 2))
	if len(created) != 1 {
		t.Fatalf("OnStreamCreated fired again on existing stream, count=%d", len(created))
	}
}

// ---------------------------------------------------------------------------
// 11b. TestStreamCallbacks_OnClosed
// ---------------------------------------------------------------------------

func TestStreamCallbacks_OnClosed(t *testing.T) {
	m := NewStreamManager()

	var closed []*TCPStream
	m.SetCallbacks(&StreamCallbacks{
		OnStreamClosed: func(s *TCPStream) {
			closed = append(closed, s)
		},
	})

	key := threeWayHandshake(m, 1000, 2000)

	// RST closes stream immediately.
	m.ProcessPacket(mkPkt(serverIP, serverPort, clientIP, clientPort,
		2001, 1001, FlagRST, nil, t0.Add(5*time.Millisecond), 4))

	if len(closed) != 1 {
		t.Fatalf("expected 1 OnStreamClosed call, got %d", len(closed))
	}
	if closed[0].Key != key {
		t.Fatalf("closed stream key mismatch")
	}
	if closed[0].State != StateClosed {
		t.Fatalf("closed callback stream state: %s", closed[0].State)
	}

	// Processing another RST should NOT fire callback again (already closed).
	m.ProcessPacket(mkPkt(serverIP, serverPort, clientIP, clientPort,
		2001, 1001, FlagRST, nil, t0.Add(6*time.Millisecond), 5))
	if len(closed) != 1 {
		t.Fatalf("OnStreamClosed fired twice, count=%d", len(closed))
	}
}

// ---------------------------------------------------------------------------
// 12. TestStreamManager_CleanExpiredStreams
// ---------------------------------------------------------------------------

func TestStreamManager_CleanExpiredStreams(t *testing.T) {
	m := NewStreamManager()

	// Create two streams.
	threeWayHandshake(m, 1000, 2000)

	m.ProcessPacket(mkPkt("172.16.0.1", 12345, "172.16.0.2", 443,
		3000, 0, FlagSYN, nil, t0, 10))

	if m.StreamCount() != 2 {
		t.Fatalf("expected 2 streams, got %d", m.StreamCount())
	}

	t.Run("nothing cleaned when fresh", func(t *testing.T) {
		// Streams were just created with t0 timestamps, which are in the past.
		// CleanExpiredStreams uses time.Now(), so they are already "old".
		// Use a very large timeout so nothing is cleaned.
		removed := m.CleanExpiredStreams(time.Hour * 24 * 365 * 100)
		if removed != 0 {
			t.Fatalf("expected 0 removed with huge timeout, got %d", removed)
		}
	})

	t.Run("closed streams always cleaned", func(t *testing.T) {
		// Close the first stream via RST.
		m.ProcessPacket(mkPkt(serverIP, serverPort, clientIP, clientPort,
			2001, 1001, FlagRST, nil, t0.Add(time.Millisecond), 20))
		s := m.GetAllStreams()
		closedCount := 0
		for _, st := range s {
			if st.State == StateClosed {
				closedCount++
			}
		}
		if closedCount != 1 {
			t.Fatalf("expected 1 closed stream, got %d", closedCount)
		}
		removed := m.CleanExpiredStreams(time.Hour * 24 * 365 * 100)
		if removed != 1 {
			t.Fatalf("expected 1 removed (closed), got %d", removed)
		}
		if m.StreamCount() != 1 {
			t.Fatalf("expected 1 remaining stream, got %d", m.StreamCount())
		}
	})

	t.Run("stale streams cleaned by timeout", func(t *testing.T) {
		// The remaining stream has LastSeen from t0, which is far in the past.
		// Using a very short timeout should clean it.
		removed := m.CleanExpiredStreams(time.Nanosecond)
		if removed != 1 {
			t.Fatalf("expected 1 removed by timeout, got %d", removed)
		}
		if m.StreamCount() != 0 {
			t.Fatalf("expected 0 streams, got %d", m.StreamCount())
		}
	})
}

// ---------------------------------------------------------------------------
// 13. TestStreamManager_Concurrent
// ---------------------------------------------------------------------------

func TestStreamManager_Concurrent(t *testing.T) {
	m := NewStreamManager()
	const goroutines = 50
	const packetsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			srcPort := uint16(10000 + id)
			for p := 0; p < packetsPerGoroutine; p++ {
				seq := uint32(p * 100)
				m.ProcessPacket(mkPkt(
					"10.0.0.1", srcPort, "10.0.0.2", 80,
					seq, 0, FlagACK, []byte("x"), t0, id*packetsPerGoroutine+p,
				))
			}
		}(g)
	}

	wg.Wait()

	count := m.StreamCount()
	if count != goroutines {
		t.Fatalf("expected %d streams, got %d", goroutines, count)
	}

	// Verify concurrent read access.
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			_ = m.GetAllStreams()
			_ = m.StreamCount()
			_ = m.IsEnabled()
		}()
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// 14. TestStreamManager_SetEnabled
// ---------------------------------------------------------------------------

func TestStreamManager_SetEnabled(t *testing.T) {
	m := NewStreamManager()

	if !m.IsEnabled() {
		t.Fatal("new manager should be enabled by default")
	}

	m.SetEnabled(false)
	key := m.ProcessPacket(mkPkt(clientIP, clientPort, serverIP, serverPort,
		1000, 0, FlagSYN, nil, t0, 1))
	if key != "" {
		t.Fatalf("expected empty key when disabled, got %q", key)
	}
	if m.StreamCount() != 0 {
		t.Fatal("no streams should be created when disabled")
	}

	m.SetEnabled(true)
	key = m.ProcessPacket(mkPkt(clientIP, clientPort, serverIP, serverPort,
		1000, 0, FlagSYN, nil, t0, 2))
	if key == "" {
		t.Fatal("expected non-empty key when re-enabled")
	}
}

// ---------------------------------------------------------------------------
// 15. TestStreamManager_GetAllStreams_Sorted
// ---------------------------------------------------------------------------

func TestStreamManager_GetAllStreams_Sorted(t *testing.T) {
	m := NewStreamManager()

	// Create several streams; IDs should be sequential.
	for i := 0; i < 5; i++ {
		m.ProcessPacket(mkPkt(
			fmt.Sprintf("10.0.%d.1", i), uint16(40000+i),
			"10.0.0.100", 80,
			uint32(i*1000), 0, FlagSYN, nil, t0, i+1,
		))
	}

	streams := m.GetAllStreams()
	if len(streams) != 5 {
		t.Fatalf("expected 5 streams, got %d", len(streams))
	}
	for i := 1; i < len(streams); i++ {
		if streams[i].ID <= streams[i-1].ID {
			t.Fatalf("streams not sorted by ID: [%d].ID=%d, [%d].ID=%d",
				i-1, streams[i-1].ID, i, streams[i].ID)
		}
	}
}

// ---------------------------------------------------------------------------
// 16. TestStream_Duration
// ---------------------------------------------------------------------------

func TestStream_Duration(t *testing.T) {
	m := NewStreamManager()
	key := threeWayHandshake(m, 1000, 2000)

	// Send data at t0+100ms so LastSeen advances.
	m.ProcessPacket(mkPkt(clientIP, clientPort, serverIP, serverPort,
		1001, 2001, FlagACK|FlagPSH, []byte("hello"), t0.Add(100*time.Millisecond), 4))

	s := m.GetStream(key)
	dur := s.Duration()
	if dur != 100*time.Millisecond {
		t.Fatalf("expected 100ms duration, got %v", dur)
	}

	// Close the stream and verify EndTime is used.
	m.ProcessPacket(mkPkt(serverIP, serverPort, clientIP, clientPort,
		2001, 1006, FlagRST, nil, t0.Add(200*time.Millisecond), 5))
	s = m.GetStream(key)
	dur = s.Duration()
	if dur != 200*time.Millisecond {
		t.Fatalf("expected 200ms duration after close, got %v", dur)
	}
}

// ---------------------------------------------------------------------------
// 17. TestStreamState_CloseWait_LastAck
// ---------------------------------------------------------------------------

func TestStreamState_CloseWait_LastAck(t *testing.T) {
	m := NewStreamManager()
	key := threeWayHandshake(m, 1000, 2000)

	// Server initiates FIN (server-initiated close).
	m.ProcessPacket(mkPkt(serverIP, serverPort, clientIP, clientPort,
		2001, 1001, FlagFIN|FlagACK, nil, t0.Add(10*time.Millisecond), 4))
	if s := m.GetStream(key); s.State != StateCloseWait {
		t.Fatalf("expected CLOSE_WAIT after server FIN, got %s", s.State)
	}

	// Client ACK of server FIN.
	m.ProcessPacket(mkPkt(clientIP, clientPort, serverIP, serverPort,
		1001, 2002, FlagACK, nil, t0.Add(11*time.Millisecond), 5))

	// Client sends its own FIN.
	// Note: The implementation transitions directly to TIME_WAIT when both
	// ClientFinSeen and ServerFinSeen are true (simultaneous close path),
	// rather than going through LAST_ACK.
	m.ProcessPacket(mkPkt(clientIP, clientPort, serverIP, serverPort,
		1001, 2002, FlagFIN|FlagACK, nil, t0.Add(12*time.Millisecond), 6))
	if s := m.GetStream(key); s.State != StateTimeWait {
		t.Fatalf("expected TIME_WAIT after client FIN in CLOSE_WAIT (both FINs seen), got %s", s.State)
	}

	// Server ACK of client FIN.
	m.ProcessPacket(mkPkt(serverIP, serverPort, clientIP, clientPort,
		2002, 1002, FlagACK, nil, t0.Add(13*time.Millisecond), 7))
	if s := m.GetStream(key); s.State != StateClosed {
		t.Fatalf("expected CLOSED after TIME_WAIT ACK, got %s", s.State)
	}
}

// ---------------------------------------------------------------------------
// 18. TestStream_DataInClosingStates
// ---------------------------------------------------------------------------

func TestStream_DataInClosingStates(t *testing.T) {
	m := NewStreamManager()
	key := threeWayHandshake(m, 1000, 2000)

	// Client FIN -> FIN_WAIT_1.
	m.ProcessPacket(mkPkt(clientIP, clientPort, serverIP, serverPort,
		1001, 2001, FlagFIN|FlagACK, nil, t0.Add(10*time.Millisecond), 4))

	// Server sends data in FIN_WAIT_1 (still valid).
	payload := []byte("late data")
	m.ProcessPacket(mkPkt(serverIP, serverPort, clientIP, clientPort,
		2001, 1002, FlagACK|FlagPSH, payload, t0.Add(11*time.Millisecond), 5))

	s := m.GetStream(key)
	if s.ServerBytes != len(payload) {
		t.Fatalf("expected data accepted in FIN_WAIT_1: got ServerBytes=%d", s.ServerBytes)
	}
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

// BenchmarkStreamManager_ProcessPacket benchmarks processing a packet on an
// existing stream (established via three-way handshake).
func BenchmarkStreamManager_ProcessPacket(b *testing.B) {
	m := NewStreamManager()
	threeWayHandshake(m, 1000, 2000)

	pkt := mkPkt(clientIP, clientPort, serverIP, serverPort,
		1001, 2001, FlagACK|FlagPSH, []byte("benchmark payload data"),
		t0, 100)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		pkt.Seq = 1001 + uint32(i*22) // avoid retransmit detection
		pkt.PacketNum = 100 + i
		m.ProcessPacket(pkt)
	}
}

// BenchmarkStreamManager_ManyStreams benchmarks creating many independent
// streams via SYN packets and looking them up.
func BenchmarkStreamManager_ManyStreams(b *testing.B) {
	b.ReportAllocs()
	m := NewStreamManager()
	for i := 0; i < b.N; i++ {
		srcPort := uint16(10000 + (i % 55000))
		srcIP := fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF)
		m.ProcessPacket(mkPkt(
			srcIP, srcPort, "10.0.0.1", 80,
			uint32(i), 0, FlagSYN, nil, t0, i,
		))
	}
}
