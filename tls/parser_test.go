package tls

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// ---------------------------------------------------------------------------
// helpers: build raw TLS byte sequences for tests
// ---------------------------------------------------------------------------

// buildTLSRecord constructs a raw TLS record: header(5) + fragment.
func buildTLSRecord(contentType uint8, version uint16, fragment []byte) []byte {
	buf := make([]byte, 5+len(fragment))
	buf[0] = contentType
	binary.BigEndian.PutUint16(buf[1:3], version)
	binary.BigEndian.PutUint16(buf[3:5], uint16(len(fragment)))
	copy(buf[5:], fragment)
	return buf
}

// buildHandshake constructs a raw handshake message: type(1) + length(3) + data.
func buildHandshake(hsType uint8, data []byte) []byte {
	buf := make([]byte, 4+len(data))
	buf[0] = hsType
	buf[1] = byte(len(data) >> 16)
	buf[2] = byte(len(data) >> 8)
	buf[3] = byte(len(data))
	copy(buf[4:], data)
	return buf
}

// buildSNIExtension creates a raw SNI extension block (type 0x0000).
// Layout: ext_type(2) + ext_len(2) + list_len(2) + name_type(1) + name_len(2) + name.
func buildSNIExtension(hostname string) []byte {
	name := []byte(hostname)
	// inner: name_type(1) + name_len(2) + name
	innerLen := 1 + 2 + len(name)
	// list_len covers innerLen
	listLen := innerLen
	// extension data = list_len(2) + inner
	extDataLen := 2 + listLen

	buf := make([]byte, 4+extDataLen)
	// ext_type = 0x0000
	binary.BigEndian.PutUint16(buf[0:2], 0x0000)
	// ext_len
	binary.BigEndian.PutUint16(buf[2:4], uint16(extDataLen))
	// list_len
	binary.BigEndian.PutUint16(buf[4:6], uint16(listLen))
	// name_type = 0 (hostname)
	buf[6] = 0x00
	// name_len
	binary.BigEndian.PutUint16(buf[7:9], uint16(len(name)))
	copy(buf[9:], name)
	return buf
}

// buildALPNExtension creates a raw ALPN extension block (type 0x0010).
// Layout: ext_type(2) + ext_len(2) + list_len(2) + (proto_len(1) + proto)*
func buildALPNExtension(protocols []string) []byte {
	// Compute ALPN list body
	var listBody []byte
	for _, p := range protocols {
		listBody = append(listBody, byte(len(p)))
		listBody = append(listBody, []byte(p)...)
	}
	listLen := len(listBody)
	extDataLen := 2 + listLen // list_len(2) + body

	buf := make([]byte, 4+extDataLen)
	binary.BigEndian.PutUint16(buf[0:2], ExtensionTypeALPN) // 0x0010
	binary.BigEndian.PutUint16(buf[2:4], uint16(extDataLen))
	binary.BigEndian.PutUint16(buf[4:6], uint16(listLen))
	copy(buf[6:], listBody)
	return buf
}

// buildClientHelloBody constructs the body of a ClientHello (no handshake header).
// version(2) + random(32) + sessionID_len(1) + sessionID + cipher_suites_len(2) + suites
// + comp_len(1) + comp + extensions_len(2) + extensions.
func buildClientHelloBody(version uint16, sessionID []byte, suites []uint16,
	compMethods []uint8, extensions []byte,
) []byte {
	var buf []byte

	// version
	v := make([]byte, 2)
	binary.BigEndian.PutUint16(v, version)
	buf = append(buf, v...)

	// random (32 bytes, zero-filled for tests)
	buf = append(buf, make([]byte, 32)...)

	// session ID
	buf = append(buf, byte(len(sessionID)))
	buf = append(buf, sessionID...)

	// cipher suites
	suitesLen := make([]byte, 2)
	binary.BigEndian.PutUint16(suitesLen, uint16(len(suites)*2))
	buf = append(buf, suitesLen...)
	for _, s := range suites {
		sb := make([]byte, 2)
		binary.BigEndian.PutUint16(sb, s)
		buf = append(buf, sb...)
	}

	// compression methods
	buf = append(buf, byte(len(compMethods)))
	buf = append(buf, compMethods...)

	// extensions (optional)
	if len(extensions) > 0 {
		extLen := make([]byte, 2)
		binary.BigEndian.PutUint16(extLen, uint16(len(extensions)))
		buf = append(buf, extLen...)
		buf = append(buf, extensions...)
	}

	return buf
}

// buildServerHelloBody constructs the body of a ServerHello (no handshake header).
func buildServerHelloBody(version uint16, sessionID []byte, suite uint16,
	compMethod uint8, extensions []byte,
) []byte {
	var buf []byte

	// version
	v := make([]byte, 2)
	binary.BigEndian.PutUint16(v, version)
	buf = append(buf, v...)

	// random (32 bytes)
	buf = append(buf, make([]byte, 32)...)

	// session ID
	buf = append(buf, byte(len(sessionID)))
	buf = append(buf, sessionID...)

	// cipher suite
	sb := make([]byte, 2)
	binary.BigEndian.PutUint16(sb, suite)
	buf = append(buf, sb...)

	// compression method
	buf = append(buf, compMethod)

	// extensions (optional)
	if len(extensions) > 0 {
		extLen := make([]byte, 2)
		binary.BigEndian.PutUint16(extLen, uint16(len(extensions)))
		buf = append(buf, extLen...)
		buf = append(buf, extensions...)
	}

	return buf
}

// ---------------------------------------------------------------------------
// 1. TestIsTLSRecord
// ---------------------------------------------------------------------------

func TestIsTLSRecord(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		// Valid content types with various TLS versions
		{
			name: "Handshake TLS 1.0",
			data: buildTLSRecord(ContentTypeHandshake, VersionTLS10, []byte{0x01}),
			want: true,
		},
		{
			name: "Handshake TLS 1.2",
			data: buildTLSRecord(ContentTypeHandshake, VersionTLS12, []byte{0x01}),
			want: true,
		},
		{
			name: "Handshake TLS 1.3",
			data: buildTLSRecord(ContentTypeHandshake, VersionTLS13, []byte{0x01}),
			want: true,
		},
		{
			name: "ApplicationData TLS 1.2",
			data: buildTLSRecord(ContentTypeApplicationData, VersionTLS12, []byte{0xFF}),
			want: true,
		},
		{
			name: "ChangeCipherSpec SSL 3.0",
			data: buildTLSRecord(ContentTypeChangeCipherSpec, VersionSSL30, []byte{0x01}),
			want: true,
		},
		{
			name: "Alert TLS 1.1",
			data: buildTLSRecord(ContentTypeAlert, VersionTLS11, []byte{0x02, 0x28}),
			want: true,
		},
		// Invalid content type
		{
			name: "invalid content type 19",
			data: []byte{19, 0x03, 0x03, 0x00, 0x01},
			want: false,
		},
		{
			name: "invalid content type 24",
			data: []byte{24, 0x03, 0x03, 0x00, 0x01},
			want: false,
		},
		{
			name: "invalid content type 0",
			data: []byte{0x00, 0x03, 0x03, 0x00, 0x01},
			want: false,
		},
		// Invalid version
		{
			name: "invalid version 0x0200",
			data: []byte{ContentTypeHandshake, 0x02, 0x00, 0x00, 0x01},
			want: false,
		},
		{
			name: "invalid version 0x0305",
			data: []byte{ContentTypeHandshake, 0x03, 0x05, 0x00, 0x01},
			want: false,
		},
		// Boundary: too short
		{
			name: "too short 0 bytes",
			data: []byte{},
			want: false,
		},
		{
			name: "too short 4 bytes",
			data: []byte{ContentTypeHandshake, 0x03, 0x03, 0x00},
			want: false,
		},
		// Boundary: exactly 5 bytes is enough for the header check
		{
			name: "exactly 5 bytes valid",
			data: []byte{ContentTypeHandshake, 0x03, 0x03, 0x00, 0x00},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsTLSRecord(tt.data)
			if got != tt.want {
				t.Errorf("IsTLSRecord(%v) = %v, want %v", tt.data, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 2. TestParseTLSRecord
// ---------------------------------------------------------------------------

func TestParseTLSRecord(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		wantCT      uint8
		wantVersion uint16
		wantFragLen int
		wantConsum  int
	}{
		{
			name:        "Handshake record",
			data:        buildTLSRecord(ContentTypeHandshake, VersionTLS12, []byte{0x01, 0x00, 0x00, 0x05}),
			wantCT:      ContentTypeHandshake,
			wantVersion: VersionTLS12,
			wantFragLen: 4,
			wantConsum:  9, // 5 header + 4 fragment
		},
		{
			name:        "ApplicationData record",
			data:        buildTLSRecord(ContentTypeApplicationData, VersionTLS13, bytes.Repeat([]byte{0xAB}, 100)),
			wantCT:      ContentTypeApplicationData,
			wantVersion: VersionTLS13,
			wantFragLen: 100,
			wantConsum:  105,
		},
		{
			name:        "Alert record",
			data:        buildTLSRecord(ContentTypeAlert, VersionTLS12, []byte{0x02, 0x28}),
			wantCT:      ContentTypeAlert,
			wantVersion: VersionTLS12,
			wantFragLen: 2,
			wantConsum:  7,
		},
		{
			name:        "ChangeCipherSpec record",
			data:        buildTLSRecord(ContentTypeChangeCipherSpec, VersionTLS12, []byte{0x01}),
			wantCT:      ContentTypeChangeCipherSpec,
			wantVersion: VersionTLS12,
			wantFragLen: 1,
			wantConsum:  6,
		},
		{
			name:        "empty fragment",
			data:        buildTLSRecord(ContentTypeHandshake, VersionTLS10, []byte{}),
			wantCT:      ContentTypeHandshake,
			wantVersion: VersionTLS10,
			wantFragLen: 0,
			wantConsum:  5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, consumed, err := ParseTLSRecord(tt.data)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if rec.ContentType != tt.wantCT {
				t.Errorf("ContentType = %d, want %d", rec.ContentType, tt.wantCT)
			}
			if rec.Version != tt.wantVersion {
				t.Errorf("Version = 0x%04X, want 0x%04X", rec.Version, tt.wantVersion)
			}
			if len(rec.Fragment) != tt.wantFragLen {
				t.Errorf("Fragment length = %d, want %d", len(rec.Fragment), tt.wantFragLen)
			}
			if consumed != tt.wantConsum {
				t.Errorf("consumed = %d, want %d", consumed, tt.wantConsum)
			}
		})
	}

	// Extra data after the record should not be consumed
	t.Run("trailing data not consumed", func(t *testing.T) {
		record := buildTLSRecord(ContentTypeHandshake, VersionTLS12, []byte{0x01})
		withTrailing := append(record, 0xDE, 0xAD)
		_, consumed, err := ParseTLSRecord(withTrailing)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if consumed != 6 { // 5 header + 1 fragment
			t.Errorf("consumed = %d, want 6", consumed)
		}
	})

	// Fragment content fidelity
	t.Run("fragment content matches", func(t *testing.T) {
		payload := []byte("HELLO TLS")
		rec, _, err := ParseTLSRecord(buildTLSRecord(ContentTypeApplicationData, VersionTLS12, payload))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(rec.Fragment, payload) {
			t.Errorf("fragment = %x, want %x", rec.Fragment, payload)
		}
	})
}

// ---------------------------------------------------------------------------
// 3. TestParseTLSRecord_TooShort
// ---------------------------------------------------------------------------

func TestParseTLSRecord_TooShort(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"1 byte", []byte{0x16}},
		{"4 bytes", []byte{0x16, 0x03, 0x03, 0x00}},
		{
			"header says 10 bytes fragment but only 5 available",
			[]byte{0x16, 0x03, 0x03, 0x00, 0x0A, 0x01, 0x02, 0x03, 0x04, 0x05},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := ParseTLSRecord(tt.data)
			if err == nil {
				t.Error("expected error for short data, got nil")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 4. TestParseHandshakeMessage
// ---------------------------------------------------------------------------

func TestParseHandshakeMessage(t *testing.T) {
	t.Run("valid ClientHello handshake", func(t *testing.T) {
		data := []byte{0xAA, 0xBB, 0xCC}
		raw := buildHandshake(HandshakeTypeClientHello, data)
		msg, consumed, err := ParseHandshakeMessage(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if msg.Type != HandshakeTypeClientHello {
			t.Errorf("Type = %d, want %d", msg.Type, HandshakeTypeClientHello)
		}
		if msg.Length != 3 {
			t.Errorf("Length = %d, want 3", msg.Length)
		}
		if !bytes.Equal(msg.Data, data) {
			t.Errorf("Data = %x, want %x", msg.Data, data)
		}
		if consumed != 7 { // 4 header + 3 data
			t.Errorf("consumed = %d, want 7", consumed)
		}
	})

	t.Run("valid ServerHello handshake", func(t *testing.T) {
		data := bytes.Repeat([]byte{0x42}, 50)
		raw := buildHandshake(HandshakeTypeServerHello, data)
		msg, consumed, err := ParseHandshakeMessage(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if msg.Type != HandshakeTypeServerHello {
			t.Errorf("Type = %d, want %d", msg.Type, HandshakeTypeServerHello)
		}
		if msg.Length != 50 {
			t.Errorf("Length = %d, want 50", msg.Length)
		}
		if consumed != 54 {
			t.Errorf("consumed = %d, want 54", consumed)
		}
	})

	t.Run("empty data body", func(t *testing.T) {
		raw := buildHandshake(HandshakeTypeServerHelloDone, []byte{})
		msg, consumed, err := ParseHandshakeMessage(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if msg.Type != HandshakeTypeServerHelloDone {
			t.Errorf("Type = %d, want %d", msg.Type, HandshakeTypeServerHelloDone)
		}
		if msg.Length != 0 {
			t.Errorf("Length = %d, want 0", msg.Length)
		}
		if consumed != 4 {
			t.Errorf("consumed = %d, want 4", consumed)
		}
	})

	t.Run("trailing bytes not consumed", func(t *testing.T) {
		raw := buildHandshake(HandshakeTypeFinished, []byte{0x01, 0x02})
		raw = append(raw, 0xFF, 0xFE) // trailing
		msg, consumed, err := ParseHandshakeMessage(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if consumed != 6 { // 4 header + 2 data
			t.Errorf("consumed = %d, want 6", consumed)
		}
		if len(msg.Data) != 2 {
			t.Errorf("Data length = %d, want 2", len(msg.Data))
		}
	})

	// Error cases
	t.Run("too short nil", func(t *testing.T) {
		_, _, err := ParseHandshakeMessage(nil)
		if err == nil {
			t.Error("expected error for nil data")
		}
	})

	t.Run("too short 3 bytes", func(t *testing.T) {
		_, _, err := ParseHandshakeMessage([]byte{0x01, 0x00, 0x00})
		if err == nil {
			t.Error("expected error for 3-byte data")
		}
	})

	t.Run("header claims more data than available", func(t *testing.T) {
		// type=1, length=100, but only 4 bytes of data provided
		raw := []byte{0x01, 0x00, 0x00, 0x64, 0xAA, 0xBB, 0xCC, 0xDD}
		_, _, err := ParseHandshakeMessage(raw)
		if err == nil {
			t.Error("expected error when data is shorter than claimed length")
		}
	})
}

// ---------------------------------------------------------------------------
// 5. TestParseClientHello
// ---------------------------------------------------------------------------

func TestParseClientHello(t *testing.T) {
	t.Run("with SNI and cipher suites", func(t *testing.T) {
		sniExt := buildSNIExtension("example.com")
		suites := []uint16{
			TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			TLS_AES_128_GCM_SHA256,
		}
		body := buildClientHelloBody(VersionTLS12, nil, suites, []uint8{0x00}, sniExt)

		ch, err := ParseClientHello(body)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ch.Version != VersionTLS12 {
			t.Errorf("Version = 0x%04X, want 0x%04X", ch.Version, VersionTLS12)
		}
		if len(ch.Random) != 32 {
			t.Errorf("Random length = %d, want 32", len(ch.Random))
		}
		if ch.SNI != "example.com" {
			t.Errorf("SNI = %q, want %q", ch.SNI, "example.com")
		}
		if len(ch.CipherSuites) != 3 {
			t.Fatalf("CipherSuites count = %d, want 3", len(ch.CipherSuites))
		}
		if ch.CipherSuites[0] != TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 {
			t.Errorf("CipherSuites[0] = 0x%04X, want 0x%04X",
				ch.CipherSuites[0], TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
		}
		if ch.CipherSuites[2] != TLS_AES_128_GCM_SHA256 {
			t.Errorf("CipherSuites[2] = 0x%04X, want 0x%04X",
				ch.CipherSuites[2], TLS_AES_128_GCM_SHA256)
		}
		if len(ch.CompressionMethods) != 1 || ch.CompressionMethods[0] != 0x00 {
			t.Errorf("CompressionMethods = %v, want [0]", ch.CompressionMethods)
		}
	})

	t.Run("with ALPN extension", func(t *testing.T) {
		alpnExt := buildALPNExtension([]string{"h2", "http/1.1"})
		body := buildClientHelloBody(VersionTLS12, nil,
			[]uint16{TLS_AES_128_GCM_SHA256}, []uint8{0x00}, alpnExt)

		ch, err := ParseClientHello(body)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(ch.ALPNProtocols) != 2 {
			t.Fatalf("ALPNProtocols count = %d, want 2", len(ch.ALPNProtocols))
		}
		if ch.ALPNProtocols[0] != "h2" {
			t.Errorf("ALPNProtocols[0] = %q, want %q", ch.ALPNProtocols[0], "h2")
		}
		if ch.ALPNProtocols[1] != "http/1.1" {
			t.Errorf("ALPNProtocols[1] = %q, want %q", ch.ALPNProtocols[1], "http/1.1")
		}
	})

	t.Run("with SNI and ALPN combined", func(t *testing.T) {
		var extensions []byte
		extensions = append(extensions, buildSNIExtension("secure.example.org")...)
		extensions = append(extensions, buildALPNExtension([]string{"h2", "h2c", "http/1.1"})...)

		body := buildClientHelloBody(VersionTLS13, []byte{0x01, 0x02, 0x03, 0x04},
			[]uint16{TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256},
			[]uint8{0x00}, extensions)

		ch, err := ParseClientHello(body)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ch.Version != VersionTLS13 {
			t.Errorf("Version = 0x%04X, want 0x%04X", ch.Version, VersionTLS13)
		}
		if ch.SNI != "secure.example.org" {
			t.Errorf("SNI = %q, want %q", ch.SNI, "secure.example.org")
		}
		if len(ch.SessionID) != 4 {
			t.Errorf("SessionID length = %d, want 4", len(ch.SessionID))
		}
		if len(ch.ALPNProtocols) != 3 {
			t.Fatalf("ALPNProtocols count = %d, want 3", len(ch.ALPNProtocols))
		}
		if ch.ALPNProtocols[0] != "h2" {
			t.Errorf("ALPNProtocols[0] = %q, want %q", ch.ALPNProtocols[0], "h2")
		}
	})

	t.Run("no extensions", func(t *testing.T) {
		body := buildClientHelloBody(VersionTLS12, nil,
			[]uint16{TLS_RSA_WITH_AES_128_CBC_SHA}, []uint8{0x00}, nil)

		ch, err := ParseClientHello(body)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ch.SNI != "" {
			t.Errorf("SNI = %q, want empty", ch.SNI)
		}
		if ch.ALPNProtocols != nil {
			t.Errorf("ALPNProtocols = %v, want nil", ch.ALPNProtocols)
		}
	})

	t.Run("with session ID", func(t *testing.T) {
		sessionID := bytes.Repeat([]byte{0xAA}, 32)
		body := buildClientHelloBody(VersionTLS12, sessionID,
			[]uint16{TLS_RSA_WITH_AES_256_CBC_SHA}, []uint8{0x00}, nil)

		ch, err := ParseClientHello(body)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(ch.SessionID, sessionID) {
			t.Errorf("SessionID mismatch")
		}
	})

	t.Run("multiple cipher suites", func(t *testing.T) {
		suites := []uint16{
			TLS_RSA_WITH_AES_128_CBC_SHA,
			TLS_RSA_WITH_AES_256_CBC_SHA,
			TLS_RSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		}
		body := buildClientHelloBody(VersionTLS12, nil, suites, []uint8{0x00}, nil)

		ch, err := ParseClientHello(body)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(ch.CipherSuites) != len(suites) {
			t.Fatalf("CipherSuites count = %d, want %d", len(ch.CipherSuites), len(suites))
		}
		for i, s := range suites {
			if ch.CipherSuites[i] != s {
				t.Errorf("CipherSuites[%d] = 0x%04X, want 0x%04X", i, ch.CipherSuites[i], s)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// 6. TestParseClientHello_TooShort
// ---------------------------------------------------------------------------

func TestParseClientHello_TooShort(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"37 bytes (need 38 minimum)", make([]byte, 37)},
		{
			"truncated at session ID",
			// version(2) + random(32) + sessionID_len=10 but no sessionID data
			func() []byte {
				buf := make([]byte, 35) // 2+32+1
				buf[34] = 10            // sessionID_len claims 10 bytes
				return buf
			}(),
		},
		{
			"truncated at cipher suites length",
			// version(2) + random(32) + sessionID_len=0 + only 1 byte for suites_len
			func() []byte {
				buf := make([]byte, 36) // 2+32+1+1 (need 2 for cipher_suites_len)
				buf[34] = 0             // sessionID_len = 0
				return buf
			}(),
		},
		{
			"truncated at cipher suites data",
			// version(2) + random(32) + sessionID_len=0 + cipher_suites_len=4 + only 2 bytes
			func() []byte {
				buf := make([]byte, 39) // 2+32+1+2+2 (need 4 more for suites)
				buf[34] = 0             // sessionID_len = 0
				buf[35] = 0
				buf[36] = 4 // cipher_suites_len = 4
				return buf
			}(),
		},
		{
			"truncated at compression methods length",
			// version(2) + random(32) + sessionID_len=0 + cipher_suites_len=2 + suite(2)
			// no compression methods length byte
			func() []byte {
				buf := make([]byte, 39) // 2+32+1+2+2, exactly up to end of suites
				buf[34] = 0             // sessionID_len = 0
				buf[35] = 0
				buf[36] = 2 // cipher_suites_len = 2
				return buf
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseClientHello(tt.data)
			if err == nil {
				t.Error("expected error for truncated ClientHello, got nil")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 7. TestParseServerHello
// ---------------------------------------------------------------------------

func TestParseServerHello(t *testing.T) {
	t.Run("basic ServerHello", func(t *testing.T) {
		body := buildServerHelloBody(VersionTLS12, nil,
			TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 0x00, nil)

		sh, err := ParseServerHello(body)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if sh.Version != VersionTLS12 {
			t.Errorf("Version = 0x%04X, want 0x%04X", sh.Version, VersionTLS12)
		}
		if len(sh.Random) != 32 {
			t.Errorf("Random length = %d, want 32", len(sh.Random))
		}
		if sh.CipherSuite != TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 {
			t.Errorf("CipherSuite = 0x%04X, want 0x%04X",
				sh.CipherSuite, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
		}
		if sh.CompressionMethod != 0x00 {
			t.Errorf("CompressionMethod = %d, want 0", sh.CompressionMethod)
		}
	})

	t.Run("with ALPN extension h2", func(t *testing.T) {
		alpnExt := buildALPNExtension([]string{"h2"})
		body := buildServerHelloBody(VersionTLS12, nil,
			TLS_AES_128_GCM_SHA256, 0x00, alpnExt)

		sh, err := ParseServerHello(body)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if sh.ALPNProtocol != "h2" {
			t.Errorf("ALPNProtocol = %q, want %q", sh.ALPNProtocol, "h2")
		}
	})

	t.Run("with session ID", func(t *testing.T) {
		sessionID := bytes.Repeat([]byte{0xBB}, 32)
		body := buildServerHelloBody(VersionTLS12, sessionID,
			TLS_RSA_WITH_AES_256_GCM_SHA384, 0x00, nil)

		sh, err := ParseServerHello(body)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(sh.SessionID, sessionID) {
			t.Errorf("SessionID mismatch")
		}
	})

	t.Run("TLS 1.3 version", func(t *testing.T) {
		body := buildServerHelloBody(VersionTLS13, nil,
			TLS_AES_256_GCM_SHA384, 0x00, nil)

		sh, err := ParseServerHello(body)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if sh.Version != VersionTLS13 {
			t.Errorf("Version = 0x%04X, want 0x%04X", sh.Version, VersionTLS13)
		}
	})

	t.Run("too short", func(t *testing.T) {
		_, err := ParseServerHello(make([]byte, 37))
		if err == nil {
			t.Error("expected error for 37-byte ServerHello")
		}
	})

	t.Run("truncated at session ID", func(t *testing.T) {
		buf := make([]byte, 35)
		buf[34] = 20 // sessionID_len claims 20 bytes, but none provided
		_, err := ParseServerHello(buf)
		if err == nil {
			t.Error("expected error for truncated session ID")
		}
	})

	t.Run("truncated at cipher suite", func(t *testing.T) {
		// version(2) + random(32) + sessionID_len=0 + only 1 byte for suite
		buf := make([]byte, 36)
		buf[34] = 0 // sessionID_len = 0
		_, err := ParseServerHello(buf)
		if err == nil {
			t.Error("expected error for truncated cipher suite")
		}
	})

	t.Run("truncated at compression method", func(t *testing.T) {
		// version(2) + random(32) + sessionID_len=0 + suite(2) but no comp method
		buf := make([]byte, 37)
		buf[34] = 0 // sessionID_len = 0
		_, err := ParseServerHello(buf)
		if err == nil {
			t.Error("expected error for truncated compression method")
		}
	})
}

// ---------------------------------------------------------------------------
// 8. TestGetVersionName
// ---------------------------------------------------------------------------

func TestGetVersionName(t *testing.T) {
	tests := []struct {
		version uint16
		want    string
	}{
		{VersionSSL30, "SSL 3.0"},
		{VersionTLS10, "TLS 1.0"},
		{VersionTLS11, "TLS 1.1"},
		{VersionTLS12, "TLS 1.2"},
		{VersionTLS13, "TLS 1.3"},
		{0x0305, "Unknown (0x0305)"},
		{0x0000, "Unknown (0x0000)"},
		{0xFFFF, "Unknown (0xFFFF)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := GetVersionName(tt.version)
			if got != tt.want {
				t.Errorf("GetVersionName(0x%04X) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 9. TestGetCipherSuiteName
// ---------------------------------------------------------------------------

func TestGetCipherSuiteName(t *testing.T) {
	tests := []struct {
		suite uint16
		want  string
	}{
		{TLS_RSA_WITH_AES_128_CBC_SHA, "TLS_RSA_WITH_AES_128_CBC_SHA"},
		{TLS_RSA_WITH_AES_256_CBC_SHA, "TLS_RSA_WITH_AES_256_CBC_SHA"},
		{TLS_RSA_WITH_AES_128_CBC_SHA256, "TLS_RSA_WITH_AES_128_CBC_SHA256"},
		{TLS_RSA_WITH_AES_256_CBC_SHA256, "TLS_RSA_WITH_AES_256_CBC_SHA256"},
		{TLS_RSA_WITH_AES_128_GCM_SHA256, "TLS_RSA_WITH_AES_128_GCM_SHA256"},
		{TLS_RSA_WITH_AES_256_GCM_SHA384, "TLS_RSA_WITH_AES_256_GCM_SHA384"},
		{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"},
		{TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"},
		{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"},
		{TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"},
		{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
		{TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
		{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
		{TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"},
		{TLS_AES_128_GCM_SHA256, "TLS_AES_128_GCM_SHA256"},
		{TLS_AES_256_GCM_SHA384, "TLS_AES_256_GCM_SHA384"},
		{TLS_CHACHA20_POLY1305_SHA256, "TLS_CHACHA20_POLY1305_SHA256"},
		// Unknown
		{0x0000, "Unknown (0x0000)"},
		{0xFFFF, "Unknown (0xFFFF)"},
		{0xCAFE, "Unknown (0xCAFE)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := GetCipherSuiteName(tt.suite)
			if got != tt.want {
				t.Errorf("GetCipherSuiteName(0x%04X) = %q, want %q", tt.suite, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 10. TestGetContentTypeName
// ---------------------------------------------------------------------------

func TestGetContentTypeName(t *testing.T) {
	tests := []struct {
		ct   uint8
		want string
	}{
		{ContentTypeChangeCipherSpec, "ChangeCipherSpec"},
		{ContentTypeAlert, "Alert"},
		{ContentTypeHandshake, "Handshake"},
		{ContentTypeApplicationData, "ApplicationData"},
		{0, "Unknown (0)"},
		{19, "Unknown (19)"},
		{24, "Unknown (24)"},
		{255, "Unknown (255)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := GetContentTypeName(tt.ct)
			if got != tt.want {
				t.Errorf("GetContentTypeName(%d) = %q, want %q", tt.ct, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 11. TestGetHandshakeTypeName
// ---------------------------------------------------------------------------

func TestGetHandshakeTypeName(t *testing.T) {
	tests := []struct {
		ht   uint8
		want string
	}{
		{HandshakeTypeClientHello, "ClientHello"},
		{HandshakeTypeServerHello, "ServerHello"},
		{HandshakeTypeCertificate, "Certificate"},
		{HandshakeTypeServerKeyExchange, "ServerKeyExchange"},
		{HandshakeTypeCertificateRequest, "CertificateRequest"},
		{HandshakeTypeServerHelloDone, "ServerHelloDone"},
		{HandshakeTypeCertificateVerify, "CertificateVerify"},
		{HandshakeTypeClientKeyExchange, "ClientKeyExchange"},
		{HandshakeTypeFinished, "Finished"},
		{0, "Unknown (0)"},
		{3, "Unknown (3)"},
		{255, "Unknown (255)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := GetHandshakeTypeName(tt.ht)
			if got != tt.want {
				t.Errorf("GetHandshakeTypeName(%d) = %q, want %q", tt.ht, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 12. TestIsHTTP2ALPN
// ---------------------------------------------------------------------------

func TestIsHTTP2ALPN(t *testing.T) {
	tests := []struct {
		protocol string
		want     bool
	}{
		{"h2", true},
		{"h2c", true},
		{"http/1.1", false},
		{"http/1.0", false},
		{"", false},
		{"H2", false},   // case-sensitive
		{"h2 ", false},  // trailing space
		{" h2", false},  // leading space
		{"spdy", false}, // other protocol
	}

	for _, tt := range tests {
		t.Run("protocol="+tt.protocol, func(t *testing.T) {
			got := IsHTTP2ALPN(tt.protocol)
			if got != tt.want {
				t.Errorf("IsHTTP2ALPN(%q) = %v, want %v", tt.protocol, got, tt.want)
			}
		})
	}
}
