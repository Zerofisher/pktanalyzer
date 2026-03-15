package tls

import (
	"encoding/binary"
	"fmt"
)

// TLS Content Types
const (
	ContentTypeChangeCipherSpec = 20
	ContentTypeAlert            = 21
	ContentTypeHandshake        = 22
	ContentTypeApplicationData  = 23
)

// TLS Handshake Types
const (
	HandshakeTypeClientHello        = 1
	HandshakeTypeServerHello        = 2
	HandshakeTypeCertificate        = 11
	HandshakeTypeServerKeyExchange  = 12
	HandshakeTypeCertificateRequest = 13
	HandshakeTypeServerHelloDone    = 14
	HandshakeTypeCertificateVerify  = 15
	HandshakeTypeClientKeyExchange  = 16
	HandshakeTypeFinished           = 20
)

// TLS Versions
const (
	VersionSSL30 = 0x0300
	VersionTLS10 = 0x0301
	VersionTLS11 = 0x0302
	VersionTLS12 = 0x0303
	VersionTLS13 = 0x0304
)

// Common Cipher Suites
const (
	TLS_RSA_WITH_AES_128_CBC_SHA            = 0x002F
	TLS_RSA_WITH_AES_256_CBC_SHA            = 0x0035
	TLS_RSA_WITH_AES_128_CBC_SHA256         = 0x003C
	TLS_RSA_WITH_AES_256_CBC_SHA256         = 0x003D
	TLS_RSA_WITH_AES_128_GCM_SHA256         = 0x009C
	TLS_RSA_WITH_AES_256_GCM_SHA384         = 0x009D
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA      = 0xC013
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA      = 0xC014
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256   = 0xC027
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384   = 0xC028
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   = 0xC02F
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384   = 0xC030
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02C
	TLS_AES_128_GCM_SHA256                  = 0x1301 // TLS 1.3
	TLS_AES_256_GCM_SHA384                  = 0x1302 // TLS 1.3
	TLS_CHACHA20_POLY1305_SHA256            = 0x1303 // TLS 1.3
)

// TLSRecord represents a TLS record layer
type TLSRecord struct {
	ContentType uint8
	Version     uint16
	Length      uint16
	Fragment    []byte
}

// HandshakeMessage represents a TLS handshake message
type HandshakeMessage struct {
	Type   uint8
	Length uint32
	Data   []byte
}

// ClientHello represents parsed ClientHello message
type ClientHello struct {
	Version            uint16
	Random             []byte // 32 bytes
	SessionID          []byte
	CipherSuites       []uint16
	CompressionMethods []uint8
	Extensions         []byte
	SNI                string
	ALPNProtocols      []string // ALPN protocols offered by client
}

// ServerHello represents parsed ServerHello message
type ServerHello struct {
	Version           uint16
	Random            []byte // 32 bytes
	SessionID         []byte
	CipherSuite       uint16
	CompressionMethod uint8
	Extensions        []byte
	ALPNProtocol      string // Selected ALPN protocol
}

// ParseTLSRecord parses a TLS record from raw bytes
func ParseTLSRecord(data []byte) (*TLSRecord, int, error) {
	if len(data) < 5 {
		return nil, 0, fmt.Errorf("data too short for TLS record header")
	}

	record := &TLSRecord{
		ContentType: data[0],
		Version:     binary.BigEndian.Uint16(data[1:3]),
		Length:      binary.BigEndian.Uint16(data[3:5]),
	}

	totalLen := 5 + int(record.Length)
	if len(data) < totalLen {
		return nil, 0, fmt.Errorf("data too short for TLS record: need %d, have %d", totalLen, len(data))
	}

	record.Fragment = make([]byte, record.Length)
	copy(record.Fragment, data[5:totalLen])

	return record, totalLen, nil
}

// ParseHandshakeMessage parses a handshake message from record fragment
func ParseHandshakeMessage(data []byte) (*HandshakeMessage, int, error) {
	if len(data) < 4 {
		return nil, 0, fmt.Errorf("data too short for handshake header")
	}

	msg := &HandshakeMessage{
		Type:   data[0],
		Length: uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3]),
	}

	totalLen := 4 + int(msg.Length)
	if len(data) < totalLen {
		return nil, 0, fmt.Errorf("data too short for handshake message")
	}

	msg.Data = make([]byte, msg.Length)
	copy(msg.Data, data[4:totalLen])

	return msg, totalLen, nil
}

// ParseClientHello parses a ClientHello message
func ParseClientHello(data []byte) (*ClientHello, error) {
	if len(data) < 38 {
		return nil, fmt.Errorf("ClientHello too short")
	}

	ch := &ClientHello{
		Version: binary.BigEndian.Uint16(data[0:2]),
		Random:  make([]byte, 32),
	}
	copy(ch.Random, data[2:34])

	offset := 34

	// Session ID
	if offset >= len(data) {
		return nil, fmt.Errorf("ClientHello truncated at session ID length")
	}
	sessionIDLen := int(data[offset])
	offset++

	if offset+sessionIDLen > len(data) {
		return nil, fmt.Errorf("ClientHello truncated at session ID")
	}
	ch.SessionID = make([]byte, sessionIDLen)
	copy(ch.SessionID, data[offset:offset+sessionIDLen])
	offset += sessionIDLen

	// Cipher Suites
	if offset+2 > len(data) {
		return nil, fmt.Errorf("ClientHello truncated at cipher suites length")
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	if offset+cipherSuitesLen > len(data) {
		return nil, fmt.Errorf("ClientHello truncated at cipher suites")
	}
	numSuites := cipherSuitesLen / 2
	ch.CipherSuites = make([]uint16, numSuites)
	for i := 0; i < numSuites; i++ {
		ch.CipherSuites[i] = binary.BigEndian.Uint16(data[offset+i*2 : offset+i*2+2])
	}
	offset += cipherSuitesLen

	// Compression Methods
	if offset >= len(data) {
		return nil, fmt.Errorf("ClientHello truncated at compression methods length")
	}
	compMethodsLen := int(data[offset])
	offset++

	if offset+compMethodsLen > len(data) {
		return nil, fmt.Errorf("ClientHello truncated at compression methods")
	}
	ch.CompressionMethods = make([]uint8, compMethodsLen)
	copy(ch.CompressionMethods, data[offset:offset+compMethodsLen])
	offset += compMethodsLen

	// Extensions (if present)
	if offset+2 <= len(data) {
		extLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2
		if offset+extLen <= len(data) {
			ch.Extensions = make([]byte, extLen)
			copy(ch.Extensions, data[offset:offset+extLen])

			// Try to extract SNI
			ch.SNI = extractSNI(ch.Extensions)
			// Try to extract ALPN protocols
			ch.ALPNProtocols = extractALPN(ch.Extensions)
		}
	}

	return ch, nil
}

// ParseServerHello parses a ServerHello message
func ParseServerHello(data []byte) (*ServerHello, error) {
	if len(data) < 38 {
		return nil, fmt.Errorf("ServerHello too short")
	}

	sh := &ServerHello{
		Version: binary.BigEndian.Uint16(data[0:2]),
		Random:  make([]byte, 32),
	}
	copy(sh.Random, data[2:34])

	offset := 34

	// Session ID
	if offset >= len(data) {
		return nil, fmt.Errorf("ServerHello truncated at session ID length")
	}
	sessionIDLen := int(data[offset])
	offset++

	if offset+sessionIDLen > len(data) {
		return nil, fmt.Errorf("ServerHello truncated at session ID")
	}
	sh.SessionID = make([]byte, sessionIDLen)
	copy(sh.SessionID, data[offset:offset+sessionIDLen])
	offset += sessionIDLen

	// Cipher Suite
	if offset+2 > len(data) {
		return nil, fmt.Errorf("ServerHello truncated at cipher suite")
	}
	sh.CipherSuite = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	// Compression Method
	if offset >= len(data) {
		return nil, fmt.Errorf("ServerHello truncated at compression method")
	}
	sh.CompressionMethod = data[offset]
	offset++

	// Extensions (if present)
	if offset+2 <= len(data) {
		extLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2
		if offset+extLen <= len(data) {
			sh.Extensions = make([]byte, extLen)
			copy(sh.Extensions, data[offset:offset+extLen])
			// Try to extract selected ALPN protocol
			sh.ALPNProtocol = extractSelectedALPN(sh.Extensions)
		}
	}

	return sh, nil
}

// extractSNI extracts the Server Name Indication from extensions
func extractSNI(extensions []byte) string {
	offset := 0
	for offset+4 <= len(extensions) {
		extType := binary.BigEndian.Uint16(extensions[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(extensions[offset+2 : offset+4]))
		offset += 4

		if offset+extLen > len(extensions) {
			break
		}

		if extType == 0 { // SNI extension
			extData := extensions[offset : offset+extLen]
			if len(extData) >= 5 {
				// Skip list length (2 bytes) and name type (1 byte)
				nameLen := int(binary.BigEndian.Uint16(extData[3:5]))
				if 5+nameLen <= len(extData) {
					return string(extData[5 : 5+nameLen])
				}
			}
		}

		offset += extLen
	}
	return ""
}

// ALPN Extension type
const (
	ExtensionTypeALPN = 16
)

// extractALPN extracts ALPN protocols from ClientHello extensions
func extractALPN(extensions []byte) []string {
	offset := 0
	for offset+4 <= len(extensions) {
		extType := binary.BigEndian.Uint16(extensions[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(extensions[offset+2 : offset+4]))
		offset += 4

		if offset+extLen > len(extensions) {
			break
		}

		if extType == ExtensionTypeALPN { // ALPN extension
			extData := extensions[offset : offset+extLen]
			return parseALPNList(extData)
		}

		offset += extLen
	}
	return nil
}

// extractSelectedALPN extracts the selected ALPN protocol from ServerHello extensions
func extractSelectedALPN(extensions []byte) string {
	offset := 0
	for offset+4 <= len(extensions) {
		extType := binary.BigEndian.Uint16(extensions[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(extensions[offset+2 : offset+4]))
		offset += 4

		if offset+extLen > len(extensions) {
			break
		}

		if extType == ExtensionTypeALPN { // ALPN extension
			extData := extensions[offset : offset+extLen]
			protocols := parseALPNList(extData)
			if len(protocols) > 0 {
				return protocols[0] // Server selects exactly one protocol
			}
		}

		offset += extLen
	}
	return ""
}

// parseALPNList parses the ALPN protocol list from extension data
func parseALPNList(data []byte) []string {
	if len(data) < 2 {
		return nil
	}

	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if len(data) < 2+listLen {
		return nil
	}

	var protocols []string
	offset := 2
	for offset < 2+listLen {
		if offset >= len(data) {
			break
		}
		protoLen := int(data[offset])
		offset++
		if offset+protoLen > len(data) {
			break
		}
		protocols = append(protocols, string(data[offset:offset+protoLen]))
		offset += protoLen
	}
	return protocols
}

// IsHTTP2ALPN checks if the ALPN protocol indicates HTTP/2
func IsHTTP2ALPN(protocol string) bool {
	return protocol == "h2" || protocol == "h2c"
}

// IsTLSRecord checks if data looks like a TLS record
func IsTLSRecord(data []byte) bool {
	if len(data) < 5 {
		return false
	}

	contentType := data[0]
	version := binary.BigEndian.Uint16(data[1:3])

	// Check content type
	if contentType < 20 || contentType > 23 {
		return false
	}

	// Check version (SSL 3.0 to TLS 1.3)
	if version < 0x0300 || version > 0x0304 {
		// TLS 1.3 may use 0x0301 in record layer
		if version != 0x0301 {
			return false
		}
	}

	return true
}

// GetCipherSuiteName returns the name of a cipher suite
func GetCipherSuiteName(suite uint16) string {
	names := map[uint16]string{
		TLS_RSA_WITH_AES_128_CBC_SHA:            "TLS_RSA_WITH_AES_128_CBC_SHA",
		TLS_RSA_WITH_AES_256_CBC_SHA:            "TLS_RSA_WITH_AES_256_CBC_SHA",
		TLS_RSA_WITH_AES_128_CBC_SHA256:         "TLS_RSA_WITH_AES_128_CBC_SHA256",
		TLS_RSA_WITH_AES_256_CBC_SHA256:         "TLS_RSA_WITH_AES_256_CBC_SHA256",
		TLS_RSA_WITH_AES_128_GCM_SHA256:         "TLS_RSA_WITH_AES_128_GCM_SHA256",
		TLS_RSA_WITH_AES_256_GCM_SHA384:         "TLS_RSA_WITH_AES_256_GCM_SHA384",
		TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:   "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
		TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:   "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		TLS_AES_128_GCM_SHA256:                  "TLS_AES_128_GCM_SHA256",
		TLS_AES_256_GCM_SHA384:                  "TLS_AES_256_GCM_SHA384",
		TLS_CHACHA20_POLY1305_SHA256:            "TLS_CHACHA20_POLY1305_SHA256",
	}
	if name, ok := names[suite]; ok {
		return name
	}
	return fmt.Sprintf("Unknown (0x%04X)", suite)
}

// GetVersionName returns the name of a TLS version
func GetVersionName(version uint16) string {
	names := map[uint16]string{
		VersionSSL30: "SSL 3.0",
		VersionTLS10: "TLS 1.0",
		VersionTLS11: "TLS 1.1",
		VersionTLS12: "TLS 1.2",
		VersionTLS13: "TLS 1.3",
	}
	if name, ok := names[version]; ok {
		return name
	}
	return fmt.Sprintf("Unknown (0x%04X)", version)
}

// GetContentTypeName returns the name of a content type
func GetContentTypeName(ct uint8) string {
	names := map[uint8]string{
		ContentTypeChangeCipherSpec: "ChangeCipherSpec",
		ContentTypeAlert:            "Alert",
		ContentTypeHandshake:        "Handshake",
		ContentTypeApplicationData:  "ApplicationData",
	}
	if name, ok := names[ct]; ok {
		return name
	}
	return fmt.Sprintf("Unknown (%d)", ct)
}

// GetHandshakeTypeName returns the name of a handshake type
func GetHandshakeTypeName(ht uint8) string {
	names := map[uint8]string{
		HandshakeTypeClientHello:        "ClientHello",
		HandshakeTypeServerHello:        "ServerHello",
		HandshakeTypeCertificate:        "Certificate",
		HandshakeTypeServerKeyExchange:  "ServerKeyExchange",
		HandshakeTypeCertificateRequest: "CertificateRequest",
		HandshakeTypeServerHelloDone:    "ServerHelloDone",
		HandshakeTypeCertificateVerify:  "CertificateVerify",
		HandshakeTypeClientKeyExchange:  "ClientKeyExchange",
		HandshakeTypeFinished:           "Finished",
	}
	if name, ok := names[ht]; ok {
		return name
	}
	return fmt.Sprintf("Unknown (%d)", ht)
}
