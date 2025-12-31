package tls

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"sync"
)

// Session represents a TLS session with its state
type Session struct {
	ClientRandom []byte
	ServerRandom []byte
	CipherSuite  uint16
	Version      uint16
	Keys         *KeyMaterial

	// Sequence numbers for MAC calculation
	ClientSeqNum uint64
	ServerSeqNum uint64

	// State
	HandshakeComplete bool
	SNI               string
}

// Decryptor manages TLS session decryption
type Decryptor struct {
	mu       sync.RWMutex
	keyLog   *KeyLog
	sessions map[string]*Session // key: "srcIP:srcPort-dstIP:dstPort"
}

// NewDecryptor creates a new TLS decryptor
func NewDecryptor(keyLog *KeyLog) *Decryptor {
	return &Decryptor{
		keyLog:   keyLog,
		sessions: make(map[string]*Session),
	}
}

// SessionKey generates a session key from connection tuple
func SessionKey(srcIP, dstIP string, srcPort, dstPort uint16) string {
	// Normalize key so both directions map to same session
	if srcIP < dstIP || (srcIP == dstIP && srcPort < dstPort) {
		return fmt.Sprintf("%s:%d-%s:%d", srcIP, srcPort, dstIP, dstPort)
	}
	return fmt.Sprintf("%s:%d-%s:%d", dstIP, dstPort, srcIP, srcPort)
}

// ProcessHandshake processes a TLS handshake message
func (d *Decryptor) ProcessHandshake(sessionKey string, srcIP, dstIP string, srcPort, dstPort uint16, data []byte, isFromClient bool) {
	if !IsTLSRecord(data) {
		return
	}

	record, _, err := ParseTLSRecord(data)
	if err != nil || record.ContentType != ContentTypeHandshake {
		return
	}

	msg, _, err := ParseHandshakeMessage(record.Fragment)
	if err != nil {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	switch msg.Type {
	case HandshakeTypeClientHello:
		ch, err := ParseClientHello(msg.Data)
		if err != nil {
			return
		}

		session := &Session{
			ClientRandom: ch.Random,
			Version:      ch.Version,
			SNI:          ch.SNI,
		}
		d.sessions[sessionKey] = session

	case HandshakeTypeServerHello:
		session, ok := d.sessions[sessionKey]
		if !ok {
			return
		}

		sh, err := ParseServerHello(msg.Data)
		if err != nil {
			return
		}

		session.ServerRandom = sh.Random
		session.CipherSuite = sh.CipherSuite
		session.Version = sh.Version

		// Try to derive keys
		if d.keyLog != nil {
			masterSecret := d.keyLog.FindMasterSecret(session.ClientRandom)
			if masterSecret != nil {
				session.Keys = DeriveKeys(masterSecret, session.ClientRandom, session.ServerRandom, session.CipherSuite)
				session.HandshakeComplete = true
			}
		}
	}
}

// DecryptApplicationData decrypts TLS application data
func (d *Decryptor) DecryptApplicationData(sessionKey string, data []byte, isFromClient bool) ([]byte, error) {
	if !IsTLSRecord(data) {
		return nil, fmt.Errorf("not a TLS record")
	}

	record, _, err := ParseTLSRecord(data)
	if err != nil {
		return nil, err
	}

	if record.ContentType != ContentTypeApplicationData {
		return nil, fmt.Errorf("not application data")
	}

	d.mu.RLock()
	session, ok := d.sessions[sessionKey]
	d.mu.RUnlock()

	if !ok || session.Keys == nil {
		return nil, fmt.Errorf("no session keys available")
	}

	info := GetCipherSuiteInfo(session.CipherSuite)
	if info == nil {
		return nil, fmt.Errorf("unsupported cipher suite: 0x%04X", session.CipherSuite)
	}

	var plaintext []byte
	if info.IsAEAD {
		plaintext, err = d.decryptGCM(session, record.Fragment, isFromClient)
	} else {
		plaintext, err = d.decryptCBC(session, record.Fragment, isFromClient)
	}

	if err != nil {
		return nil, err
	}

	// Update sequence number
	d.mu.Lock()
	if isFromClient {
		session.ClientSeqNum++
	} else {
		session.ServerSeqNum++
	}
	d.mu.Unlock()

	return plaintext, nil
}

// decryptGCM decrypts AES-GCM encrypted data
func (d *Decryptor) decryptGCM(session *Session, ciphertext []byte, isFromClient bool) ([]byte, error) {
	var key, implicitIV []byte
	var seqNum uint64

	if isFromClient {
		key = session.Keys.ClientWriteKey
		implicitIV = session.Keys.ClientWriteIV
		seqNum = session.ClientSeqNum
	} else {
		key = session.Keys.ServerWriteKey
		implicitIV = session.Keys.ServerWriteIV
		seqNum = session.ServerSeqNum
	}

	if len(ciphertext) < 8+16 { // explicit nonce + tag
		return nil, fmt.Errorf("ciphertext too short for GCM")
	}

	// TLS 1.2 GCM: nonce = implicit_iv (4 bytes) + explicit_nonce (8 bytes)
	explicitNonce := ciphertext[:8]
	nonce := make([]byte, 12)
	copy(nonce[:4], implicitIV)
	copy(nonce[4:], explicitNonce)

	// Encrypted data is after explicit nonce, includes 16-byte tag at end
	encrypted := ciphertext[8:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Additional data: seq_num (8) + type (1) + version (2) + length (2)
	additionalData := make([]byte, 13)
	binary.BigEndian.PutUint64(additionalData[:8], seqNum)
	additionalData[8] = ContentTypeApplicationData
	binary.BigEndian.PutUint16(additionalData[9:11], session.Version)
	binary.BigEndian.PutUint16(additionalData[11:13], uint16(len(encrypted)-16))

	plaintext, err := aead.Open(nil, nonce, encrypted, additionalData)
	if err != nil {
		return nil, fmt.Errorf("GCM decryption failed: %w", err)
	}

	return plaintext, nil
}

// decryptCBC decrypts AES-CBC encrypted data
func (d *Decryptor) decryptCBC(session *Session, ciphertext []byte, isFromClient bool) ([]byte, error) {
	var key, macKey []byte
	info := GetCipherSuiteInfo(session.CipherSuite)
	if info == nil {
		return nil, fmt.Errorf("unsupported cipher suite")
	}

	if isFromClient {
		key = session.Keys.ClientWriteKey
		macKey = session.Keys.ClientMACKey
	} else {
		key = session.Keys.ServerWriteKey
		macKey = session.Keys.ServerMACKey
	}

	// TLS 1.1+ uses explicit IV
	if len(ciphertext) < info.BlockSize {
		return nil, fmt.Errorf("ciphertext too short for CBC")
	}

	iv := ciphertext[:info.BlockSize]
	encrypted := ciphertext[info.BlockSize:]

	if len(encrypted)%info.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext not aligned to block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(encrypted))
	mode.CryptBlocks(plaintext, encrypted)

	// Remove padding
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("empty plaintext")
	}
	padLen := int(plaintext[len(plaintext)-1]) + 1
	if padLen > len(plaintext) || padLen > info.BlockSize {
		return nil, fmt.Errorf("invalid padding")
	}
	plaintext = plaintext[:len(plaintext)-padLen]

	// Remove MAC
	if len(plaintext) < info.MACLen {
		return nil, fmt.Errorf("plaintext too short for MAC")
	}
	plaintext = plaintext[:len(plaintext)-info.MACLen]

	// MAC key is used but verification is skipped for simplicity
	_ = macKey

	return plaintext, nil
}

// GetSession returns the session for a connection
func (d *Decryptor) GetSession(sessionKey string) *Session {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.sessions[sessionKey]
}

// HasKeys checks if we have keys for a session
func (d *Decryptor) HasKeys(sessionKey string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	session, ok := d.sessions[sessionKey]
	return ok && session.Keys != nil
}

// GetSNI returns the SNI for a session
func (d *Decryptor) GetSNI(sessionKey string) string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if session, ok := d.sessions[sessionKey]; ok {
		return session.SNI
	}
	return ""
}

// SessionCount returns the number of tracked sessions
func (d *Decryptor) SessionCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.sessions)
}

// DecryptedSessionCount returns the number of sessions with keys
func (d *Decryptor) DecryptedSessionCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	count := 0
	for _, session := range d.sessions {
		if session.Keys != nil {
			count++
		}
	}
	return count
}
