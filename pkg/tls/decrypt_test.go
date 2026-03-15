package tls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

// buildCBCRecord constructs a valid TLS 1.2 CBC record (IV || encrypt(plaintext || MAC || padding)).
// cipher suite: TLS_RSA_WITH_AES_128_CBC_SHA (0x002F), MACLen=20, KeyLen=16, IV=16, hash=SHA-256.
func buildCBCRecord(t *testing.T, plaintext []byte, key, macKey []byte, seqNum uint64, version uint16) []byte {
	t.Helper()

	// 1. Compute HMAC-SHA-256 (TLS 1.2 style) over seq_num || type || version || length || plaintext
	// RFC 5246 §6.2.3.1: MAC(MAC_write_key, seq_num + TLSCompressed.type +
	//     TLSCompressed.version + TLSCompressed.length + TLSCompressed.fragment)
	macBuf := make([]byte, 8+1+2+2+len(plaintext))
	binary.BigEndian.PutUint64(macBuf[:8], seqNum)
	macBuf[8] = ContentTypeApplicationData
	binary.BigEndian.PutUint16(macBuf[9:11], version)
	binary.BigEndian.PutUint16(macBuf[11:13], uint16(len(plaintext)))
	copy(macBuf[13:], plaintext)

	h := hmac.New(sha256.New, macKey)
	h.Write(macBuf)
	mac := h.Sum(nil)
	mac = mac[:20] // TLS_RSA_WITH_AES_128_CBC_SHA uses 20-byte MAC

	// 2. payload = plaintext || MAC
	payload := append(plaintext, mac...)

	// 3. Add PKCS#7/TLS padding so total length is multiple of 16
	blockSize := 16
	padLen := blockSize - (len(payload)+1)%blockSize // +1 for the pad-length byte itself
	if padLen < 0 {
		padLen += blockSize
	}
	padByte := byte(padLen)
	for i := 0; i <= padLen; i++ {
		payload = append(payload, padByte)
	}

	// 4. Generate random IV and encrypt
	iv := make([]byte, blockSize)
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	cbc := cipher.NewCBCEncrypter(block, iv)
	encrypted := make([]byte, len(payload))
	cbc.CryptBlocks(encrypted, payload)

	// Record fragment = IV || encrypted
	return append(iv, encrypted...)
}

func TestDecryptCBC_TamperedCiphertext(t *testing.T) {
	// Setup: create a session with CBC cipher suite and known keys
	key := make([]byte, 16)
	macKey := make([]byte, 20)
	iv := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(macKey); err != nil {
		t.Fatal(err)
	}

	session := &Session{
		CipherSuite: TLS_RSA_WITH_AES_128_CBC_SHA,
		Version:     VersionTLS12,
		Keys: &KeyMaterial{
			ServerWriteKey: key,
			ServerMACKey:   macKey,
			ServerWriteIV:  iv,
		},
	}

	d := &Decryptor{
		sessions: map[string]*Session{"test": session},
	}

	originalPlaintext := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	fragment := buildCBCRecord(t, originalPlaintext, key, macKey, 0, VersionTLS12)

	// ---- Test 1: untampered record should decrypt correctly ----
	result, err := d.decryptCBC(session, fragment, false)
	if err != nil {
		t.Fatalf("untampered record failed: %v", err)
	}
	if string(result) != string(originalPlaintext) {
		t.Fatalf("untampered plaintext mismatch: got %q, want %q", result, originalPlaintext)
	}

	// ---- Test 2: tamper the ciphertext and observe the bug ----
	// Flip a byte in the encrypted portion (after the IV).
	// With proper MAC verification this MUST return an error.
	tampered := make([]byte, len(fragment))
	copy(tampered, fragment)
	// Tamper a byte in the second-to-last block to avoid disturbing padding
	tamperedIdx := len(tampered) - 32 - 1 // well inside the encrypted region
	if tamperedIdx < 16 {
		tamperedIdx = 17 // at minimum, right after IV
	}
	tampered[tamperedIdx] ^= 0xFF

	result2, err2 := d.decryptCBC(session, tampered, false)

	// BUG: the current code returns NO error for tampered ciphertext
	// because MAC verification is skipped (macKey is discarded with _ = macKey).
	// A correct implementation MUST return an error here.
	if err2 == nil {
		t.Errorf("BUG REPRODUCED: decryptCBC accepted tampered ciphertext without error, "+
			"returned %d bytes of forged plaintext: %q", len(result2), result2)
	} else {
		t.Logf("PASS: tampered ciphertext correctly rejected: %v", err2)
	}
}

func TestDecryptCBC_WrongMACKey(t *testing.T) {
	// Even with a completely wrong MAC key, decryption should fail
	// if MAC is verified. Without verification, it silently succeeds.
	key := make([]byte, 16)
	realMACKey := make([]byte, 20)
	wrongMACKey := make([]byte, 20)
	iv := make([]byte, 16)
	rand.Read(key)
	rand.Read(realMACKey)
	rand.Read(wrongMACKey)

	plaintext := []byte("secret data")
	fragment := buildCBCRecord(t, plaintext, key, realMACKey, 0, VersionTLS12)

	// Create session with the WRONG MAC key
	session := &Session{
		CipherSuite: TLS_RSA_WITH_AES_128_CBC_SHA,
		Version:     VersionTLS12,
		Keys: &KeyMaterial{
			ServerWriteKey: key,
			ServerMACKey:   wrongMACKey,
			ServerWriteIV:  iv,
		},
	}

	d := &Decryptor{
		sessions: map[string]*Session{"test": session},
	}

	result, err := d.decryptCBC(session, fragment, false)
	if err == nil {
		t.Errorf("BUG REPRODUCED: decryptCBC accepted data with wrong MAC key, "+
			"returned plaintext: %q", result)
	} else {
		t.Logf("PASS: wrong MAC key correctly rejected: %v", err)
	}
}
