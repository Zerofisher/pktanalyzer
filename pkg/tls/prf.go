package tls

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

// KeyMaterial holds the derived key material for a TLS session
type KeyMaterial struct {
	ClientWriteKey []byte
	ServerWriteKey []byte
	ClientWriteIV  []byte
	ServerWriteIV  []byte
	ClientMACKey   []byte // For CBC mode
	ServerMACKey   []byte // For CBC mode
}

// CipherSuiteInfo contains information about a cipher suite
type CipherSuiteInfo struct {
	KeyLen    int
	IVLen     int
	MACLen    int
	IsAEAD    bool
	HashFunc  func() hash.Hash
	BlockSize int
}

// GetCipherSuiteInfo returns information about a cipher suite
func GetCipherSuiteInfo(suite uint16) *CipherSuiteInfo {
	switch suite {
	case TLS_RSA_WITH_AES_128_CBC_SHA,
		TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
		return &CipherSuiteInfo{
			KeyLen:    16,
			IVLen:     16,
			MACLen:    20,
			IsAEAD:    false,
			HashFunc:  sha256.New,
			BlockSize: 16,
		}
	case TLS_RSA_WITH_AES_256_CBC_SHA,
		TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		return &CipherSuiteInfo{
			KeyLen:    32,
			IVLen:     16,
			MACLen:    20,
			IsAEAD:    false,
			HashFunc:  sha256.New,
			BlockSize: 16,
		}
	case TLS_RSA_WITH_AES_128_CBC_SHA256,
		TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
		return &CipherSuiteInfo{
			KeyLen:    16,
			IVLen:     16,
			MACLen:    32,
			IsAEAD:    false,
			HashFunc:  sha256.New,
			BlockSize: 16,
		}
	case TLS_RSA_WITH_AES_256_CBC_SHA256,
		TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
		return &CipherSuiteInfo{
			KeyLen:    32,
			IVLen:     16,
			MACLen:    32,
			IsAEAD:    false,
			HashFunc:  sha256.New,
			BlockSize: 16,
		}
	case TLS_RSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		TLS_AES_128_GCM_SHA256:
		return &CipherSuiteInfo{
			KeyLen:    16,
			IVLen:     4, // Implicit IV for GCM
			MACLen:    0,
			IsAEAD:    true,
			HashFunc:  sha256.New,
			BlockSize: 16,
		}
	case TLS_RSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		TLS_AES_256_GCM_SHA384:
		return &CipherSuiteInfo{
			KeyLen:    32,
			IVLen:     4, // Implicit IV for GCM
			MACLen:    0,
			IsAEAD:    true,
			HashFunc:  sha512.New384,
			BlockSize: 16,
		}
	default:
		return nil
	}
}

// PRF12 implements TLS 1.2 PRF using SHA-256
func PRF12(secret, label, seed []byte, length int) []byte {
	return pHash(sha256.New, secret, append(label, seed...), length)
}

// pHash implements P_hash from RFC 5246
func pHash(hashFunc func() hash.Hash, secret, seed []byte, length int) []byte {
	result := make([]byte, 0, length)
	mac := hmac.New(hashFunc, secret)

	// A(1) = HMAC_hash(secret, seed)
	mac.Write(seed)
	a := mac.Sum(nil)

	for len(result) < length {
		mac.Reset()
		mac.Write(a)
		mac.Write(seed)
		result = append(result, mac.Sum(nil)...)

		// A(i+1) = HMAC_hash(secret, A(i))
		mac.Reset()
		mac.Write(a)
		a = mac.Sum(nil)
	}

	return result[:length]
}

// DeriveKeys derives key material from master secret for TLS 1.2
func DeriveKeys(masterSecret, clientRandom, serverRandom []byte, suite uint16) *KeyMaterial {
	info := GetCipherSuiteInfo(suite)
	if info == nil {
		return nil
	}

	// key_block = PRF(master_secret, "key expansion", server_random + client_random)
	seed := make([]byte, 0, len(serverRandom)+len(clientRandom))
	seed = append(seed, serverRandom...)
	seed = append(seed, clientRandom...)
	keyBlockLen := 2*info.MACLen + 2*info.KeyLen + 2*info.IVLen
	keyBlock := PRF12(masterSecret, []byte("key expansion"), seed, keyBlockLen)

	km := &KeyMaterial{}
	offset := 0

	// Extract MAC keys (for CBC mode)
	if info.MACLen > 0 {
		km.ClientMACKey = make([]byte, info.MACLen)
		copy(km.ClientMACKey, keyBlock[offset:offset+info.MACLen])
		offset += info.MACLen

		km.ServerMACKey = make([]byte, info.MACLen)
		copy(km.ServerMACKey, keyBlock[offset:offset+info.MACLen])
		offset += info.MACLen
	}

	// Extract encryption keys
	km.ClientWriteKey = make([]byte, info.KeyLen)
	copy(km.ClientWriteKey, keyBlock[offset:offset+info.KeyLen])
	offset += info.KeyLen

	km.ServerWriteKey = make([]byte, info.KeyLen)
	copy(km.ServerWriteKey, keyBlock[offset:offset+info.KeyLen])
	offset += info.KeyLen

	// Extract IVs
	km.ClientWriteIV = make([]byte, info.IVLen)
	copy(km.ClientWriteIV, keyBlock[offset:offset+info.IVLen])
	offset += info.IVLen

	km.ServerWriteIV = make([]byte, info.IVLen)
	copy(km.ServerWriteIV, keyBlock[offset:offset+info.IVLen])

	return km
}

// HKDFExpandLabel implements HKDF-Expand-Label for TLS 1.3
func HKDFExpandLabel(secret []byte, label string, context []byte, length int, hashFunc func() hash.Hash) []byte {
	// HKDF-Expand-Label(Secret, Label, Context, Length) =
	//     HKDF-Expand(Secret, HkdfLabel, Length)
	//
	// struct {
	//     uint16 length = Length;
	//     opaque label<7..255> = "tls13 " + Label;
	//     opaque context<0..255> = Context;
	// } HkdfLabel;

	fullLabel := append([]byte("tls13 "), []byte(label)...)

	hkdfLabel := make([]byte, 0, 2+1+len(fullLabel)+1+len(context))
	hkdfLabel = append(hkdfLabel, byte(length>>8), byte(length))
	hkdfLabel = append(hkdfLabel, byte(len(fullLabel)))
	hkdfLabel = append(hkdfLabel, fullLabel...)
	hkdfLabel = append(hkdfLabel, byte(len(context)))
	hkdfLabel = append(hkdfLabel, context...)

	return hkdfExpand(secret, hkdfLabel, length, hashFunc)
}

// hkdfExpand implements HKDF-Expand from RFC 5869
func hkdfExpand(prk, info []byte, length int, hashFunc func() hash.Hash) []byte {
	mac := hmac.New(hashFunc, prk)
	hashLen := mac.Size()

	n := (length + hashLen - 1) / hashLen
	result := make([]byte, 0, n*hashLen)

	var prev []byte
	for i := 1; i <= n; i++ {
		mac.Reset()
		mac.Write(prev)
		mac.Write(info)
		mac.Write([]byte{byte(i)})
		prev = mac.Sum(nil)
		result = append(result, prev...)
	}

	return result[:length]
}

// DeriveKeysTLS13 derives key material from traffic secret for TLS 1.3
func DeriveKeysTLS13(trafficSecret []byte, suite uint16) *KeyMaterial {
	info := GetCipherSuiteInfo(suite)
	if info == nil {
		return nil
	}

	km := &KeyMaterial{}
	hashFunc := info.HashFunc

	// key = HKDF-Expand-Label(Secret, "key", "", key_length)
	km.ClientWriteKey = HKDFExpandLabel(trafficSecret, "key", nil, info.KeyLen, hashFunc)
	km.ServerWriteKey = HKDFExpandLabel(trafficSecret, "key", nil, info.KeyLen, hashFunc)

	// iv = HKDF-Expand-Label(Secret, "iv", "", iv_length)
	km.ClientWriteIV = HKDFExpandLabel(trafficSecret, "iv", nil, 12, hashFunc) // TLS 1.3 uses 12-byte IV
	km.ServerWriteIV = HKDFExpandLabel(trafficSecret, "iv", nil, 12, hashFunc)

	return km
}
