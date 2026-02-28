package tls

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

// ---------------------------------------------------------------------------
// GetCipherSuiteInfo
// ---------------------------------------------------------------------------

func TestGetCipherSuiteInfo_CBC(t *testing.T) {
	tests := []struct {
		name   string
		suite  uint16
		keyLen int
		ivLen  int
		macLen int
		isAEAD bool
	}{
		{
			name:   "AES-128-CBC-SHA",
			suite:  TLS_RSA_WITH_AES_128_CBC_SHA,
			keyLen: 16,
			ivLen:  16,
			macLen: 20,
			isAEAD: false,
		},
		{
			name:   "AES-256-CBC-SHA",
			suite:  TLS_RSA_WITH_AES_256_CBC_SHA,
			keyLen: 32,
			ivLen:  16,
			macLen: 20,
			isAEAD: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := GetCipherSuiteInfo(tt.suite)
			if info == nil {
				t.Fatal("expected non-nil CipherSuiteInfo")
			}
			if info.KeyLen != tt.keyLen {
				t.Errorf("KeyLen = %d, want %d", info.KeyLen, tt.keyLen)
			}
			if info.IVLen != tt.ivLen {
				t.Errorf("IVLen = %d, want %d", info.IVLen, tt.ivLen)
			}
			if info.MACLen != tt.macLen {
				t.Errorf("MACLen = %d, want %d", info.MACLen, tt.macLen)
			}
			if info.IsAEAD != tt.isAEAD {
				t.Errorf("IsAEAD = %v, want %v", info.IsAEAD, tt.isAEAD)
			}
			if info.BlockSize != 16 {
				t.Errorf("BlockSize = %d, want 16", info.BlockSize)
			}
			if info.HashFunc == nil {
				t.Error("HashFunc must not be nil")
			}
		})
	}
}

func TestGetCipherSuiteInfo_GCM(t *testing.T) {
	tests := []struct {
		name   string
		suite  uint16
		keyLen int
		ivLen  int
	}{
		{
			name:   "AES-128-GCM-SHA256",
			suite:  TLS_RSA_WITH_AES_128_GCM_SHA256,
			keyLen: 16,
			ivLen:  4,
		},
		{
			name:   "AES-256-GCM-SHA384",
			suite:  TLS_RSA_WITH_AES_256_GCM_SHA384,
			keyLen: 32,
			ivLen:  4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := GetCipherSuiteInfo(tt.suite)
			if info == nil {
				t.Fatal("expected non-nil CipherSuiteInfo")
			}
			if info.KeyLen != tt.keyLen {
				t.Errorf("KeyLen = %d, want %d", info.KeyLen, tt.keyLen)
			}
			if info.IVLen != tt.ivLen {
				t.Errorf("IVLen = %d, want %d", info.IVLen, tt.ivLen)
			}
			if info.MACLen != 0 {
				t.Errorf("MACLen = %d, want 0 for AEAD", info.MACLen)
			}
			if !info.IsAEAD {
				t.Error("IsAEAD must be true for GCM suites")
			}
			if info.HashFunc == nil {
				t.Error("HashFunc must not be nil")
			}
		})
	}
}

func TestGetCipherSuiteInfo_TLS13(t *testing.T) {
	tests := []struct {
		name   string
		suite  uint16
		keyLen int
	}{
		{
			name:   "TLS13-AES-128-GCM-SHA256",
			suite:  TLS_AES_128_GCM_SHA256,
			keyLen: 16,
		},
		{
			name:   "TLS13-AES-256-GCM-SHA384",
			suite:  TLS_AES_256_GCM_SHA384,
			keyLen: 32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := GetCipherSuiteInfo(tt.suite)
			if info == nil {
				t.Fatal("expected non-nil CipherSuiteInfo")
			}
			if info.KeyLen != tt.keyLen {
				t.Errorf("KeyLen = %d, want %d", info.KeyLen, tt.keyLen)
			}
			if info.IVLen != 4 {
				t.Errorf("IVLen = %d, want 4", info.IVLen)
			}
			if !info.IsAEAD {
				t.Error("IsAEAD must be true for TLS 1.3 suites")
			}
			if info.MACLen != 0 {
				t.Errorf("MACLen = %d, want 0 for TLS 1.3 AEAD", info.MACLen)
			}
		})
	}
}

func TestGetCipherSuiteInfo_Unknown(t *testing.T) {
	unknownSuites := []uint16{0x0000, 0xFFFF, 0x1234, 0xCAFE}
	for _, suite := range unknownSuites {
		info := GetCipherSuiteInfo(suite)
		if info != nil {
			t.Errorf("GetCipherSuiteInfo(0x%04X) = %+v, want nil", suite, info)
		}
	}
}

// ---------------------------------------------------------------------------
// PRF12
// ---------------------------------------------------------------------------

func TestPRF12(t *testing.T) {
	secret := []byte("master secret value for test")
	label := []byte("key expansion")
	seed := make([]byte, 64) // simulated client_random + server_random
	for i := range seed {
		seed[i] = byte(i)
	}

	t.Run("correct length", func(t *testing.T) {
		for _, length := range []int{0, 1, 16, 32, 48, 72, 128, 256} {
			out := PRF12(secret, label, seed, length)
			if len(out) != length {
				t.Errorf("PRF12 length %d: got %d bytes", length, len(out))
			}
		}
	})

	t.Run("deterministic", func(t *testing.T) {
		length := 48
		out1 := PRF12(secret, label, seed, length)
		out2 := PRF12(secret, label, seed, length)
		if !bytes.Equal(out1, out2) {
			t.Error("PRF12 produced different outputs for identical inputs")
		}
	})

	t.Run("different secrets produce different output", func(t *testing.T) {
		secret2 := []byte("different secret value for test!")
		length := 48
		out1 := PRF12(secret, label, seed, length)
		out2 := PRF12(secret2, label, seed, length)
		if bytes.Equal(out1, out2) {
			t.Error("PRF12 produced identical output for different secrets")
		}
	})

	t.Run("different labels produce different output", func(t *testing.T) {
		label2 := []byte("client finished")
		length := 48
		out1 := PRF12(secret, label, seed, length)
		out2 := PRF12(secret, label2, seed, length)
		if bytes.Equal(out1, out2) {
			t.Error("PRF12 produced identical output for different labels")
		}
	})

	t.Run("output is not all zeros", func(t *testing.T) {
		out := PRF12(secret, label, seed, 48)
		allZero := true
		for _, b := range out {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			t.Error("PRF12 output is all zeros")
		}
	})
}

// ---------------------------------------------------------------------------
// DeriveKeys (TLS 1.2)
// ---------------------------------------------------------------------------

func TestDeriveKeys_CBC(t *testing.T) {
	masterSecret := make([]byte, 48)
	clientRandom := make([]byte, 32)
	serverRandom := make([]byte, 32)
	for i := range masterSecret {
		masterSecret[i] = byte(i)
	}
	for i := range clientRandom {
		clientRandom[i] = byte(i + 100)
	}
	for i := range serverRandom {
		serverRandom[i] = byte(i + 200)
	}

	suite := uint16(TLS_RSA_WITH_AES_128_CBC_SHA)
	info := GetCipherSuiteInfo(suite)
	if info == nil {
		t.Fatal("CipherSuiteInfo must not be nil for CBC suite")
	}

	km := DeriveKeys(masterSecret, clientRandom, serverRandom, suite)
	if km == nil {
		t.Fatal("DeriveKeys returned nil for valid CBC suite")
	}

	// Verify key lengths match CipherSuiteInfo
	if len(km.ClientWriteKey) != info.KeyLen {
		t.Errorf("ClientWriteKey length = %d, want %d", len(km.ClientWriteKey), info.KeyLen)
	}
	if len(km.ServerWriteKey) != info.KeyLen {
		t.Errorf("ServerWriteKey length = %d, want %d", len(km.ServerWriteKey), info.KeyLen)
	}
	if len(km.ClientWriteIV) != info.IVLen {
		t.Errorf("ClientWriteIV length = %d, want %d", len(km.ClientWriteIV), info.IVLen)
	}
	if len(km.ServerWriteIV) != info.IVLen {
		t.Errorf("ServerWriteIV length = %d, want %d", len(km.ServerWriteIV), info.IVLen)
	}

	// CBC suites must have MAC keys
	if len(km.ClientMACKey) != info.MACLen {
		t.Errorf("ClientMACKey length = %d, want %d", len(km.ClientMACKey), info.MACLen)
	}
	if len(km.ServerMACKey) != info.MACLen {
		t.Errorf("ServerMACKey length = %d, want %d", len(km.ServerMACKey), info.MACLen)
	}

	// Client and server keys must differ (key block is split sequentially)
	if bytes.Equal(km.ClientWriteKey, km.ServerWriteKey) {
		t.Error("ClientWriteKey and ServerWriteKey must not be equal")
	}
	if bytes.Equal(km.ClientMACKey, km.ServerMACKey) {
		t.Error("ClientMACKey and ServerMACKey must not be equal")
	}

	// Deterministic: same inputs produce same outputs
	km2 := DeriveKeys(masterSecret, clientRandom, serverRandom, suite)
	if !bytes.Equal(km.ClientWriteKey, km2.ClientWriteKey) {
		t.Error("DeriveKeys is not deterministic for ClientWriteKey")
	}
	if !bytes.Equal(km.ServerWriteKey, km2.ServerWriteKey) {
		t.Error("DeriveKeys is not deterministic for ServerWriteKey")
	}
}

func TestDeriveKeys_GCM(t *testing.T) {
	masterSecret := make([]byte, 48)
	clientRandom := make([]byte, 32)
	serverRandom := make([]byte, 32)
	for i := range masterSecret {
		masterSecret[i] = byte(i * 3)
	}
	for i := range clientRandom {
		clientRandom[i] = byte(i + 50)
	}
	for i := range serverRandom {
		serverRandom[i] = byte(i + 150)
	}

	suite := uint16(TLS_RSA_WITH_AES_128_GCM_SHA256)
	info := GetCipherSuiteInfo(suite)
	if info == nil {
		t.Fatal("CipherSuiteInfo must not be nil for GCM suite")
	}

	km := DeriveKeys(masterSecret, clientRandom, serverRandom, suite)
	if km == nil {
		t.Fatal("DeriveKeys returned nil for valid GCM suite")
	}

	// Verify key lengths
	if len(km.ClientWriteKey) != info.KeyLen {
		t.Errorf("ClientWriteKey length = %d, want %d", len(km.ClientWriteKey), info.KeyLen)
	}
	if len(km.ServerWriteKey) != info.KeyLen {
		t.Errorf("ServerWriteKey length = %d, want %d", len(km.ServerWriteKey), info.KeyLen)
	}
	if len(km.ClientWriteIV) != info.IVLen {
		t.Errorf("ClientWriteIV length = %d, want %d", len(km.ClientWriteIV), info.IVLen)
	}
	if len(km.ServerWriteIV) != info.IVLen {
		t.Errorf("ServerWriteIV length = %d, want %d", len(km.ServerWriteIV), info.IVLen)
	}

	// GCM (AEAD) suites must NOT have MAC keys
	if len(km.ClientMACKey) != 0 {
		t.Errorf("ClientMACKey length = %d, want 0 for GCM", len(km.ClientMACKey))
	}
	if len(km.ServerMACKey) != 0 {
		t.Errorf("ServerMACKey length = %d, want 0 for GCM", len(km.ServerMACKey))
	}
}

func TestDeriveKeys_UnknownSuite(t *testing.T) {
	masterSecret := make([]byte, 48)
	clientRandom := make([]byte, 32)
	serverRandom := make([]byte, 32)

	km := DeriveKeys(masterSecret, clientRandom, serverRandom, 0xFFFF)
	if km != nil {
		t.Errorf("DeriveKeys returned %+v for unknown suite, want nil", km)
	}
}

// ---------------------------------------------------------------------------
// HKDFExpandLabel (TLS 1.3)
// ---------------------------------------------------------------------------

func TestHKDFExpandLabel(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	context := []byte{}

	t.Run("correct length", func(t *testing.T) {
		for _, length := range []int{1, 12, 16, 32, 48} {
			out := HKDFExpandLabel(secret, "key", context, length, sha256.New)
			if len(out) != length {
				t.Errorf("HKDFExpandLabel length %d: got %d bytes", length, len(out))
			}
		}
	})

	t.Run("deterministic", func(t *testing.T) {
		out1 := HKDFExpandLabel(secret, "key", context, 16, sha256.New)
		out2 := HKDFExpandLabel(secret, "key", context, 16, sha256.New)
		if !bytes.Equal(out1, out2) {
			t.Error("HKDFExpandLabel produced different outputs for identical inputs")
		}
	})

	t.Run("different labels produce different output", func(t *testing.T) {
		out1 := HKDFExpandLabel(secret, "key", context, 16, sha256.New)
		out2 := HKDFExpandLabel(secret, "iv", context, 16, sha256.New)
		if bytes.Equal(out1, out2) {
			t.Error("HKDFExpandLabel produced identical output for different labels")
		}
	})

	t.Run("different secrets produce different output", func(t *testing.T) {
		secret2 := make([]byte, 32)
		for i := range secret2 {
			secret2[i] = byte(i + 128)
		}
		out1 := HKDFExpandLabel(secret, "key", context, 16, sha256.New)
		out2 := HKDFExpandLabel(secret2, "key", context, 16, sha256.New)
		if bytes.Equal(out1, out2) {
			t.Error("HKDFExpandLabel produced identical output for different secrets")
		}
	})

	t.Run("output is not all zeros", func(t *testing.T) {
		out := HKDFExpandLabel(secret, "key", context, 32, sha256.New)
		allZero := true
		for _, b := range out {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			t.Error("HKDFExpandLabel output is all zeros")
		}
	})
}

// ---------------------------------------------------------------------------
// DeriveKeysTLS13
// ---------------------------------------------------------------------------

func TestDeriveKeysTLS13(t *testing.T) {
	trafficSecret := make([]byte, 32)
	for i := range trafficSecret {
		trafficSecret[i] = byte(i * 7)
	}

	tests := []struct {
		name   string
		suite  uint16
		keyLen int
	}{
		{
			name:   "AES-128-GCM-SHA256",
			suite:  TLS_AES_128_GCM_SHA256,
			keyLen: 16,
		},
		{
			name:   "AES-256-GCM-SHA384",
			suite:  TLS_AES_256_GCM_SHA384,
			keyLen: 32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			km := DeriveKeysTLS13(trafficSecret, tt.suite)
			if km == nil {
				t.Fatal("DeriveKeysTLS13 returned nil for valid TLS 1.3 suite")
			}

			// Key lengths must match CipherSuiteInfo.KeyLen
			if len(km.ClientWriteKey) != tt.keyLen {
				t.Errorf("ClientWriteKey length = %d, want %d", len(km.ClientWriteKey), tt.keyLen)
			}
			if len(km.ServerWriteKey) != tt.keyLen {
				t.Errorf("ServerWriteKey length = %d, want %d", len(km.ServerWriteKey), tt.keyLen)
			}

			// TLS 1.3 always uses 12-byte IV regardless of CipherSuiteInfo.IVLen
			if len(km.ClientWriteIV) != 12 {
				t.Errorf("ClientWriteIV length = %d, want 12", len(km.ClientWriteIV))
			}
			if len(km.ServerWriteIV) != 12 {
				t.Errorf("ServerWriteIV length = %d, want 12", len(km.ServerWriteIV))
			}

			// TLS 1.3 is AEAD-only: no MAC keys
			if len(km.ClientMACKey) != 0 {
				t.Errorf("ClientMACKey length = %d, want 0", len(km.ClientMACKey))
			}
			if len(km.ServerMACKey) != 0 {
				t.Errorf("ServerMACKey length = %d, want 0", len(km.ServerMACKey))
			}

			// In TLS 1.3, same traffic secret produces identical client/server keys
			// because DeriveKeysTLS13 uses the same secret for both directions
			if !bytes.Equal(km.ClientWriteKey, km.ServerWriteKey) {
				t.Error("client and server write keys should be equal when derived from the same traffic secret")
			}
			if !bytes.Equal(km.ClientWriteIV, km.ServerWriteIV) {
				t.Error("client and server write IVs should be equal when derived from the same traffic secret")
			}

			// Deterministic
			km2 := DeriveKeysTLS13(trafficSecret, tt.suite)
			if !bytes.Equal(km.ClientWriteKey, km2.ClientWriteKey) {
				t.Error("DeriveKeysTLS13 is not deterministic for ClientWriteKey")
			}
			if !bytes.Equal(km.ClientWriteIV, km2.ClientWriteIV) {
				t.Error("DeriveKeysTLS13 is not deterministic for ClientWriteIV")
			}
		})
	}
}

func TestDeriveKeysTLS13_UnknownSuite(t *testing.T) {
	trafficSecret := make([]byte, 32)

	unknownSuites := []uint16{0x0000, 0xFFFF, 0xDEAD}
	for _, suite := range unknownSuites {
		km := DeriveKeysTLS13(trafficSecret, suite)
		if km != nil {
			t.Errorf("DeriveKeysTLS13(0x%04X) = %+v, want nil", suite, km)
		}
	}
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkPRF12(b *testing.B) {
	secret := make([]byte, 48)
	label := []byte("key expansion")
	seed := make([]byte, 64)
	for i := range secret {
		secret[i] = byte(i)
	}
	for i := range seed {
		seed[i] = byte(i)
	}
	length := 72 // typical key block: 2*20 + 2*16 = 72 for CBC-SHA

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		PRF12(secret, label, seed, length)
	}
}

func BenchmarkDeriveKeys(b *testing.B) {
	masterSecret := make([]byte, 48)
	clientRandom := make([]byte, 32)
	serverRandom := make([]byte, 32)
	for i := range masterSecret {
		masterSecret[i] = byte(i)
	}
	for i := range clientRandom {
		clientRandom[i] = byte(i + 100)
	}
	for i := range serverRandom {
		serverRandom[i] = byte(i + 200)
	}

	suites := []struct {
		name  string
		suite uint16
	}{
		{"CBC-SHA", TLS_RSA_WITH_AES_128_CBC_SHA},
		{"GCM-SHA256", TLS_RSA_WITH_AES_128_GCM_SHA256},
	}

	for _, s := range suites {
		b.Run(s.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				DeriveKeys(masterSecret, clientRandom, serverRandom, s.suite)
			}
		})
	}
}
