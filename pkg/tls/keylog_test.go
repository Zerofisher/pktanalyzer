package tls

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
)

// makeClientRandom returns a deterministic 32-byte client random for testing.
// The index i creates distinct values.
func makeClientRandom(t *testing.T, i int) []byte {
	t.Helper()
	raw := fmt.Sprintf("%064x", i) // 64 hex chars = 32 bytes
	b, err := hex.DecodeString(raw[:64])
	if err != nil {
		t.Fatalf("makeClientRandom: %v", err)
	}
	return b
}

// makeMasterSecret returns a deterministic 48-byte master secret for testing.
func makeMasterSecret(t *testing.T, i int) []byte {
	t.Helper()
	raw := fmt.Sprintf("%096x", i) // 96 hex chars = 48 bytes
	b, err := hex.DecodeString(raw[:96])
	if err != nil {
		t.Fatalf("makeMasterSecret: %v", err)
	}
	return b
}

// makeTrafficSecret returns a deterministic 32-byte traffic secret (TLS 1.3).
func makeTrafficSecret(t *testing.T, i int) []byte {
	t.Helper()
	raw := fmt.Sprintf("%064x", i+0xAA) // offset to differ from client random
	b, err := hex.DecodeString(raw[:64])
	if err != nil {
		t.Fatalf("makeTrafficSecret: %v", err)
	}
	return b
}

// writeKeyLogFile writes content to a temp file and returns the path.
// The caller does not need to clean up; t.TempDir handles it.
func writeKeyLogFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/keylog.txt"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writeKeyLogFile: %v", err)
	}
	return path
}

func TestNewKeyLog(t *testing.T) {
	kl := NewKeyLog()
	if kl == nil {
		t.Fatal("NewKeyLog returned nil")
	}
	if got := kl.Count(); got != 0 {
		t.Errorf("Count: got %d, want 0", got)
	}
	if got := kl.SessionCount(); got != 0 {
		t.Errorf("SessionCount: got %d, want 0", got)
	}
}

func TestLoadKeyLogFile(t *testing.T) {
	cr1 := makeClientRandom(t, 1)
	ms1 := makeMasterSecret(t, 1)
	cr2 := makeClientRandom(t, 2)
	ms2 := makeMasterSecret(t, 2)

	content := fmt.Sprintf(
		"CLIENT_RANDOM %s %s\nCLIENT_RANDOM %s %s\n",
		hex.EncodeToString(cr1), hex.EncodeToString(ms1),
		hex.EncodeToString(cr2), hex.EncodeToString(ms2),
	)
	path := writeKeyLogFile(t, content)

	kl, err := LoadKeyLogFile(path)
	if err != nil {
		t.Fatalf("LoadKeyLogFile: %v", err)
	}
	if got := kl.Count(); got != 2 {
		t.Errorf("Count: got %d, want 2", got)
	}
	if got := kl.SessionCount(); got != 2 {
		t.Errorf("SessionCount: got %d, want 2", got)
	}

	// Verify actual secrets are retrievable.
	secret1 := kl.FindMasterSecret(cr1)
	if secret1 == nil {
		t.Fatal("FindMasterSecret(cr1) returned nil")
	}
	if hex.EncodeToString(secret1) != hex.EncodeToString(ms1) {
		t.Errorf("FindMasterSecret(cr1): got %x, want %x", secret1, ms1)
	}

	secret2 := kl.FindMasterSecret(cr2)
	if secret2 == nil {
		t.Fatal("FindMasterSecret(cr2) returned nil")
	}
	if hex.EncodeToString(secret2) != hex.EncodeToString(ms2) {
		t.Errorf("FindMasterSecret(cr2): got %x, want %x", secret2, ms2)
	}
}

func TestLoadKeyLogFile_Comments(t *testing.T) {
	cr := makeClientRandom(t, 10)
	ms := makeMasterSecret(t, 10)

	content := fmt.Sprintf(
		"# NSS Key Log\n\n# Another comment\n\nCLIENT_RANDOM %s %s\n\n# trailing comment\n",
		hex.EncodeToString(cr), hex.EncodeToString(ms),
	)
	path := writeKeyLogFile(t, content)

	kl, err := LoadKeyLogFile(path)
	if err != nil {
		t.Fatalf("LoadKeyLogFile: %v", err)
	}
	if got := kl.Count(); got != 1 {
		t.Errorf("Count: got %d, want 1 (comments and blanks should be skipped)", got)
	}
	if got := kl.SessionCount(); got != 1 {
		t.Errorf("SessionCount: got %d, want 1", got)
	}
	if !kl.HasKey(cr) {
		t.Error("HasKey returned false for the single valid entry")
	}
}

func TestLoadKeyLogFile_InvalidLines(t *testing.T) {
	cr := makeClientRandom(t, 20)
	ms := makeMasterSecret(t, 20)
	validLine := fmt.Sprintf("CLIENT_RANDOM %s %s",
		hex.EncodeToString(cr), hex.EncodeToString(ms))

	lines := []string{
		"ONLY_TWO_FIELDS deadbeef",                          // too few fields
		"TOO MANY FIELDS HERE extra",                        // too many fields
		"CLIENT_RANDOM ZZZZ " + hex.EncodeToString(ms),      // invalid hex in client random
		"CLIENT_RANDOM " + hex.EncodeToString(cr) + " ZZZZ", // invalid hex in secret
		validLine,
	}
	content := strings.Join(lines, "\n") + "\n"
	path := writeKeyLogFile(t, content)

	kl, err := LoadKeyLogFile(path)
	if err != nil {
		t.Fatalf("LoadKeyLogFile should not return error for invalid lines: %v", err)
	}
	if got := kl.Count(); got != 1 {
		t.Errorf("Count: got %d, want 1 (only the valid line)", got)
	}
	if !kl.HasKey(cr) {
		t.Error("HasKey returned false for the valid entry")
	}
}

func TestLoadKeyLogFile_NotFound(t *testing.T) {
	_, err := LoadKeyLogFile("/nonexistent/path/keylog.txt")
	if err == nil {
		t.Fatal("LoadKeyLogFile should return error for missing file")
	}
}

func TestKeyLog_FindMasterSecret(t *testing.T) {
	cr := makeClientRandom(t, 30)
	ms := makeMasterSecret(t, 30)

	content := fmt.Sprintf("CLIENT_RANDOM %s %s\n",
		hex.EncodeToString(cr), hex.EncodeToString(ms))
	path := writeKeyLogFile(t, content)

	kl, err := LoadKeyLogFile(path)
	if err != nil {
		t.Fatalf("LoadKeyLogFile: %v", err)
	}

	secret := kl.FindMasterSecret(cr)
	if secret == nil {
		t.Fatal("FindMasterSecret returned nil for existing key")
	}
	if hex.EncodeToString(secret) != hex.EncodeToString(ms) {
		t.Errorf("FindMasterSecret: got %x, want %x", secret, ms)
	}

	// Verify that the returned slice is a copy: mutating it must not affect
	// the stored value.
	for i := range secret {
		secret[i] = 0xFF
	}
	secret2 := kl.FindMasterSecret(cr)
	if secret2 == nil {
		t.Fatal("FindMasterSecret returned nil on second call")
	}
	if hex.EncodeToString(secret2) != hex.EncodeToString(ms) {
		t.Errorf("mutating returned copy corrupted store: got %x, want %x", secret2, ms)
	}
}

func TestKeyLog_FindMasterSecret_NotFound(t *testing.T) {
	kl := NewKeyLog()
	unknownCR := makeClientRandom(t, 99)
	if got := kl.FindMasterSecret(unknownCR); got != nil {
		t.Errorf("FindMasterSecret for unknown key: got %x, want nil", got)
	}
}

func TestKeyLog_FindClientTrafficSecret(t *testing.T) {
	cr := makeClientRandom(t, 40)
	ts := makeTrafficSecret(t, 40)

	content := fmt.Sprintf("CLIENT_TRAFFIC_SECRET_0 %s %s\n",
		hex.EncodeToString(cr), hex.EncodeToString(ts))
	path := writeKeyLogFile(t, content)

	kl, err := LoadKeyLogFile(path)
	if err != nil {
		t.Fatalf("LoadKeyLogFile: %v", err)
	}

	secret := kl.FindClientTrafficSecret(cr)
	if secret == nil {
		t.Fatal("FindClientTrafficSecret returned nil")
	}
	if hex.EncodeToString(secret) != hex.EncodeToString(ts) {
		t.Errorf("FindClientTrafficSecret: got %x, want %x", secret, ts)
	}

	// Must not exist in master secret map.
	if got := kl.FindMasterSecret(cr); got != nil {
		t.Errorf("CLIENT_TRAFFIC_SECRET_0 should not appear as master secret, got %x", got)
	}
}

func TestKeyLog_FindServerTrafficSecret(t *testing.T) {
	cr := makeClientRandom(t, 50)
	ts := makeTrafficSecret(t, 50)

	content := fmt.Sprintf("SERVER_TRAFFIC_SECRET_0 %s %s\n",
		hex.EncodeToString(cr), hex.EncodeToString(ts))
	path := writeKeyLogFile(t, content)

	kl, err := LoadKeyLogFile(path)
	if err != nil {
		t.Fatalf("LoadKeyLogFile: %v", err)
	}

	secret := kl.FindServerTrafficSecret(cr)
	if secret == nil {
		t.Fatal("FindServerTrafficSecret returned nil")
	}
	if hex.EncodeToString(secret) != hex.EncodeToString(ts) {
		t.Errorf("FindServerTrafficSecret: got %x, want %x", secret, ts)
	}

	// Must not exist in client traffic secret map.
	if got := kl.FindClientTrafficSecret(cr); got != nil {
		t.Errorf("SERVER_TRAFFIC_SECRET_0 should not appear as client traffic secret, got %x", got)
	}
}

func TestKeyLog_HasKey(t *testing.T) {
	cr := makeClientRandom(t, 60)
	ms := makeMasterSecret(t, 60)
	unknownCR := makeClientRandom(t, 61)

	content := fmt.Sprintf("CLIENT_RANDOM %s %s\n",
		hex.EncodeToString(cr), hex.EncodeToString(ms))
	path := writeKeyLogFile(t, content)

	kl, err := LoadKeyLogFile(path)
	if err != nil {
		t.Fatalf("LoadKeyLogFile: %v", err)
	}

	if !kl.HasKey(cr) {
		t.Error("HasKey returned false for existing key")
	}
	if kl.HasKey(unknownCR) {
		t.Error("HasKey returned true for unknown key")
	}
}

func TestKeyLog_Count(t *testing.T) {
	// Two sessions, one with multiple labels (TLS 1.3 style).
	cr1 := makeClientRandom(t, 70)
	cr2 := makeClientRandom(t, 71)
	ms := makeMasterSecret(t, 70)
	cts := makeTrafficSecret(t, 70)
	sts := makeTrafficSecret(t, 71)

	lines := []string{
		fmt.Sprintf("CLIENT_RANDOM %s %s",
			hex.EncodeToString(cr1), hex.EncodeToString(ms)),
		fmt.Sprintf("CLIENT_TRAFFIC_SECRET_0 %s %s",
			hex.EncodeToString(cr2), hex.EncodeToString(cts)),
		fmt.Sprintf("SERVER_TRAFFIC_SECRET_0 %s %s",
			hex.EncodeToString(cr2), hex.EncodeToString(sts)),
	}
	content := strings.Join(lines, "\n") + "\n"
	path := writeKeyLogFile(t, content)

	kl, err := LoadKeyLogFile(path)
	if err != nil {
		t.Fatalf("LoadKeyLogFile: %v", err)
	}

	// Total entries: 3 (one CLIENT_RANDOM + one CLIENT_TRAFFIC + one SERVER_TRAFFIC).
	if got := kl.Count(); got != 3 {
		t.Errorf("Count: got %d, want 3", got)
	}
}

func TestKeyLog_SessionCount(t *testing.T) {
	// Two distinct client randoms, the second has two labels.
	cr1 := makeClientRandom(t, 80)
	cr2 := makeClientRandom(t, 81)
	ms := makeMasterSecret(t, 80)
	cts := makeTrafficSecret(t, 80)
	sts := makeTrafficSecret(t, 81)

	lines := []string{
		fmt.Sprintf("CLIENT_RANDOM %s %s",
			hex.EncodeToString(cr1), hex.EncodeToString(ms)),
		fmt.Sprintf("CLIENT_TRAFFIC_SECRET_0 %s %s",
			hex.EncodeToString(cr2), hex.EncodeToString(cts)),
		fmt.Sprintf("SERVER_TRAFFIC_SECRET_0 %s %s",
			hex.EncodeToString(cr2), hex.EncodeToString(sts)),
	}
	content := strings.Join(lines, "\n") + "\n"
	path := writeKeyLogFile(t, content)

	kl, err := LoadKeyLogFile(path)
	if err != nil {
		t.Fatalf("LoadKeyLogFile: %v", err)
	}

	// Unique client randoms: cr1 and cr2 = 2 sessions.
	if got := kl.SessionCount(); got != 2 {
		t.Errorf("SessionCount: got %d, want 2", got)
	}
}

func TestKeyLog_Concurrent(t *testing.T) {
	// Build a keylog file with multiple sessions.
	const numSessions = 50
	var lines []string
	clientRandoms := make([][]byte, numSessions)
	for i := range numSessions {
		cr := makeClientRandom(t, 1000+i)
		ms := makeMasterSecret(t, 1000+i)
		clientRandoms[i] = cr
		lines = append(lines, fmt.Sprintf("CLIENT_RANDOM %s %s",
			hex.EncodeToString(cr), hex.EncodeToString(ms)))
	}
	content := strings.Join(lines, "\n") + "\n"
	path := writeKeyLogFile(t, content)

	kl, err := LoadKeyLogFile(path)
	if err != nil {
		t.Fatalf("LoadKeyLogFile: %v", err)
	}

	// Launch concurrent readers across all sessions.
	var wg sync.WaitGroup
	const goroutinesPerSession = 4

	for i := range numSessions {
		cr := clientRandoms[i]
		for range goroutinesPerSession {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if !kl.HasKey(cr) {
					t.Errorf("HasKey returned false for session %d", i)
				}
				secret := kl.FindMasterSecret(cr)
				if secret == nil {
					t.Errorf("FindMasterSecret returned nil for session %d", i)
				}
				_ = kl.Count()
				_ = kl.SessionCount()
			}()
		}
	}

	wg.Wait()

	// Final consistency check after concurrent access.
	if got := kl.Count(); got != numSessions {
		t.Errorf("Count after concurrent access: got %d, want %d", got, numSessions)
	}
	if got := kl.SessionCount(); got != numSessions {
		t.Errorf("SessionCount after concurrent access: got %d, want %d", got, numSessions)
	}
}
