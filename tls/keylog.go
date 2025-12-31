package tls

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
)

// KeyLogEntry represents a single entry in the key log file
type KeyLogEntry struct {
	Label        string
	ClientRandom []byte
	Secret       []byte
}

// KeyLog holds all keys from the SSLKEYLOGFILE
type KeyLog struct {
	mu      sync.RWMutex
	entries map[string][]KeyLogEntry // keyed by hex(ClientRandom)

	// TLS 1.2 keys (CLIENT_RANDOM -> master_secret)
	masterSecrets map[string][]byte

	// TLS 1.3 keys
	clientHandshakeSecrets map[string][]byte
	serverHandshakeSecrets map[string][]byte
	clientTrafficSecrets   map[string][]byte
	serverTrafficSecrets   map[string][]byte
}

// NewKeyLog creates a new empty KeyLog
func NewKeyLog() *KeyLog {
	return &KeyLog{
		entries:                make(map[string][]KeyLogEntry),
		masterSecrets:          make(map[string][]byte),
		clientHandshakeSecrets: make(map[string][]byte),
		serverHandshakeSecrets: make(map[string][]byte),
		clientTrafficSecrets:   make(map[string][]byte),
		serverTrafficSecrets:   make(map[string][]byte),
	}
}

// LoadKeyLogFile loads keys from an SSLKEYLOGFILE format file
func LoadKeyLogFile(path string) (*KeyLog, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open key log file: %w", err)
	}
	defer file.Close()

	kl := NewKeyLog()
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		entry, err := parseKeyLogLine(line)
		if err != nil {
			// Skip invalid lines but continue parsing
			continue
		}

		kl.addEntry(entry)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading key log file: %w", err)
	}

	return kl, nil
}

// parseKeyLogLine parses a single line from the key log file
// Format: <LABEL> <ClientRandom hex> <Secret hex>
func parseKeyLogLine(line string) (*KeyLogEntry, error) {
	parts := strings.Fields(line)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid line format: expected 3 fields, got %d", len(parts))
	}

	label := parts[0]
	clientRandomHex := parts[1]
	secretHex := parts[2]

	clientRandom, err := hex.DecodeString(clientRandomHex)
	if err != nil {
		return nil, fmt.Errorf("invalid client random hex: %w", err)
	}

	secret, err := hex.DecodeString(secretHex)
	if err != nil {
		return nil, fmt.Errorf("invalid secret hex: %w", err)
	}

	return &KeyLogEntry{
		Label:        label,
		ClientRandom: clientRandom,
		Secret:       secret,
	}, nil
}

// addEntry adds a key log entry to the appropriate map
func (kl *KeyLog) addEntry(entry *KeyLogEntry) {
	kl.mu.Lock()
	defer kl.mu.Unlock()

	key := hex.EncodeToString(entry.ClientRandom)

	// Store in entries map
	kl.entries[key] = append(kl.entries[key], *entry)

	// Store in type-specific maps for faster lookup
	switch entry.Label {
	case "CLIENT_RANDOM":
		kl.masterSecrets[key] = entry.Secret
	case "CLIENT_HANDSHAKE_TRAFFIC_SECRET":
		kl.clientHandshakeSecrets[key] = entry.Secret
	case "SERVER_HANDSHAKE_TRAFFIC_SECRET":
		kl.serverHandshakeSecrets[key] = entry.Secret
	case "CLIENT_TRAFFIC_SECRET_0":
		kl.clientTrafficSecrets[key] = entry.Secret
	case "SERVER_TRAFFIC_SECRET_0":
		kl.serverTrafficSecrets[key] = entry.Secret
	}
}

// FindMasterSecret finds the master secret for a given client random (TLS 1.2)
func (kl *KeyLog) FindMasterSecret(clientRandom []byte) []byte {
	kl.mu.RLock()
	defer kl.mu.RUnlock()

	key := hex.EncodeToString(clientRandom)
	if secret, ok := kl.masterSecrets[key]; ok {
		result := make([]byte, len(secret))
		copy(result, secret)
		return result
	}
	return nil
}

// FindClientTrafficSecret finds the client traffic secret (TLS 1.3)
func (kl *KeyLog) FindClientTrafficSecret(clientRandom []byte) []byte {
	kl.mu.RLock()
	defer kl.mu.RUnlock()

	key := hex.EncodeToString(clientRandom)
	if secret, ok := kl.clientTrafficSecrets[key]; ok {
		result := make([]byte, len(secret))
		copy(result, secret)
		return result
	}
	return nil
}

// FindServerTrafficSecret finds the server traffic secret (TLS 1.3)
func (kl *KeyLog) FindServerTrafficSecret(clientRandom []byte) []byte {
	kl.mu.RLock()
	defer kl.mu.RUnlock()

	key := hex.EncodeToString(clientRandom)
	if secret, ok := kl.serverTrafficSecrets[key]; ok {
		result := make([]byte, len(secret))
		copy(result, secret)
		return result
	}
	return nil
}

// HasKey checks if there's any key for the given client random
func (kl *KeyLog) HasKey(clientRandom []byte) bool {
	kl.mu.RLock()
	defer kl.mu.RUnlock()

	key := hex.EncodeToString(clientRandom)
	_, ok := kl.entries[key]
	return ok
}

// Count returns the total number of key entries
func (kl *KeyLog) Count() int {
	kl.mu.RLock()
	defer kl.mu.RUnlock()

	count := 0
	for _, entries := range kl.entries {
		count += len(entries)
	}
	return count
}

// SessionCount returns the number of unique sessions (client randoms)
func (kl *KeyLog) SessionCount() int {
	kl.mu.RLock()
	defer kl.mu.RUnlock()
	return len(kl.entries)
}
