package tracing

import (
	"context"
	"os"
	"sync"
	"testing"
	"unicode/utf8"
)

func TestInit_NoEnvVars(t *testing.T) {
	// Ensure env vars are not set
	os.Unsetenv("LANGFUSE_PUBLIC_KEY")
	os.Unsetenv("LANGFUSE_SECRET_KEY")

	// Reset the package state for testing
	initOnce = sync.Once{}
	tracer = nil
	tp = nil
	isEnabled = false

	err := Init(context.Background())
	if err != nil {
		t.Fatalf("Init() returned error: %v", err)
	}

	if IsEnabled() {
		t.Error("IsEnabled() should return false when env vars are not set")
	}

	if Tracer() == nil {
		t.Error("Tracer() should return a non-nil tracer (noop tracer)")
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxLen   int
		expected string
	}{
		{"short ASCII", "hello", 10, "hello"},
		{"truncate ASCII", "hello world", 5, "hello..."},
		{"empty string", "", 5, ""},
		{"exact length", "abc", 3, "abc"},
		{"one over", "abcd", 3, "abc..."},
		// Multi-byte UTF-8 tests - Chinese characters are 3 bytes each
		{"Chinese no truncate", "你好", 10, "你好"},
		{"Chinese truncate at boundary", "你好世界", 6, "你好..."},       // 6 bytes = 2 chars
		{"Chinese partial byte limit", "你好世界", 4, "你..."},          // 4 bytes can only fit 1 char (3 bytes)
		{"Mixed ASCII and Chinese", "Hi你好", 5, "Hi你..."},            // "Hi" (2 bytes) + "你" (3 bytes) = 5 bytes
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Truncate(tt.input, tt.maxLen)
			if result != tt.expected {
				t.Errorf("Truncate(%q, %d) = %q; want %q", tt.input, tt.maxLen, result, tt.expected)
			}
		})
	}
}

func TestSanitizeUTF8(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"valid ASCII", "hello"},
		{"valid Chinese", "你好"},
		{"invalid byte", "hello\x80world"},
		{"invalid sequence", "\xff\xfe"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeUTF8(tt.input)
			// Verify result is valid UTF-8
			for i := 0; i < len(result); {
				r, size := []rune(result)[0], 1
				if i < len(result) {
					_, size = utf8.DecodeRuneInString(result[i:])
				}
				if r == utf8.RuneError && size == 1 && len(result) > 0 {
					// Check if we're at a replacement character (which is valid)
					if result[i:i+3] != "\uFFFD" {
						t.Errorf("SanitizeUTF8(%q) produced invalid UTF-8 at position %d", tt.input, i)
					}
				}
				i += size
			}
			// Simpler check: just verify result is valid UTF-8
			if !utf8.ValidString(result) {
				t.Errorf("SanitizeUTF8(%q) = %q is not valid UTF-8", tt.input, result)
			}
		})
	}
}
