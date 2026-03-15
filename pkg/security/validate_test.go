package security

import "testing"

func TestClampInt(t *testing.T) {
	tests := []struct {
		val, min, max, want int
	}{
		{5, 1, 10, 5},
		{0, 1, 10, 1},
		{15, 1, 10, 10},
		{-1, 0, 100, 0},
	}
	for _, tt := range tests {
		got := ClampInt(tt.val, tt.min, tt.max)
		if got != tt.want {
			t.Errorf("ClampInt(%d, %d, %d) = %d, want %d", tt.val, tt.min, tt.max, got, tt.want)
		}
	}
}

func TestClampString(t *testing.T) {
	if got := ClampString("hello", 10); got != "hello" {
		t.Errorf("ClampString short = %q", got)
	}
	if got := ClampString("hello world", 5); got != "hello..." {
		t.Errorf("ClampString long = %q", got)
	}
}

func TestClampLimit(t *testing.T) {
	cfg := DefaultConfig()
	if got := ClampLimit(300, cfg.MaxLimit); got != cfg.MaxLimit {
		t.Errorf("ClampLimit(300) = %d, want %d", got, cfg.MaxLimit)
	}
	if got := ClampLimit(0, cfg.MaxLimit); got != 1 {
		t.Errorf("ClampLimit(0) = %d, want 1", got)
	}
	if got := ClampLimit(50, cfg.MaxLimit); got != 50 {
		t.Errorf("ClampLimit(50) = %d, want 50", got)
	}
}

func TestClampOffset(t *testing.T) {
	cfg := DefaultConfig()
	if got := ClampOffset(-1, cfg.MaxOffset); got != 0 {
		t.Errorf("ClampOffset(-1) = %d, want 0", got)
	}
}
