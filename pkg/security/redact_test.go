package security

import (
	"strings"
	"testing"
)

func TestRedactIP(t *testing.T) {
	// Private IP keeps first two octets
	got := RedactIP("192.168.1.100")
	if !strings.HasPrefix(got, "192.168.") {
		t.Errorf("RedactIP private = %q, want prefix 192.168.", got)
	}
	if !strings.Contains(got, "x.x[") {
		t.Errorf("RedactIP private = %q, want x.x[hash]", got)
	}

	// Public IP fully redacted
	got = RedactIP("93.184.216.34")
	if !strings.HasPrefix(got, "IP[") {
		t.Errorf("RedactIP public = %q, want IP[hash]", got)
	}
}

func TestRedactMAC(t *testing.T) {
	got := RedactMAC("aa:bb:cc:dd:ee:ff")
	if !strings.HasPrefix(got, "aa:bb:cc:") {
		t.Errorf("RedactMAC = %q, want OUI prefix", got)
	}
	if !strings.Contains(got, "xx:xx:xx[") {
		t.Errorf("RedactMAC = %q, want xx:xx:xx[hash]", got)
	}
}

func TestRedactText_AllEnabled(t *testing.T) {
	cfg := &RedactConfig{
		Enabled:    true,
		RedactIPs:  true,
		RedactMACs: true,
	}
	input := "src=192.168.1.1 dst=8.8.8.8 mac=aa:bb:cc:dd:ee:ff"
	got := RedactText(input, cfg)
	if strings.Contains(got, "192.168.1.1") {
		t.Errorf("RedactText did not redact private IP")
	}
	if strings.Contains(got, "8.8.8.8") {
		t.Errorf("RedactText did not redact public IP")
	}
	if strings.Contains(got, "dd:ee:ff") {
		t.Errorf("RedactText did not redact MAC suffix")
	}
}

func TestRedactText_Disabled(t *testing.T) {
	cfg := &RedactConfig{Enabled: false}
	input := "192.168.1.1"
	if got := RedactText(input, cfg); got != input {
		t.Errorf("RedactText disabled = %q, want %q", got, input)
	}
}
