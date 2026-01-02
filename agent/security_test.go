package agent

import (
	"strings"
	"testing"
)

func TestClampInt(t *testing.T) {
	tests := []struct {
		name     string
		val      int
		min      int
		max      int
		expected int
	}{
		{"within range", 10, 0, 20, 10},
		{"below min", -5, 0, 20, 0},
		{"above max", 100, 0, 20, 20},
		{"at min", 0, 0, 20, 0},
		{"at max", 20, 0, 20, 20},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ClampInt(tt.val, tt.min, tt.max)
			if result != tt.expected {
				t.Errorf("ClampInt(%d, %d, %d) = %d, want %d", tt.val, tt.min, tt.max, result, tt.expected)
			}
		})
	}
}

func TestClampString(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		maxLen   int
		expected string
	}{
		{"short string", "hello", 10, "hello"},
		{"exact length", "hello", 5, "hello"},
		{"truncated", "hello world", 5, "hello..."},
		{"empty string", "", 10, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ClampString(tt.s, tt.maxLen)
			if result != tt.expected {
				t.Errorf("ClampString(%q, %d) = %q, want %q", tt.s, tt.maxLen, result, tt.expected)
			}
		})
	}
}

func TestValidateLimit(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]interface{}
		expected int
	}{
		{"default", map[string]interface{}{}, 20},
		{"valid limit", map[string]interface{}{"limit": float64(30)}, 30},
		{"exceed max", map[string]interface{}{"limit": float64(100)}, MaxLimit},
		{"negative", map[string]interface{}{"limit": float64(-5)}, 1},
		{"zero", map[string]interface{}{"limit": float64(0)}, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateLimit(tt.input)
			if result != tt.expected {
				t.Errorf("ValidateLimit() = %d, want %d", result, tt.expected)
			}
		})
	}
}

func TestValidateOffset(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]interface{}
		expected int
	}{
		{"default", map[string]interface{}{}, 0},
		{"valid offset", map[string]interface{}{"offset": float64(50)}, 50},
		{"exceed max", map[string]interface{}{"offset": float64(2000)}, MaxOffset},
		{"negative", map[string]interface{}{"offset": float64(-10)}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateOffset(tt.input)
			if result != tt.expected {
				t.Errorf("ValidateOffset() = %d, want %d", result, tt.expected)
			}
		})
	}
}

func TestRedactIP(t *testing.T) {
	tests := []struct {
		name  string
		ip    string
		check func(string) bool
	}{
		{
			"private 192.168",
			"192.168.1.100",
			func(r string) bool { return strings.HasPrefix(r, "192.168.x.x") },
		},
		{
			"private 10.x",
			"10.0.0.1",
			func(r string) bool { return strings.HasPrefix(r, "10.0.x.x") },
		},
		{
			"public IP",
			"8.8.8.8",
			func(r string) bool { return strings.HasPrefix(r, "IP[") },
		},
		{
			"localhost",
			"127.0.0.1",
			func(r string) bool { return strings.HasPrefix(r, "127.0.x.x") },
		},
		{
			"empty",
			"",
			func(r string) bool { return r == "" },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RedactIP(tt.ip)
			if !tt.check(result) {
				t.Errorf("RedactIP(%q) = %q, unexpected format", tt.ip, result)
			}
		})
	}
}

func TestRedactMAC(t *testing.T) {
	tests := []struct {
		name  string
		mac   string
		check func(string) bool
	}{
		{
			"valid MAC",
			"00:1a:2b:3c:4d:5e",
			func(r string) bool { return strings.HasPrefix(r, "00:1a:2b:xx:xx:xx") },
		},
		{
			"empty",
			"",
			func(r string) bool { return r == "" },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RedactMAC(tt.mac)
			if !tt.check(result) {
				t.Errorf("RedactMAC(%q) = %q, unexpected format", tt.mac, result)
			}
		})
	}
}

func TestRedactHTTPHeader(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		contains string
	}{
		{
			"authorization header",
			"Authorization: Bearer token123",
			"[REDACTED-",
		},
		{
			"cookie header",
			"Cookie: session=abc123",
			"[REDACTED-",
		},
		{
			"normal header",
			"Content-Type: application/json",
			"application/json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RedactHTTPHeader(tt.header)
			if !strings.Contains(result, tt.contains) {
				t.Errorf("RedactHTTPHeader(%q) = %q, should contain %q", tt.header, result, tt.contains)
			}
		})
	}
}

func TestRedactQueryParams(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		contains string
	}{
		{
			"with query params",
			"https://example.com/api?key=secret&user=admin",
			"[PARAMS-REDACTED-",
		},
		{
			"no query params",
			"https://example.com/api",
			"example.com/api",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RedactQueryParams(tt.url)
			if !strings.Contains(result, tt.contains) {
				t.Errorf("RedactQueryParams(%q) = %q, should contain %q", tt.url, result, tt.contains)
			}
		})
	}
}

func TestCheckRawDataAuthorization(t *testing.T) {
	tests := []struct {
		name        string
		userInput   string
		includeRaw  bool
		wantAuth    bool
		wantConfirm bool
	}{
		{"no raw requested", "分析数据包", false, false, false},
		{"raw requested without session auth", "分析数据包", true, false, true},
		{"raw keyword no longer auto-authorizes", "显示原始数据", true, false, true},
		{"hex keyword no longer auto-authorizes", "show me the hex dump", true, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use nil authStore (no session grants)
			allowed, _, _, needsConfirm := CheckRawDataAuthorization(tt.userInput, tt.includeRaw, nil)
			if allowed != tt.wantAuth {
				t.Errorf("CheckRawDataAuthorization(%q, %v) allowed=%v, want %v",
					tt.userInput, tt.includeRaw, allowed, tt.wantAuth)
			}
			if needsConfirm != tt.wantConfirm {
				t.Errorf("CheckRawDataAuthorization(%q, %v) needsConfirm=%v, want %v",
					tt.userInput, tt.includeRaw, needsConfirm, tt.wantConfirm)
			}
		})
	}
}

func TestCheckRawDataAuthorizationWithSessionGrant(t *testing.T) {
	store := NewAuthorizationStore()

	// Without session grant, should need confirmation
	allowed, _, _, needsConfirm := CheckRawDataAuthorization("分析数据包", true, store)
	if allowed || !needsConfirm {
		t.Error("Without session grant, should need confirmation")
	}

	// Grant session authorization
	store.sessionGrants[AuthTypeRawData] = true

	// With session grant, should be allowed without confirmation
	allowed, _, _, needsConfirm = CheckRawDataAuthorization("分析数据包", true, store)
	if !allowed || needsConfirm {
		t.Error("With session grant, should be allowed without confirmation")
	}
}

func TestEvidenceFormat(t *testing.T) {
	tests := []struct {
		name     string
		evidence *Evidence
		contains []string
	}{
		{
			"with packets",
			&Evidence{PacketIDs: []int{1, 2, 3}, EvidenceType: "test"},
			[]string{"Evidence:", "packets="},
		},
		{
			"with connections",
			&Evidence{Connections: []string{"1.1.1.1:80-2.2.2.2:443"}, EvidenceType: "conn"},
			[]string{"Evidence:", "connections="},
		},
		{
			"empty evidence",
			&Evidence{},
			[]string{}, // Should return empty string
		},
		{
			"nil evidence",
			nil,
			[]string{}, // Should return empty string
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.evidence.Format()
			for _, c := range tt.contains {
				if !strings.Contains(result, c) {
					t.Errorf("Evidence.Format() = %q, should contain %q", result, c)
				}
			}
			if len(tt.contains) == 0 && result != "" {
				t.Errorf("Evidence.Format() = %q, expected empty string", result)
			}
		})
	}
}

func TestTruncateInfo(t *testing.T) {
	tests := []struct {
		name     string
		info     string
		expected string
	}{
		{"short info", "GET /api", "GET /api"},
		{"exact length", strings.Repeat("a", MaxInfoLen), strings.Repeat("a", MaxInfoLen)},
		{"too long", strings.Repeat("a", MaxInfoLen+10), strings.Repeat("a", MaxInfoLen) + "..."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TruncateInfo(tt.info)
			if result != tt.expected {
				t.Errorf("TruncateInfo() length = %d, want %d", len(result), len(tt.expected))
			}
		})
	}
}

func TestGetToolNames(t *testing.T) {
	names := GetToolNames()

	expectedTools := []string{
		"get_packets",
		"filter_packets",
		"analyze_packet",
		"get_statistics",
		"explain_protocol",
		"find_connections",
		"find_dns_queries",
		"find_http_requests",
		"detect_anomalies",
	}

	for _, tool := range expectedTools {
		if !names[tool] {
			t.Errorf("GetToolNames() missing expected tool: %s", tool)
		}
	}

	// Check that unknown tools are not in the list
	if names["unknown_tool"] {
		t.Error("GetToolNames() should not contain unknown_tool")
	}
}

func TestAuthorizationStore(t *testing.T) {
	store := NewAuthorizationStore()

	// Initially no pending request
	if store.GetPendingRequest() != nil {
		t.Error("NewAuthorizationStore should have no pending request")
	}

	// Request authorization
	ctx := map[string]interface{}{"packet_number": 1}
	req := store.RequestAuthorization(AuthTypeRawData, "analyze_packet", ctx)
	if req == nil {
		t.Fatal("RequestAuthorization should return a request")
	}
	if req.Granted || req.Responded {
		t.Error("New request should not be granted or responded")
	}
	if req.Type != AuthTypeRawData {
		t.Errorf("Request type should be AuthTypeRawData, got %v", req.Type)
	}

	// Check pending request
	pending := store.GetPendingRequest()
	if pending == nil {
		t.Error("GetPendingRequest should return the pending request")
	}
	if pending != req {
		t.Error("GetPendingRequest should return the same request")
	}

	// Grant authorization for session
	store.GrantAuthorization(true)
	if !req.Granted || !req.Responded {
		t.Error("After GrantAuthorization, request should be granted and responded")
	}

	// Session should be authorized now
	if !store.IsAuthorized(AuthTypeRawData) {
		t.Error("After session grant, should be authorized")
	}

	// Clear pending request
	store.ClearPendingRequest()
	if store.GetPendingRequest() != nil {
		t.Error("After ClearPendingRequest, should have no pending request")
	}

	// New request should auto-grant because session is authorized
	req2 := store.RequestAuthorization(AuthTypeRawData, "analyze_packet", ctx)
	if !req2.Granted || !req2.Responded {
		t.Error("When session is authorized, new request should be auto-granted")
	}

	// Clear session grants
	store.ClearSessionGrants()
	if store.IsAuthorized(AuthTypeRawData) {
		t.Error("After ClearSessionGrants, should not be authorized")
	}
}

func TestAuthorizationDeny(t *testing.T) {
	store := NewAuthorizationStore()

	ctx := map[string]interface{}{"packet_number": 1}
	req := store.RequestAuthorization(AuthTypeRawData, "analyze_packet", ctx)

	// Deny authorization
	store.DenyAuthorization()
	if req.Granted {
		t.Error("After DenyAuthorization, request should not be granted")
	}
	if !req.Responded {
		t.Error("After DenyAuthorization, request should be responded")
	}

	// Session should NOT be authorized
	if store.IsAuthorized(AuthTypeRawData) {
		t.Error("After deny, session should not be authorized")
	}
}
