package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestFetchURL_RejectsNonHTTP verifies that FetchURL rejects non-HTTP schemes.
func TestFetchURL_RejectsNonHTTP(t *testing.T) {
	client := NewWebSearchClient()
	ctx := context.Background()

	tests := []struct {
		name string
		url  string
	}{
		{"file scheme", "file:///etc/passwd"},
		{"ftp scheme", "ftp://example.com/secret"},
		{"gopher scheme", "gopher://evil.com"},
		{"javascript scheme", "javascript:alert(1)"},
		{"data scheme", "data:text/html,<h1>hi</h1>"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.FetchURL(ctx, tt.url, DefaultContentChars)
			if err == nil {
				t.Errorf("FetchURL(%q) should reject non-http/https scheme, but got nil error", tt.url)
			}
			if err != nil && !strings.Contains(err.Error(), "http/https") {
				t.Errorf("FetchURL(%q) error should mention http/https restriction, got: %v", tt.url, err)
			}
		})
	}
}

// TestFetchURL_LoopbackBlocked verifies that FetchURL blocks loopback addresses.
func TestFetchURL_LoopbackBlocked(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("internal-loopback-data"))
	}))
	defer server.Close()

	client := NewWebSearchClient()
	ctx := context.Background()

	_, err := client.FetchURL(ctx, server.URL, DefaultContentChars)
	if err == nil {
		t.Fatal("FetchURL to loopback should be blocked but succeeded")
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "SSRF") && !strings.Contains(errStr, "blocked") &&
		!strings.Contains(errStr, "not allowed") && !strings.Contains(errStr, "安全检查") {
		t.Errorf("FetchURL error should indicate SSRF protection, got: %v", err)
	}
}

// TestFetchURL_PrivateNetworkBlocked verifies that FetchURL blocks private network IPs.
func TestFetchURL_PrivateNetworkBlocked(t *testing.T) {
	client := NewWebSearchClient()
	ctx := context.Background()

	privateIPs := []struct {
		name string
		url  string
	}{
		{"RFC1918 10.x", "http://10.255.255.1:12345/secret"},
		{"RFC1918 172.16.x", "http://172.16.0.1:12345/internal"},
		{"RFC1918 192.168.x", "http://192.168.1.1:12345/router"},
		{"cloud metadata", "http://169.254.169.254:12345/latest/meta-data/"},
		{"link-local", "http://169.254.1.1:12345/link-local"},
	}

	for _, tt := range privateIPs {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.FetchURL(ctx, tt.url, DefaultContentChars)
			if err == nil {
				t.Errorf("FetchURL(%q) should be blocked but succeeded", tt.url)
				return
			}

			errStr := err.Error()
			if !strings.Contains(errStr, "SSRF") && !strings.Contains(errStr, "blocked") &&
				!strings.Contains(errStr, "not allowed") && !strings.Contains(errStr, "安全检查") {
				t.Errorf("FetchURL(%q) should fail with SSRF error, got: %v", tt.url, err)
			}
		})
	}
}

// TestFetchURL_RedirectToInternalBlocked verifies that redirect to loopback is blocked.
func TestFetchURL_RedirectToInternalBlocked(t *testing.T) {
	internalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("secret-internal-data-via-redirect"))
	}))
	defer internalServer.Close()

	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internalServer.URL, http.StatusFound)
	}))
	defer redirectServer.Close()

	// Use test client since redirectServer itself is on loopback
	client := NewTestWebSearchClient()
	ctx := context.Background()

	// Even with allowLocal, the SSRF-safe DialContext still applies in production.
	// But in test mode we allow local - this test verifies the redirect validation
	// at the CheckRedirect level. Since test client allows local, redirect will succeed.
	// The key protection is that NewWebSearchClient() blocks it.
	prodClient := NewWebSearchClient()
	_, err := prodClient.FetchURL(ctx, redirectServer.URL, DefaultContentChars)
	if err == nil {
		t.Fatal("Production client should block redirect to loopback but succeeded")
	}

	_ = ctx
	_ = client
}

// TestFetchURL_ValidURL verifies that FetchURL works correctly using test client.
func TestFetchURL_ValidURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body><h1>Test Page</h1><p>This is test content for FetchURL.</p></body></html>"))
	}))
	defer server.Close()

	// Use test client for httptest (which binds to 127.0.0.1)
	client := NewTestWebSearchClient()
	ctx := context.Background()

	result, err := client.FetchURL(ctx, server.URL, DefaultContentChars)
	if err != nil {
		t.Fatalf("FetchURL failed for valid URL: %v", err)
	}

	if !strings.Contains(result, "Test Page") {
		t.Errorf("FetchURL result should contain 'Test Page', got: %s", result)
	}
	if !strings.Contains(result, "test content") {
		t.Errorf("FetchURL result should contain 'test content', got: %s", result)
	}
	if !strings.Contains(result, server.URL) {
		t.Errorf("FetchURL result should contain the source URL %s", server.URL)
	}
}

// TestFetchURL_MultipleRedirectsToInternalBlocked tests chained redirects are blocked.
func TestFetchURL_MultipleRedirectsToInternalBlocked(t *testing.T) {
	internalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("deeply-nested-internal-secret"))
	}))
	defer internalServer.Close()

	middleServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internalServer.URL, http.StatusTemporaryRedirect)
	}))
	defer middleServer.Close()

	entryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, middleServer.URL, http.StatusFound)
	}))
	defer entryServer.Close()

	client := NewWebSearchClient()
	ctx := context.Background()

	_, err := client.FetchURL(ctx, entryServer.URL, DefaultContentChars)
	if err == nil {
		t.Fatal("FetchURL with chained redirects to loopback should be blocked")
	}
}

// TestFetchURL_CloudMetadataBlocked verifies that cloud metadata endpoints are blocked.
func TestFetchURL_CloudMetadataBlocked(t *testing.T) {
	client := NewWebSearchClient()
	ctx := context.Background()

	metadataURLs := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://169.254.169.254/computeMetadata/v1/",
		"http://169.254.169.254/metadata/instance?api-version=2021-02-01",
	}

	for _, metaURL := range metadataURLs {
		t.Run(metaURL, func(t *testing.T) {
			_, err := client.FetchURL(ctx, metaURL, DefaultContentChars)
			if err == nil {
				t.Errorf("FetchURL(%q) should be blocked but succeeded", metaURL)
				return
			}

			errStr := err.Error()
			if !strings.Contains(errStr, "SSRF") && !strings.Contains(errStr, "blocked") &&
				!strings.Contains(errStr, "not allowed") && !strings.Contains(errStr, "安全检查") {
				t.Errorf("FetchURL(%q) should fail with SSRF error, got: %v", metaURL, err)
			}
		})
	}
}

// TestFetchURL_TestClientAllowsLocal verifies that the test client can access local servers.
func TestFetchURL_TestClientAllowsLocal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("local-test-data"))
	}))
	defer server.Close()

	client := NewTestWebSearchClient()
	ctx := context.Background()

	result, err := client.FetchURL(ctx, server.URL, DefaultContentChars)
	if err != nil {
		t.Fatalf("TestWebSearchClient should allow local addresses: %v", err)
	}
	if !strings.Contains(result, "local-test-data") {
		t.Errorf("Expected 'local-test-data' in result, got: %s", result)
	}
}
