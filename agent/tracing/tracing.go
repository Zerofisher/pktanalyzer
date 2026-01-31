// Package tracing provides OpenTelemetry-based observability for the AI agent.
// It supports runtime detection of Langfuse credentials and automatic tracing setup.
package tracing

import (
	"context"
	"encoding/base64"
	"os"
	"strings"
	"sync"
	"unicode/utf8"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
)

var (
	tracer    trace.Tracer
	tp        *sdktrace.TracerProvider
	initOnce  sync.Once
	isEnabled bool
)

// Init initializes tracing by detecting environment variables at runtime.
// If LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY are set, it configures
// OTLP HTTP exporter to send traces to Langfuse. Otherwise, a noop tracer is used.
func Init(ctx context.Context) error {
	var initErr error
	initOnce.Do(func() {
		initErr = initFromEnv(ctx)
	})
	return initErr
}

func initFromEnv(ctx context.Context) error {
	publicKey := os.Getenv("LANGFUSE_PUBLIC_KEY")
	secretKey := os.Getenv("LANGFUSE_SECRET_KEY")

	// If not configured, use noop tracer (no-op by default from otel global)
	if publicKey == "" || secretKey == "" {
		tracer = otel.Tracer("pktanalyzer.agent")
		isEnabled = false
		return nil
	}

	// Build Langfuse OTLP endpoint
	host := os.Getenv("LANGFUSE_HOST")
	if host == "" {
		host = "cloud.langfuse.com"
	}
	// Strip protocol prefix if present
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")

	// Basic Auth header: base64(publicKey:secretKey)
	auth := base64.StdEncoding.EncodeToString([]byte(publicKey + ":" + secretKey))

	// Create OTLP HTTP exporter
	// Use WithEndpoint + WithURLPath for explicit control over the trace endpoint
	exporter, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpoint(host),
		otlptracehttp.WithURLPath("/api/public/otel/v1/traces"),
		otlptracehttp.WithHeaders(map[string]string{
			"Authorization": "Basic " + auth,
		}),
	)
	if err != nil {
		return err
	}

	// Create TracerProvider with batching and resource attributes
	tp = sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName("pktanalyzer"),
			semconv.ServiceVersion("1.0.0"),
		)),
	)

	// Set as global TracerProvider
	otel.SetTracerProvider(tp)
	tracer = tp.Tracer("pktanalyzer.agent")
	isEnabled = true

	return nil
}

// Tracer returns the configured tracer instance.
// Safe to call before Init - returns a noop tracer if not initialized.
func Tracer() trace.Tracer {
	if tracer == nil {
		return otel.Tracer("pktanalyzer.agent")
	}
	return tracer
}

// IsEnabled returns whether tracing is actively sending data.
// Returns false if credentials are not configured.
func IsEnabled() bool {
	return isEnabled
}

// Shutdown gracefully shuts down the tracer provider, flushing any pending spans.
// Should be called before application exit.
func Shutdown(ctx context.Context) error {
	if tp != nil {
		return tp.Shutdown(ctx)
	}
	return nil
}

// Truncate truncates a string to approximately maxLen bytes, appending "..." if truncated.
// It sanitizes the string to ensure valid UTF-8 and avoids splitting multi-byte characters.
func Truncate(s string, maxLen int) string {
	s = sanitizeUTF8(s)
	if len(s) <= maxLen {
		return s
	}
	// Truncate at a rune boundary to avoid splitting multi-byte characters
	truncated := make([]byte, 0, maxLen)
	for _, r := range s {
		encoded := utf8.RuneLen(r)
		if len(truncated)+encoded > maxLen {
			break
		}
		buf := make([]byte, encoded)
		utf8.EncodeRune(buf, r)
		truncated = append(truncated, buf...)
	}
	return string(truncated) + "..."
}

// SanitizeUTF8 replaces invalid UTF-8 bytes with the Unicode replacement character.
// Exported for use in error messages passed to span attributes.
func SanitizeUTF8(s string) string {
	return sanitizeUTF8(s)
}

// sanitizeUTF8 replaces invalid UTF-8 bytes with the Unicode replacement character.
// This is necessary because OTLP protobuf requires valid UTF-8 strings.
func sanitizeUTF8(s string) string {
	if isValidUTF8(s) {
		return s
	}
	// Replace invalid bytes with replacement character
	return strings.ToValidUTF8(s, "\uFFFD")
}

// isValidUTF8 checks if a string contains only valid UTF-8 sequences.
func isValidUTF8(s string) bool {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			return false
		}
		i += size
	}
	return true
}
