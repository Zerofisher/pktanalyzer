package tools

import (
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
)

// toolError creates an MCP error result with structured JSON matching the spec format:
// {"error": "<snake_case_error>", "message": "<human message>", "code": "<ERROR_CODE>"}
func toolError(code, message string) *mcp.CallToolResult {
	errJSON := toJSON(map[string]string{
		"error":   toSnakeCase(message),
		"message": message,
		"code":    code,
	})
	result := mcp.NewToolResultText(errJSON)
	result.IsError = true
	return result
}

// toSnakeCase converts a message to a short snake_case error identifier.
// e.g. "no capture loaded" → "no_capture_loaded"
func toSnakeCase(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, " ", "_")
	// Truncate to first 40 chars for brevity
	if len(s) > 40 {
		s = s[:40]
	}
	return s
}

// requiredString extracts a required string parameter from the request.
func requiredString(req mcp.CallToolRequest, name string) (string, error) {
	args := req.GetArguments()
	v, ok := args[name]
	if !ok || v == nil {
		return "", fmt.Errorf("required parameter %q is missing", name)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("parameter %q must be a string", name)
	}
	if s == "" {
		return "", fmt.Errorf("parameter %q must not be empty", name)
	}
	return s, nil
}

// optionalString extracts an optional string parameter with a default.
func optionalString(req mcp.CallToolRequest, name, defaultVal string) string {
	args := req.GetArguments()
	v, ok := args[name]
	if !ok || v == nil {
		return defaultVal
	}
	s, ok := v.(string)
	if !ok {
		return defaultVal
	}
	return s
}

// optionalInt extracts an optional integer parameter with a default.
// JSON numbers arrive as float64.
func optionalInt(req mcp.CallToolRequest, name string, defaultVal int) int {
	args := req.GetArguments()
	v, ok := args[name]
	if !ok || v == nil {
		return defaultVal
	}
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	default:
		return defaultVal
	}
}

// optionalBool extracts an optional boolean parameter with a default.
func optionalBool(req mcp.CallToolRequest, name string, defaultVal bool) bool {
	args := req.GetArguments()
	v, ok := args[name]
	if !ok || v == nil {
		return defaultVal
	}
	b, ok := v.(bool)
	if !ok {
		return defaultVal
	}
	return b
}
