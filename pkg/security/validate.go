package security

// ClampInt clamps val to [min, max].
func ClampInt(val, min, max int) int {
	if val < min {
		return min
	}
	if val > max {
		return max
	}
	return val
}

// ClampString truncates s to maxLen characters, appending "..." if truncated.
func ClampString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// ClampLimit validates and clamps a limit parameter to [1, max].
func ClampLimit(limit, max int) int {
	return ClampInt(limit, 1, max)
}

// ClampOffset validates and clamps an offset parameter to [0, max].
func ClampOffset(offset, max int) int {
	return ClampInt(offset, 0, max)
}

// ValidateStringParam clamps a string parameter to MaxStringLen.
func ValidateStringParam(s string, maxLen int) string {
	return ClampString(s, maxLen)
}
