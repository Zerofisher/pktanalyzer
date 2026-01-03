// Package openrouter provides OpenRouter API client (OpenAI-compatible)
package openrouter

import (
	"fmt"
	"os"

	"github.com/Zerofisher/pktanalyzer/agent/llm"
	"github.com/Zerofisher/pktanalyzer/agent/providers/openai"
)

const (
	DefaultBaseURL = "https://openrouter.ai/api/v1"
	DefaultModel   = "anthropic/claude-sonnet-4" // OpenRouter uses provider/model format
)

// New creates a new OpenRouter client
// OpenRouter is OpenAI-compatible, so we reuse the OpenAI client
func New(cfg *llm.Config) (*openai.Client, error) {
	if cfg == nil {
		cfg = llm.DefaultConfig()
	}

	// Get API key from config or environment
	apiKey := cfg.APIKey
	if apiKey == "" {
		apiKey = os.Getenv("OPENROUTER_API_KEY")
	}
	if apiKey == "" {
		return nil, fmt.Errorf("OPENROUTER_API_KEY not set")
	}
	cfg.APIKey = apiKey

	// Set defaults
	if cfg.BaseURL == "" {
		cfg.BaseURL = DefaultBaseURL
	}
	if cfg.Model == "" {
		cfg.Model = os.Getenv("AI_MODEL")
		if cfg.Model == "" {
			cfg.Model = DefaultModel
		}
	}

	// Add OpenRouter-specific headers
	if cfg.ExtraHeader == nil {
		cfg.ExtraHeader = make(map[string]string)
	}
	// Optional: add site info for OpenRouter analytics
	if _, ok := cfg.ExtraHeader["HTTP-Referer"]; !ok {
		cfg.ExtraHeader["HTTP-Referer"] = "https://github.com/pktanalyzer"
	}
	if _, ok := cfg.ExtraHeader["X-Title"]; !ok {
		cfg.ExtraHeader["X-Title"] = "PktAnalyzer"
	}

	return openai.NewWithProvider(cfg, llm.ProviderOpenRouter)
}
