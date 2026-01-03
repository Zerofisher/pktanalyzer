// Package ollama provides Ollama API client (OpenAI-compatible mode)
package ollama

import (
	"fmt"
	"os"

	"github.com/Zerofisher/pktanalyzer/agent/llm"
	"github.com/Zerofisher/pktanalyzer/agent/providers/openai"
)

const (
	DefaultBaseURL = "http://localhost:11434/v1" // Ollama's OpenAI-compatible endpoint
	DefaultModel   = "llama3.2"
)

// New creates a new Ollama client using OpenAI-compatible mode
// Ollama supports /v1/chat/completions which is OpenAI-compatible
func New(cfg *llm.Config) (*openai.Client, error) {
	if cfg == nil {
		cfg = llm.DefaultConfig()
	}

	// Get base URL from environment or use default
	if cfg.BaseURL == "" {
		cfg.BaseURL = os.Getenv("OLLAMA_BASE_URL")
		if cfg.BaseURL == "" {
			cfg.BaseURL = DefaultBaseURL
		}
	}

	// Ensure URL ends with /v1 for OpenAI compatibility
	if cfg.BaseURL == "http://localhost:11434" {
		cfg.BaseURL += "/v1"
	}

	// Get model from environment or use default
	if cfg.Model == "" {
		cfg.Model = os.Getenv("AI_MODEL")
		if cfg.Model == "" {
			cfg.Model = DefaultModel
		}
	}

	// Ollama doesn't require an API key, but the OpenAI client needs one
	// We use a dummy key
	if cfg.APIKey == "" {
		cfg.APIKey = os.Getenv("OLLAMA_API_KEY")
		if cfg.APIKey == "" {
			cfg.APIKey = "ollama" // dummy key for local Ollama
		}
	}

	client, err := openai.NewWithProvider(cfg, llm.ProviderOllama)
	if err != nil {
		return nil, fmt.Errorf("failed to create Ollama client: %w", err)
	}

	return client, nil
}

// IsAvailable checks if Ollama is running locally
func IsAvailable() bool {
	baseURL := os.Getenv("OLLAMA_BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}

	// Try to create a client - if it works, Ollama is available
	cfg := llm.DefaultConfig()
	cfg.BaseURL = baseURL + "/v1"
	cfg.APIKey = "ollama"
	cfg.Model = DefaultModel

	_, err := openai.NewWithProvider(cfg, llm.ProviderOllama)
	return err == nil
}
