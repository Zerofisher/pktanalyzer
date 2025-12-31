// Package llm provides client factory and configuration detection
package llm

import (
	"fmt"
	"os"
)

// ProviderConfig holds provider-specific configuration from environment
type ProviderConfig struct {
	Provider   Provider
	APIKey     string
	BaseURL    string
	Model      string
	Available  bool
}

// DetectProvider detects available LLM provider from environment variables
// Priority: AI_PROVIDER explicit > OPENROUTER_API_KEY > ANTHROPIC_API_KEY > OPENAI_API_KEY > OLLAMA
func DetectProvider() Provider {
	// Check explicit provider setting
	if p := os.Getenv("AI_PROVIDER"); p != "" {
		switch p {
		case "claude", "anthropic":
			return ProviderClaude
		case "openai":
			return ProviderOpenAI
		case "openrouter":
			return ProviderOpenRouter
		case "ollama":
			return ProviderOllama
		}
	}

	// Check API keys in priority order
	if os.Getenv("OPENROUTER_API_KEY") != "" {
		return ProviderOpenRouter
	}
	if os.Getenv("ANTHROPIC_API_KEY") != "" {
		return ProviderClaude
	}
	if os.Getenv("OPENAI_API_KEY") != "" {
		return ProviderOpenAI
	}

	// Check if Ollama is configured
	if os.Getenv("OLLAMA_BASE_URL") != "" {
		return ProviderOllama
	}

	return ""
}

// GetProviderConfigs returns configuration for all detectable providers
func GetProviderConfigs() []ProviderConfig {
	var configs []ProviderConfig

	// Claude
	if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
		configs = append(configs, ProviderConfig{
			Provider:  ProviderClaude,
			APIKey:    key,
			BaseURL:   os.Getenv("ANTHROPIC_BASE_URL"),
			Model:     os.Getenv("AI_MODEL"),
			Available: true,
		})
	}

	// OpenAI
	if key := os.Getenv("OPENAI_API_KEY"); key != "" {
		configs = append(configs, ProviderConfig{
			Provider:  ProviderOpenAI,
			APIKey:    key,
			BaseURL:   os.Getenv("OPENAI_BASE_URL"),
			Model:     os.Getenv("AI_MODEL"),
			Available: true,
		})
	}

	// OpenRouter
	if key := os.Getenv("OPENROUTER_API_KEY"); key != "" {
		configs = append(configs, ProviderConfig{
			Provider:  ProviderOpenRouter,
			APIKey:    key,
			Model:     os.Getenv("AI_MODEL"),
			Available: true,
		})
	}

	// Ollama
	if baseURL := os.Getenv("OLLAMA_BASE_URL"); baseURL != "" {
		configs = append(configs, ProviderConfig{
			Provider:  ProviderOllama,
			BaseURL:   baseURL,
			Model:     os.Getenv("AI_MODEL"),
			Available: true,
		})
	}

	return configs
}

// ConfigFromEnv creates a Config from environment variables
func ConfigFromEnv(provider Provider) *Config {
	cfg := DefaultConfig()
	cfg.Model = os.Getenv("AI_MODEL")

	switch provider {
	case ProviderClaude:
		cfg.APIKey = os.Getenv("ANTHROPIC_API_KEY")
		cfg.BaseURL = os.Getenv("ANTHROPIC_BASE_URL")
	case ProviderOpenAI:
		cfg.APIKey = os.Getenv("OPENAI_API_KEY")
		cfg.BaseURL = os.Getenv("OPENAI_BASE_URL")
	case ProviderOpenRouter:
		cfg.APIKey = os.Getenv("OPENROUTER_API_KEY")
	case ProviderOllama:
		cfg.BaseURL = os.Getenv("OLLAMA_BASE_URL")
		cfg.APIKey = os.Getenv("OLLAMA_API_KEY")
	}

	return cfg
}

// ProviderName returns human-readable provider name
func (p Provider) String() string {
	switch p {
	case ProviderClaude:
		return "Claude (Anthropic)"
	case ProviderOpenAI:
		return "OpenAI"
	case ProviderOpenRouter:
		return "OpenRouter"
	case ProviderOllama:
		return "Ollama"
	default:
		return string(p)
	}
}

// EnvVarName returns the primary environment variable for this provider
func (p Provider) EnvVarName() string {
	switch p {
	case ProviderClaude:
		return "ANTHROPIC_API_KEY"
	case ProviderOpenAI:
		return "OPENAI_API_KEY"
	case ProviderOpenRouter:
		return "OPENROUTER_API_KEY"
	case ProviderOllama:
		return "OLLAMA_BASE_URL"
	default:
		return ""
	}
}

// ValidateConfig validates the configuration
func ValidateConfig(cfg *Config, provider Provider) error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}

	switch provider {
	case ProviderClaude, ProviderOpenAI, ProviderOpenRouter:
		if cfg.APIKey == "" {
			return fmt.Errorf("%s not set", provider.EnvVarName())
		}
	case ProviderOllama:
		// Ollama doesn't require API key
	default:
		return fmt.Errorf("unknown provider: %s", provider)
	}

	return nil
}
