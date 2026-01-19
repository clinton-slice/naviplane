package config

import (
	"fmt"
	"os"
)

type Config struct {
	Port        string
	Environment string
}

// Load reads configuration from environment variables.
// It fails fast with clear errors for missing required values.
func Load() (*Config, error) {
	var missing []string

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // sensible default
	}

	env := os.Getenv("ENV")
	if env == "" {
		env = "development" // sensible default
	}

	// Validate environment value
	if env != "development" && env != "staging" && env != "production" {
		return nil, fmt.Errorf("invalid ENV value %q: must be development, staging, or production", env)
	}

	// Example: fail fast for required values (uncomment when needed)
	// apiKey := os.Getenv("API_KEY")
	// if apiKey == "" {
	// 	missing = append(missing, "API_KEY")
	// }

	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required environment variables: %v", missing)
	}

	return &Config{
		Port:        port,
		Environment: env,
	}, nil
}
