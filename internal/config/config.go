// Package config loads runtime configuration for the service.
package config

import (
	"os"
)

// Config stores the task broker runtime settings.
type Config struct {
	HTTPAddress string
	HTTPPort    string
}

// Load reads configuration from environment variables.
func Load() (Config, error) {
	cfg := Config{
		HTTPAddress: getEnv("HTTP_ADDRESS", "0.0.0.0"),
		HTTPPort:    getEnv("HTTP_PORT", "8080"),
	}

	return cfg, nil
}

func getEnv(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	return value
}
