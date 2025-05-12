package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server struct {
		Host string `yaml:"host"`
		Port string `yaml:"port"`
	} `yaml:"server"`
	Auth struct {
		JWTSecret          string   `yaml:"jwt_secret"`
		RefreshTokenSecret string   `yaml:"refresh_token_secret"`
		AccessTokenTTL     int      `yaml:"access_token_ttl"`
		RefreshTokenTTL    int      `yaml:"refresh_token_ttl"`
		WebhookURL         string   `yaml:"webhook_url"`
		AllowedHosts       []string `yaml:"allowed_hosts"`
	} `yaml:"auth"`
	Database struct {
		DSN string `yaml:"dsn"`
	} `yaml:"database"`
}

func LoadConfig(filename string) (*Config, error) {
	cleanPath := filepath.Clean(filename)

	if strings.Contains(cleanPath, "..") {
		return nil, fmt.Errorf("invalid config path: path traversal attempt detected")
	}

	fileInfo, err := os.Stat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("config file error: %w", err)
	}

	if !fileInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("config path is not a regular file")
	}

	f, err := os.Open(cleanPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	config := &Config{}
	if err := yaml.NewDecoder(f).Decode(config); err != nil {
		return nil, err
	}

	if jwtSecret := os.Getenv("JWT_SECRET"); jwtSecret != "" {
		config.Auth.JWTSecret = jwtSecret
	}

	if refreshTokenSecret := os.Getenv("REFRESH_TOKEN_SECRET"); refreshTokenSecret != "" {
		config.Auth.RefreshTokenSecret = refreshTokenSecret
	}

	if webhookURL := os.Getenv("WEBHOOK_URL"); webhookURL != "" {
		config.Auth.WebhookURL = webhookURL
	}

	if len(config.Auth.AllowedHosts) == 0 && config.Auth.WebhookURL != "" {
		webhookHost := extractHostFromURL(config.Auth.WebhookURL)
		if webhookHost != "" {
			config.Auth.AllowedHosts = []string{webhookHost}
		}
	}

	return config, nil
}

func extractHostFromURL(urlStr string) string {
	urlStr = strings.TrimPrefix(urlStr, "http://")
	urlStr = strings.TrimPrefix(urlStr, "https://")

	parts := strings.Split(urlStr, "/")
	if len(parts) > 0 {
		return parts[0]
	}

	return ""
}
