package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// identityPattern defines allowed characters in identity claims.
// Alphanumeric, hyphens, underscores, periods. Rejects Redis-special
// characters (: * ? [ ]) and whitespace/control characters.
var identityPattern = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

const (
	// MinSecretLength is the minimum acceptable length for HMAC secrets.
	// HMAC-SHA256 should use at least 32 bytes of entropy.
	MinSecretLength = 32
)

type Config struct {
	Server     ServerConfig     `yaml:"server"`
	Auth       AuthConfig       `yaml:"auth"`
	Redis      RedisConfig      `yaml:"redis"`
	Transports TransportsConfig `yaml:"transports"`
	Logging    LoggingConfig    `yaml:"logging"`
}

type ServerConfig struct {
	Host                   string   `yaml:"host"`
	Port                   int      `yaml:"port"`
	HeartbeatSeconds       int      `yaml:"heartbeat_seconds"`
	MaxConnectionsTotal    int      `yaml:"max_connections_total"`
	MaxConnectionsPerIdent int      `yaml:"max_connections_per_identity"`
	MaxMessageSizeBytes    int      `yaml:"max_message_size_bytes"`
	ClientBufferSize       int      `yaml:"client_buffer_size"`
	SlowConsumerPolicy     string   `yaml:"slow_consumer_policy"`
	WebSocketPingSeconds    int      `yaml:"websocket_ping_seconds"`
	WebSocketWriteTimeoutMs int     `yaml:"websocket_write_timeout_ms"`
	ShutdownTimeoutSeconds  int     `yaml:"shutdown_timeout_seconds"`
	AllowedOrigins         []string `yaml:"allowed_origins"`
	StatsIdentity          string   `yaml:"stats_identity"`
}

type AuthConfig struct {
	JWTSecret        string         `yaml:"jwt_secret"`
	JWTPublicKey     string         `yaml:"jwt_public_key"`
	IdentityClaim    string         `yaml:"identity_claim"`
	ExpectedIssuer   string         `yaml:"expected_issuer"`
	ExpectedAudience string         `yaml:"expected_audience"`
	RequireExpiry    *bool          `yaml:"require_expiry"`
	ServiceToken     string         `yaml:"service_token"`
	Verify           *VerifyConfig  `yaml:"verify,omitempty"`
	Refresh          *RefreshConfig `yaml:"refresh,omitempty"`
}

type VerifyConfig struct {
	URL           string `yaml:"url"`
	Method        string `yaml:"method"`
	TokenParam    string `yaml:"token_param"`
	TokenLocation string `yaml:"token_location"`
	ActiveField   string `yaml:"active_field"`
	IdentityField string `yaml:"identity_field"`
	CacheSeconds  int    `yaml:"cache_seconds"`
}

type RefreshConfig struct {
	URL             string `yaml:"url"`
	Method          string `yaml:"method"`
	TokenParam      string `yaml:"token_param"`
	TokenLocation   string `yaml:"token_location"`
	NewTokenField   string `yaml:"new_token_field"`
	IntervalSeconds int    `yaml:"interval_seconds"`
}

type RedisConfig struct {
	URL           string `yaml:"url"`
	Password      string `yaml:"password"`
	DB            int    `yaml:"db"`
	ChannelPrefix string `yaml:"channel_prefix"`
}

type TransportsConfig struct {
	SSE           bool   `yaml:"sse"`
	WebSocket     bool   `yaml:"websocket"`
	InboundPrefix string `yaml:"inbound_prefix"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// Load reads configuration from a YAML file path.
// Secrets should be injected via environment variable overrides, not
// embedded in the config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	applyEnvOverrides(cfg)
	applyDefaults(cfg)

	if err := validate(cfg); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

func applyDefaults(cfg *Config) {
	if cfg.Server.Host == "" {
		cfg.Server.Host = "0.0.0.0"
	}
	if cfg.Server.Port == 0 {
		cfg.Server.Port = 8080
	}
	if cfg.Server.HeartbeatSeconds == 0 {
		cfg.Server.HeartbeatSeconds = 30
	}
	if cfg.Server.MaxMessageSizeBytes == 0 {
		cfg.Server.MaxMessageSizeBytes = 4096
	}
	if cfg.Server.ClientBufferSize == 0 {
		cfg.Server.ClientBufferSize = 64
	}
	if cfg.Server.SlowConsumerPolicy == "" {
		cfg.Server.SlowConsumerPolicy = "drop_newest_message"
	}
	if cfg.Server.WebSocketPingSeconds == 0 {
		cfg.Server.WebSocketPingSeconds = 30
	}
	if cfg.Server.WebSocketWriteTimeoutMs == 0 {
		cfg.Server.WebSocketWriteTimeoutMs = 10000
	}
	if cfg.Server.ShutdownTimeoutSeconds == 0 {
		cfg.Server.ShutdownTimeoutSeconds = 10
	}
	if cfg.Auth.IdentityClaim == "" {
		cfg.Auth.IdentityClaim = "sub"
	}
	if cfg.Auth.RequireExpiry == nil {
		t := true
		cfg.Auth.RequireExpiry = &t
	}
	if cfg.Redis.URL == "" {
		cfg.Redis.URL = "redis://localhost:6379"
	}
	if cfg.Redis.ChannelPrefix == "" {
		cfg.Redis.ChannelPrefix = "streams"
	}
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}
	if cfg.Logging.Format == "" {
		cfg.Logging.Format = "text"
	}

	// Default verify config values.
	if cfg.Auth.Verify != nil {
		if cfg.Auth.Verify.Method == "" {
			cfg.Auth.Verify.Method = "POST"
		}
		if cfg.Auth.Verify.TokenParam == "" {
			cfg.Auth.Verify.TokenParam = "token"
		}
		if cfg.Auth.Verify.TokenLocation == "" {
			cfg.Auth.Verify.TokenLocation = "body"
		}
		if cfg.Auth.Verify.ActiveField == "" {
			cfg.Auth.Verify.ActiveField = "active"
		}
		if cfg.Auth.Verify.IdentityField == "" {
			cfg.Auth.Verify.IdentityField = "sub"
		}
		if cfg.Auth.Verify.CacheSeconds == 0 {
			cfg.Auth.Verify.CacheSeconds = 60
		}
	}

	// Default refresh config values.
	if cfg.Auth.Refresh != nil {
		if cfg.Auth.Refresh.Method == "" {
			cfg.Auth.Refresh.Method = "POST"
		}
		if cfg.Auth.Refresh.TokenParam == "" {
			cfg.Auth.Refresh.TokenParam = "refresh_token"
		}
		if cfg.Auth.Refresh.TokenLocation == "" {
			cfg.Auth.Refresh.TokenLocation = "body"
		}
		if cfg.Auth.Refresh.NewTokenField == "" {
			cfg.Auth.Refresh.NewTokenField = "access_token"
		}
		if cfg.Auth.Refresh.IntervalSeconds == 0 {
			cfg.Auth.Refresh.IntervalSeconds = 1800
		}
	}
}

// applyEnvOverrides reads specific environment variables that take
// precedence over config file values. Use for secrets in production.
func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("STREAMRELAY_AUTH_JWT_SECRET"); v != "" {
		cfg.Auth.JWTSecret = v
	}
	if v := os.Getenv("STREAMRELAY_AUTH_JWT_PUBLIC_KEY"); v != "" {
		cfg.Auth.JWTPublicKey = v
	}
	if v := os.Getenv("STREAMRELAY_AUTH_SERVICE_TOKEN"); v != "" {
		cfg.Auth.ServiceToken = v
	}
	if v := os.Getenv("STREAMRELAY_REDIS_URL"); v != "" {
		cfg.Redis.URL = v
	}
	if v := os.Getenv("STREAMRELAY_REDIS_PASSWORD"); v != "" {
		cfg.Redis.Password = v
	}
}

func validate(cfg *Config) error {
	if cfg.Auth.JWTSecret == "" && cfg.Auth.JWTPublicKey == "" {
		return fmt.Errorf("auth: must set either jwt_secret or jwt_public_key")
	}
	if cfg.Auth.JWTSecret != "" && cfg.Auth.JWTPublicKey != "" {
		return fmt.Errorf("auth: set jwt_secret OR jwt_public_key, not both")
	}
	if cfg.Auth.JWTSecret != "" && len(cfg.Auth.JWTSecret) < MinSecretLength {
		return fmt.Errorf("auth: jwt_secret must be at least %d characters", MinSecretLength)
	}
	if !cfg.Transports.SSE && !cfg.Transports.WebSocket {
		return fmt.Errorf("transports: at least one of sse or websocket must be enabled")
	}
	if cfg.Auth.Verify != nil {
		loc := cfg.Auth.Verify.TokenLocation
		if loc != "body" && loc != "header" && loc != "query" {
			return fmt.Errorf("auth.verify.token_location must be body, header, or query")
		}
	}
	if cfg.Auth.Refresh != nil {
		loc := cfg.Auth.Refresh.TokenLocation
		if loc != "body" && loc != "header" && loc != "query" {
			return fmt.Errorf("auth.refresh.token_location must be body, header, or query")
		}
	}

	policy := cfg.Server.SlowConsumerPolicy
	if policy != "drop_client" && policy != "drop_newest_message" {
		return fmt.Errorf("server.slow_consumer_policy must be drop_client or drop_newest_message")
	}

	level := strings.ToLower(cfg.Logging.Level)
	if level != "debug" && level != "info" && level != "warn" && level != "error" {
		return fmt.Errorf("logging.level must be debug, info, warn, or error")
	}

	return nil
}

// Addr returns the host:port string for the server listener.
func (c *Config) Addr() string {
	return fmt.Sprintf("%s:%d", c.Server.Host, c.Server.Port)
}

// ChannelForIdentity returns the Redis channel name for a given identity.
func (c *Config) ChannelForIdentity(identity string) string {
	return fmt.Sprintf("%s:%s", c.Redis.ChannelPrefix, identity)
}

// InboundChannelForIdentity returns the Redis inbound channel for a given identity.
// Returns empty string if inbound publishing is disabled.
func (c *Config) InboundChannelForIdentity(identity string) string {
	if c.Transports.InboundPrefix == "" {
		return ""
	}
	return fmt.Sprintf("%s:%s", c.Transports.InboundPrefix, identity)
}

// IsOriginAllowed checks whether a given origin is permitted.
// If no allowed_origins are configured, all origins are rejected.
// Use ["*"] to explicitly allow all origins (not recommended for production).
func (c *Config) IsOriginAllowed(origin string) bool {
	if len(c.Server.AllowedOrigins) == 0 {
		return false
	}
	for _, allowed := range c.Server.AllowedOrigins {
		if allowed == "*" || strings.EqualFold(allowed, origin) {
			return true
		}
	}
	return false
}

// IsPlaceholderSecret returns true if the JWT secret is a known placeholder
// that must not be used in production.
func (c *Config) IsPlaceholderSecret() bool {
	placeholders := []string{
		"change-me-in-production",
		"secret",
		"password",
		"jwt_secret",
		"your-secret-here",
	}
	secret := strings.ToLower(c.Auth.JWTSecret)
	for _, p := range placeholders {
		if secret == p {
			return true
		}
	}
	return false
}

// ValidateIdentity checks that an identity string is safe for use as a
// Redis channel component. Rejects empty strings, strings with
// Redis-special characters (: * ? [), and control characters.
func ValidateIdentity(identity string) error {
	if identity == "" {
		return fmt.Errorf("identity is empty")
	}
	if len(identity) > 128 {
		return fmt.Errorf("identity exceeds 128 characters")
	}
	if !identityPattern.MatchString(identity) {
		return fmt.Errorf("identity contains invalid characters (allowed: alphanumeric, . _ -)")
	}
	return nil
}
