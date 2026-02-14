package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/streamrelay/streamrelay/internal/config"
)

var (
	ErrInvalidToken  = errors.New("invalid or expired token")
	ErrNoIdentity    = errors.New("token missing identity claim")
	ErrBadIdentity   = errors.New("identity claim contains invalid characters")
	ErrVerifyFailed  = errors.New("remote token verification failed")
	ErrRefreshFailed = errors.New("token refresh failed")
)

const (
	// Maximum number of entries in the verification cache.
	maxCacheEntries = 10000
)

// Claims represents the relevant JWT claims extracted during validation.
type Claims struct {
	Identity     string
	ExpiresAt    time.Time
	RawToken     string
	RefreshToken string
}

// cacheEntry holds a cached verification result with access tracking for LRU.
type cacheEntry struct {
	expiry     time.Time
	lastAccess time.Time
}

// Authenticator handles JWT validation, optional remote verification,
// and optional token refresh.
type Authenticator struct {
	cfg        config.AuthConfig
	key        interface{} // *rsa.PublicKey, *ecdsa.PublicKey, or []byte (HMAC)
	method     jwt.SigningMethod
	httpClient *http.Client

	// Verification cache: SHA-256(token) -> cache entry.
	cacheMu sync.RWMutex
	cache   map[string]cacheEntry
}

// New creates an Authenticator from the auth configuration.
func New(cfg config.AuthConfig) (*Authenticator, error) {
	a := &Authenticator{
		cfg:   cfg,
		cache: make(map[string]cacheEntry),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}

	if cfg.JWTSecret != "" {
		a.key = []byte(cfg.JWTSecret)
		a.method = jwt.SigningMethodHS256
	} else if cfg.JWTPublicKey != "" {
		key, method, err := loadPublicKey(cfg.JWTPublicKey)
		if err != nil {
			return nil, fmt.Errorf("loading public key: %w", err)
		}
		a.key = key
		a.method = method
	}

	// Validate remote endpoint URLs at startup — reject private/link-local
	// addresses to prevent SSRF against cloud metadata services.
	if cfg.Verify != nil {
		if err := validateEndpointURL(cfg.Verify.URL); err != nil {
			return nil, fmt.Errorf("auth.verify.url: %w", err)
		}
	}
	if cfg.Refresh != nil {
		if err := validateEndpointURL(cfg.Refresh.URL); err != nil {
			return nil, fmt.Errorf("auth.refresh.url: %w", err)
		}
	}

	return a, nil
}

// Validate checks a JWT token and returns the extracted claims.
// Performs local signature/expiry/issuer/audience validation first,
// then optional remote verification if configured.
func (a *Authenticator) Validate(ctx context.Context, rawToken string) (*Claims, error) {
	claims, err := a.validateLocal(rawToken)
	if err != nil {
		return nil, err
	}

	if a.cfg.Verify != nil {
		if err := a.verifyRemote(ctx, rawToken); err != nil {
			return nil, err
		}
	}

	return claims, nil
}

// IsExpired checks whether the given claims have expired.
func (a *Authenticator) IsExpired(c *Claims) bool {
	if c.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(c.ExpiresAt)
}

// Refresh attempts to obtain a new token using the refresh endpoint.
func (a *Authenticator) Refresh(ctx context.Context, refreshToken string) (string, error) {
	if a.cfg.Refresh == nil {
		return "", ErrRefreshFailed
	}

	r := a.cfg.Refresh
	newToken, err := a.callRemote(ctx, r.URL, r.Method, r.TokenParam, r.TokenLocation, refreshToken, r.NewTokenField)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrRefreshFailed, err)
	}

	return newToken, nil
}

// RefreshEnabled returns true if a refresh endpoint is configured.
func (a *Authenticator) RefreshEnabled() bool {
	return a.cfg.Refresh != nil
}

// RefreshInterval returns the configured refresh interval.
func (a *Authenticator) RefreshInterval() time.Duration {
	if a.cfg.Refresh == nil {
		return 0
	}
	return time.Duration(a.cfg.Refresh.IntervalSeconds) * time.Second
}

// validateLocal performs local JWT validation: signature, expiry,
// algorithm, and optionally issuer and audience.
func (a *Authenticator) validateLocal(rawToken string) (*Claims, error) {
	parserOpts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{a.method.Alg()}),
	}

	// Require expiry claim by default. Tokens without exp are rejected.
	if a.cfg.RequireExpiry != nil && *a.cfg.RequireExpiry {
		parserOpts = append(parserOpts, jwt.WithExpirationRequired())
	}

	// Add issuer validation if configured.
	if a.cfg.ExpectedIssuer != "" {
		parserOpts = append(parserOpts, jwt.WithIssuer(a.cfg.ExpectedIssuer))
	}

	// Add audience validation if configured.
	if a.cfg.ExpectedAudience != "" {
		parserOpts = append(parserOpts, jwt.WithAudience(a.cfg.ExpectedAudience))
	}

	parser := jwt.NewParser(parserOpts...)

	token, err := parser.Parse(rawToken, func(t *jwt.Token) (interface{}, error) {
		return a.key, nil
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidToken
	}

	// Extract identity from configured claim.
	identityRaw, exists := mapClaims[a.cfg.IdentityClaim]
	if !exists {
		return nil, fmt.Errorf("%w: claim '%s' not found", ErrNoIdentity, a.cfg.IdentityClaim)
	}
	identity := fmt.Sprintf("%v", identityRaw)

	// Validate identity is safe for use as a Redis channel component.
	if err := config.ValidateIdentity(identity); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadIdentity, err)
	}

	// Extract expiry if present.
	var expiresAt time.Time
	if exp, err := mapClaims.GetExpirationTime(); err == nil && exp != nil {
		expiresAt = exp.Time
	}

	return &Claims{
		Identity:  identity,
		ExpiresAt: expiresAt,
		RawToken:  rawToken,
	}, nil
}

// verifyRemote calls the configured verification endpoint.
func (a *Authenticator) verifyRemote(ctx context.Context, rawToken string) error {
	v := a.cfg.Verify
	cacheKey := hashToken(rawToken)

	// Check cache first.
	a.cacheMu.RLock()
	if entry, cached := a.cache[cacheKey]; cached && time.Now().Before(entry.expiry) {
		a.cacheMu.RUnlock()
		a.touchCacheEntry(cacheKey)
		return nil
	}
	a.cacheMu.RUnlock()

	result, err := a.callRemote(ctx, v.URL, v.Method, v.TokenParam, v.TokenLocation, rawToken, v.ActiveField)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrVerifyFailed, err)
	}

	if result != "true" && result != "1" {
		return ErrVerifyFailed
	}

	// Cache the successful verification.
	a.cacheMu.Lock()
	a.evictIfNeeded()
	a.cache[cacheKey] = cacheEntry{
		expiry:     time.Now().Add(time.Duration(v.CacheSeconds) * time.Second),
		lastAccess: time.Now(),
	}
	a.cacheMu.Unlock()

	return nil
}

// touchCacheEntry updates the last access time for LRU tracking.
func (a *Authenticator) touchCacheEntry(key string) {
	a.cacheMu.Lock()
	if entry, exists := a.cache[key]; exists {
		entry.lastAccess = time.Now()
		a.cache[key] = entry
	}
	a.cacheMu.Unlock()
}

// evictIfNeeded removes the least recently used entries if the cache
// exceeds its maximum size. Must be called with cacheMu held.
func (a *Authenticator) evictIfNeeded() {
	if len(a.cache) < maxCacheEntries {
		return
	}

	evictCount := maxCacheEntries / 10
	if evictCount < 1 {
		evictCount = 1
	}

	for i := 0; i < evictCount; i++ {
		var oldestKey string
		var oldestTime time.Time
		first := true

		for k, entry := range a.cache {
			if first || entry.lastAccess.Before(oldestTime) {
				oldestKey = k
				oldestTime = entry.lastAccess
				first = false
			}
		}

		if oldestKey != "" {
			delete(a.cache, oldestKey)
		}
	}
}

// callRemote makes an HTTP request to a remote auth endpoint and extracts
// a field from the JSON response.
func (a *Authenticator) callRemote(ctx context.Context, endpoint, method, tokenParam, tokenLocation, tokenValue, responseField string) (string, error) {
	var req *http.Request
	var err error

	switch strings.ToLower(tokenLocation) {
	case "body":
		form := url.Values{}
		form.Set(tokenParam, tokenValue)
		req, err = http.NewRequestWithContext(ctx, method, endpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return "", err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	case "header":
		req, err = http.NewRequestWithContext(ctx, method, endpoint, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set(tokenParam, "Bearer "+tokenValue)

	case "query":
		u, parseErr := url.Parse(endpoint)
		if parseErr != nil {
			return "", parseErr
		}
		q := u.Query()
		q.Set(tokenParam, tokenValue)
		u.RawQuery = q.Encode()
		req, err = http.NewRequestWithContext(ctx, method, u.String(), nil)
		if err != nil {
			return "", err
		}

	default:
		return "", fmt.Errorf("unsupported token_location: %s", tokenLocation)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("remote returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return "", err
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return "", fmt.Errorf("parsing response: %w", err)
	}

	value, exists := data[responseField]
	if !exists {
		return "", fmt.Errorf("response missing field '%s'", responseField)
	}

	return fmt.Sprintf("%v", value), nil
}

// ClearCache removes expired entries from the verification cache.
func (a *Authenticator) ClearCache() {
	a.cacheMu.Lock()
	defer a.cacheMu.Unlock()
	now := time.Now()
	for k, entry := range a.cache {
		if now.After(entry.expiry) {
			delete(a.cache, k)
		}
	}
}

// hashToken produces a fixed-size SHA-256 hex digest of a token string.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// validateEndpointURL resolves the hostname in a URL and rejects private,
// link-local, and loopback addresses to prevent SSRF attacks.
func validateEndpointURL(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("URL has no hostname")
	}

	// Resolve to IP addresses.
	ips, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("DNS resolution failed for %s: %w", host, err)
	}

	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if isBlockedIP(ip) {
			return fmt.Errorf("blocked address %s (resolves from %s)", ipStr, host)
		}
	}

	return nil
}

// isBlockedIP returns true for private, link-local, and loopback addresses.
func isBlockedIP(ip net.IP) bool {
	// RFC 1918 private ranges, loopback, link-local, metadata endpoints.
	blockedRanges := []struct {
		network string
	}{
		{"10.0.0.0/8"},
		{"172.16.0.0/12"},
		{"192.168.0.0/16"},
		{"127.0.0.0/8"},
		{"169.254.0.0/16"}, // Link-local / cloud metadata (AWS, GCP, Azure).
		{"::1/128"},        // IPv6 loopback.
		{"fc00::/7"},       // IPv6 unique local.
		{"fe80::/10"},      // IPv6 link-local.
	}

	for _, b := range blockedRanges {
		_, network, err := net.ParseCIDR(b.network)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// loadPublicKey reads a PEM-encoded public key and returns the parsed key
// and the appropriate signing method.
func loadPublicKey(path string) (interface{}, jwt.SigningMethod, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, nil, fmt.Errorf("no PEM block found in %s", path)
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing public key: %w", err)
	}

	switch k := key.(type) {
	case *rsa.PublicKey:
		slog.Info("loaded RSA public key", "path", path)
		return k, jwt.SigningMethodRS256, nil
	case *ecdsa.PublicKey:
		slog.Info("loaded ECDSA public key", "path", path)
		return k, jwt.SigningMethodES256, nil
	default:
		return nil, nil, fmt.Errorf("unsupported key type: %T", key)
	}
}
