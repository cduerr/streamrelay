package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/streamrelay/streamrelay/internal/auth"
	"github.com/streamrelay/streamrelay/internal/broker"
	"github.com/streamrelay/streamrelay/internal/config"
	"github.com/streamrelay/streamrelay/internal/hub"
	"github.com/streamrelay/streamrelay/internal/transport"
)

// Server wraps the HTTP server and all dependencies.
type Server struct {
	cfg    *config.Config
	hub    *hub.Hub
	auth   *auth.Authenticator
	broker *broker.RedisBroker
	http   *http.Server
	logger *slog.Logger
}

// New creates a fully wired Server ready to start.
func New(cfg *config.Config, h *hub.Hub, a *auth.Authenticator, b *broker.RedisBroker, logger *slog.Logger) *Server {
	mux := http.NewServeMux()

	// Health check — no auth required.
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		total, identities := h.Stats()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":      "ok",
			"connections": total,
			"identities":  identities,
			"uptime":      time.Since(startTime).String(),
		})
	})

	// SSE endpoint.
	if cfg.Transports.SSE {
		sseHandler := transport.NewSSEHandler(h, a, logger)
		mux.Handle("GET /events", sseHandler)
		logger.Info("SSE transport enabled", "path", "/events")
	}

	// WebSocket endpoint.
	if cfg.Transports.WebSocket {
		wsHandler := transport.NewWSHandler(h, a, b, *cfg, logger)
		mux.Handle("GET /ws", wsHandler)
		logger.Info("WebSocket transport enabled", "path", "/ws")
	}

	// Build middleware chain.
	limiter := newIPRateLimiter(cfg.Server.RateLimitPerSecond)
	handler := corsMiddleware(cfg,
		rateLimitMiddleware(limiter, logger,
			loggingMiddleware(logger, mux),
		),
	)

	return &Server{
		cfg:    cfg,
		hub:    h,
		auth:   a,
		broker: b,
		logger: logger,
		http: &http.Server{
			Addr:         cfg.Addr(),
			Handler:      handler,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 0, // SSE/WebSocket connections are long-lived.
			IdleTimeout:  120 * time.Second,
		},
	}
}

var startTime = time.Now()

// Start begins listening for connections. Blocks until the server stops.
func (s *Server) Start() error {
	s.logger.Info("server starting", "addr", s.cfg.Addr())
	return s.http.ListenAndServe()
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("server shutting down")
	return s.http.Shutdown(ctx)
}

// --- Rate Limiter ---

// ipRateLimiter tracks connection attempts per IP using a sliding window.
type ipRateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time
	limit    int
}

func newIPRateLimiter(perSecond int) *ipRateLimiter {
	return &ipRateLimiter{
		requests: make(map[string][]time.Time),
		limit:    perSecond,
	}
}

// Allow checks whether an IP is within its rate limit.
func (rl *ipRateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	window := now.Add(-1 * time.Second)

	// Remove expired entries.
	timestamps := rl.requests[ip]
	valid := timestamps[:0]
	for _, t := range timestamps {
		if t.After(window) {
			valid = append(valid, t)
		}
	}

	if len(valid) >= rl.limit {
		rl.requests[ip] = valid
		return false
	}

	rl.requests[ip] = append(valid, now)
	return true
}

// Cleanup removes stale IPs. Call periodically.
func (rl *ipRateLimiter) Cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	window := time.Now().Add(-1 * time.Second)
	for ip, timestamps := range rl.requests {
		valid := timestamps[:0]
		for _, t := range timestamps {
			if t.After(window) {
				valid = append(valid, t)
			}
		}
		if len(valid) == 0 {
			delete(rl.requests, ip)
		} else {
			rl.requests[ip] = valid
		}
	}
}

// --- Middleware ---

// rateLimitMiddleware rejects requests that exceed the per-IP rate limit.
// Only applies to connection endpoints (/events, /ws), not health checks.
func rateLimitMiddleware(limiter *ipRateLimiter, logger *slog.Logger, next http.Handler) http.Handler {
	// Periodic cleanup of stale entries.
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			limiter.Cleanup()
		}
	}()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only rate-limit connection endpoints.
		if r.URL.Path != "/events" && r.URL.Path != "/ws" {
			next.ServeHTTP(w, r)
			return
		}

		ip := extractIP(r)
		if !limiter.Allow(ip) {
			logger.Warn("rate limit exceeded", "ip", ip, "path", r.URL.Path)
			http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// corsMiddleware adds CORS headers based on configured allowed origins.
func corsMiddleware(cfg *config.Config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		if origin != "" && cfg.IsOriginAllowed(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Refresh-Token")
			w.Header().Set("Access-Control-Max-Age", "86400")
			w.Header().Set("Vary", "Origin")
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// loggingMiddleware logs each request (except high-frequency SSE/WS).
func loggingMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Skip detailed logging for SSE/WS connections (logged elsewhere).
		if r.URL.Path == "/events" || r.URL.Path == "/ws" {
			next.ServeHTTP(w, r)
			return
		}

		next.ServeHTTP(w, r)

		logger.Debug("request",
			"method", r.Method,
			"path", r.URL.Path,
			"remote", r.RemoteAddr,
			"duration", time.Since(start),
		)
	})
}

// extractIP gets the client IP, respecting X-Forwarded-For behind a proxy.
func extractIP(r *http.Request) string {
	// Check X-Forwarded-For first (trusted proxy scenario).
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP (client IP).
		if idx := strings.IndexByte(xff, ','); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	// Fall back to RemoteAddr.
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
