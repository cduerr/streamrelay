package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
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

	// Health check — minimal, for load balancers. No auth required.
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Stats endpoint — detailed, requires auth. If stats_identity is
	// configured, only that identity can access this endpoint.
	mux.HandleFunc("GET /stats", func(w http.ResponseWriter, r *http.Request) {
		rawToken := transport.ExtractToken(r)
		if rawToken == "" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		claims, err := a.Validate(r.Context(), rawToken)
		if err != nil {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		if cfg.Server.StatsIdentity != "" && claims.Identity != cfg.Server.StatsIdentity {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}

		stats := h.Stats()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":           "ok",
			"connections":      stats.Connections,
			"identities":       stats.Identities,
			"messages_dropped": stats.MessagesDropped,
			"clients_dropped":  stats.ClientsDropped,
			"uptime":           time.Since(startTime).String(),
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

	// Middleware chain: CORS → logging → routes.
	// Rate limiting is expected to be handled by the load balancer.
	handler := corsMiddleware(cfg,
		loggingMiddleware(logger, mux),
	)

	return &Server{
		cfg:    cfg,
		hub:    h,
		auth:   a,
		broker: b,
		logger: logger,
		http: &http.Server{
			Addr:              cfg.Addr(),
			Handler:           handler,
			ReadTimeout:       0, // Must be 0 for SSE/WebSocket (long-lived).
			ReadHeaderTimeout: time.Duration(cfg.Server.ReadHeaderTimeoutSeconds) * time.Second,
			WriteTimeout:      0, // Must be 0 for SSE/WebSocket (long-lived).
			IdleTimeout:       time.Duration(cfg.Server.IdleTimeoutSeconds) * time.Second,
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

// --- Middleware ---

// corsMiddleware adds CORS headers based on configured allowed origins.
// Sets Vary: Origin unconditionally so caches don't conflate responses
// for different origins.
func corsMiddleware(cfg *config.Config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Vary", "Origin")

		origin := r.Header.Get("Origin")
		if origin != "" && cfg.IsOriginAllowed(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Refresh-Token")
			w.Header().Set("Access-Control-Max-Age", "86400")
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
