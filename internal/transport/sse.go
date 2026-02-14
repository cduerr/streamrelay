package transport

import (
	"log/slog"
	"net/http"

	"github.com/streamrelay/streamrelay/internal/auth"
	"github.com/streamrelay/streamrelay/internal/hub"
)

// SSEHandler handles Server-Sent Event connections.
type SSEHandler struct {
	hub    *hub.Hub
	auth   *auth.Authenticator
	logger *slog.Logger
}

// NewSSEHandler creates a handler for SSE connections.
func NewSSEHandler(h *hub.Hub, a *auth.Authenticator, logger *slog.Logger) *SSEHandler {
	return &SSEHandler{
		hub:    h,
		auth:   a,
		logger: logger,
	}
}

// ServeHTTP handles an incoming SSE connection request.
func (s *SSEHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Authenticate.
	rawToken := extractToken(r)
	if rawToken == "" {
		http.Error(w, `{"error":"missing token"}`, http.StatusUnauthorized)
		return
	}

	claims, err := s.auth.Validate(r.Context(), rawToken)
	if err != nil {
		s.logger.Debug("SSE auth failed", "error", err, "remote", r.RemoteAddr)
		http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
		return
	}

	// Extract optional refresh token.
	refreshToken := r.URL.Query().Get("refresh_token")
	if refreshToken == "" {
		refreshToken = r.Header.Get("X-Refresh-Token")
	}

	// Check that response supports flushing.
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, `{"error":"streaming not supported"}`, http.StatusInternalServerError)
		return
	}

	// Register the client.
	client := hub.NewClient(claims.Identity, "sse", claims, refreshToken)
	if err := s.hub.Register(client); err != nil {
		s.logger.Warn("SSE registration denied", "identity", claims.Identity, "error", err)
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusTooManyRequests)
		return
	}
	defer s.hub.Unregister(client)

	// Set SSE headers.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // Disable nginx buffering.

	// Send initial connected event.
	connected := "event: connected\ndata: {\"identity\":\"" + claims.Identity + "\"}\n\n"
	w.Write([]byte(connected))
	flusher.Flush()

	s.logger.Info("SSE connection established",
		"client_id", client.ID,
		"identity", claims.Identity,
		"remote", r.RemoteAddr,
	)

	// Stream events until client disconnects or is closed.
	for {
		select {
		case <-r.Context().Done():
			// Client disconnected.
			s.logger.Debug("SSE client disconnected", "client_id", client.ID)
			return

		case <-client.Done():
			// Server closed the client (e.g., token expiry).
			s.logger.Debug("SSE client closed by server", "client_id", client.ID)
			return

		case msg, ok := <-client.Send:
			if !ok {
				// Channel closed.
				return
			}
			if _, err := w.Write(msg); err != nil {
				s.logger.Debug("SSE write failed", "client_id", client.ID, "error", err)
				return
			}
			flusher.Flush()
		}
	}
}
