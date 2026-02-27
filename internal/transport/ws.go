package transport

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/gorilla/websocket"

	"github.com/streamrelay/streamrelay/internal/auth"
	"github.com/streamrelay/streamrelay/internal/broker"
	"github.com/streamrelay/streamrelay/internal/config"
	"github.com/streamrelay/streamrelay/internal/hub"
)

// WSHandler handles WebSocket connections.
type WSHandler struct {
	hub      *hub.Hub
	auth     *auth.Authenticator
	broker   *broker.RedisBroker
	cfg      config.Config
	logger   *slog.Logger
	upgrader websocket.Upgrader
}

// NewWSHandler creates a handler for WebSocket connections.
func NewWSHandler(h *hub.Hub, a *auth.Authenticator, b *broker.RedisBroker, cfg config.Config, logger *slog.Logger) *WSHandler {
	return &WSHandler{
		hub:    h,
		auth:   a,
		broker: b,
		cfg:    cfg,
		logger: logger,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				origin := r.Header.Get("Origin")
				if origin == "" {
					return true // Non-browser clients.
				}
				return cfg.IsOriginAllowed(origin)
			},
		},
	}
}

// ServeHTTP handles an incoming WebSocket upgrade request.
func (ws *WSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Authenticate before upgrading.
	rawToken := ExtractToken(r)
	if rawToken == "" {
		http.Error(w, `{"error":"missing token"}`, http.StatusUnauthorized)
		return
	}

	claims, err := ws.auth.Validate(r.Context(), rawToken)
	if err != nil {
		ws.logger.Warn("WebSocket auth failed", "error", err, "remote", r.RemoteAddr)
		http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
		return
	}

	// Extract refresh token from header only (never query param for security).
	refreshToken := r.Header.Get("X-Refresh-Token")

	// Upgrade to WebSocket.
	conn, err := ws.upgrader.Upgrade(w, r, nil)
	if err != nil {
		ws.logger.Error("WebSocket upgrade failed", "error", err)
		return
	}
	defer conn.Close()

	conn.SetReadLimit(int64(ws.cfg.Server.MaxMessageSizeBytes))

	// Register the client.
	client := ws.hub.NewClient(claims.Identity, "websocket", claims, refreshToken)
	if err := ws.hub.Register(client); err != nil {
		ws.logger.Warn("WebSocket registration denied", "identity", claims.Identity, "error", err)
		conn.WriteJSON(map[string]string{"error": "too many connections"})
		return
	}
	defer ws.hub.Unregister(client)

	ws.logger.Info("WebSocket connection established",
		"client_id", client.ID,
		"identity", claims.Identity,
		"remote", r.RemoteAddr,
	)

	// Send initial connected message.
	conn.WriteJSON(map[string]string{
		"event":    "connected",
		"identity": claims.Identity,
	})

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Read pump: client -> Redis (inbound messages).
	go ws.readPump(ctx, cancel, conn, client)

	// Write pump: hub -> client (outbound messages).
	ws.writePump(ctx, conn, client)
}

// readPump reads messages from the WebSocket and publishes them to Redis.
func (ws *WSHandler) readPump(ctx context.Context, cancel context.CancelFunc, conn *websocket.Conn, client *hub.Client) {
	defer cancel()

	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				ws.logger.Debug("WebSocket read error", "client_id", client.ID, "error", err)
			}
			return
		}

		// Publish inbound message to Redis if configured.
		inboundChannel := ws.cfg.InboundChannelForIdentity(client.Identity)
		if inboundChannel == "" {
			ws.logger.Debug("inbound message dropped (inbound_prefix not configured)",
				"client_id", client.ID,
			)
			continue
		}

		if err := ws.broker.Publish(ctx, inboundChannel, message); err != nil {
			ws.logger.Error("failed to publish inbound message",
				"client_id", client.ID,
				"channel", inboundChannel,
				"error", err,
			)
		} else {
			ws.logger.Debug("inbound message published",
				"client_id", client.ID,
				"channel", inboundChannel,
				"size", len(message),
			)
		}
	}
}

// writePump writes messages from the hub to the WebSocket connection.
func (ws *WSHandler) writePump(ctx context.Context, conn *websocket.Conn, client *hub.Client) {
	pingTicker := time.NewTicker(30 * time.Second)
	defer pingTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			conn.WriteMessage(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			return

		case <-client.Done():
			conn.WriteMessage(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, "session expired"))
			return

		case msg, ok := <-client.Send:
			if !ok {
				conn.WriteMessage(websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
				return
			}

			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))

			// For WebSocket, send as text (not SSE formatted).
			payload := stripSSEFraming(msg)
			if err := conn.WriteMessage(websocket.TextMessage, payload); err != nil {
				ws.logger.Debug("WebSocket write failed", "client_id", client.ID, "error", err)
				return
			}

		case <-pingTicker.C:
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// stripSSEFraming removes SSE event/data framing from a message
// so WebSocket clients get clean JSON payloads.
func stripSSEFraming(msg []byte) []byte {
	s := string(msg)
	if len(s) < 5 {
		return msg
	}

	var payload string
	lines := splitLines(s)
	for _, line := range lines {
		if len(line) > 6 && line[:6] == "data: " {
			if payload != "" {
				payload += "\n"
			}
			payload += line[6:]
		}
	}

	if payload == "" {
		return msg
	}
	return []byte(payload)
}

// splitLines splits a string by newlines, handling \r\n and \n.
func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			line := s[start:i]
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			lines = append(lines, line)
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}
