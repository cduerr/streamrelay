package hub

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/streamrelay/streamrelay/internal/auth"
)

// Stats holds a snapshot of hub connection and drop statistics.
type Stats struct {
	Connections     int
	Identities      int
	MessagesDropped int64
	ClientsDropped  int64
}

// Client represents a single connected client (SSE or WebSocket).
type Client struct {
	ID          string
	Identity    string
	RefreshTok  string
	Transport   string // "sse" or "websocket"
	Send        chan []byte
	ConnectedAt time.Time
	done        chan struct{}
	closeOnce   sync.Once

	// claimsMu protects Claims from concurrent read/write between
	// the heartbeat goroutine (which refreshes tokens) and transport
	// goroutines (which may read claims).
	claimsMu sync.RWMutex
	claims   *auth.Claims
}

// NewClient creates a new Client with a buffered send channel.
// The buffer size is determined by the Hub's configured clientBufferSize.
func (h *Hub) NewClient(identity, transport string, claims *auth.Claims, refreshToken string) *Client {
	return &Client{
		ID:          fmt.Sprintf("%s-%s-%d", identity, transport, time.Now().UnixNano()),
		Identity:    identity,
		claims:      claims,
		RefreshTok:  refreshToken,
		Transport:   transport,
		Send:        make(chan []byte, h.clientBufferSize),
		ConnectedAt: time.Now(),
		done:        make(chan struct{}),
	}
}

// GetClaims returns the client's current claims (thread-safe).
func (c *Client) GetClaims() *auth.Claims {
	c.claimsMu.RLock()
	defer c.claimsMu.RUnlock()
	return c.claims
}

// SetClaims updates the client's claims (thread-safe).
func (c *Client) SetClaims(claims *auth.Claims) {
	c.claimsMu.Lock()
	defer c.claimsMu.Unlock()
	c.claims = claims
}

// Done returns a channel that is closed when the client is closed.
func (c *Client) Done() <-chan struct{} {
	return c.done
}

// Close marks the client as done and closes the send channel.
// Safe to call multiple times.
func (c *Client) Close() {
	c.closeOnce.Do(func() {
		close(c.done)
		close(c.Send)
	})
}

// Hub manages all active client connections, grouped by identity.
// It handles registration, unregistration, fan-out, and per-identity limits.
type Hub struct {
	mu               sync.RWMutex
	clients          map[string]map[*Client]struct{} // identity -> set of clients
	maxPerIdentity   int
	maxTotal         int
	clientBufferSize int
	dropNewest       bool // true = drop message on full buffer; false = drop client
	totalConnections int

	messagesDropped atomic.Int64
	clientsDropped  atomic.Int64

	logger *slog.Logger
}

// New creates a Hub with the given connection limits, client buffer size,
// and slow consumer policy ("drop_client" or "drop_newest_message").
func New(maxPerIdentity, maxTotal, clientBufferSize int, slowConsumerPolicy string, logger *slog.Logger) *Hub {
	return &Hub{
		clients:          make(map[string]map[*Client]struct{}),
		maxPerIdentity:   maxPerIdentity,
		maxTotal:         maxTotal,
		clientBufferSize: clientBufferSize,
		dropNewest:       slowConsumerPolicy == "drop_newest_message",
		logger:           logger,
	}
}

// Register adds a client to the hub.
// Returns an error if connection limits would be exceeded.
func (h *Hub) Register(client *Client) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Check total limit.
	if h.maxTotal > 0 && h.totalConnections >= h.maxTotal {
		return fmt.Errorf("server connection limit reached (%d)", h.maxTotal)
	}

	// Check per-identity limit.
	identClients := h.clients[client.Identity]
	if h.maxPerIdentity > 0 && len(identClients) >= h.maxPerIdentity {
		return fmt.Errorf("connection limit per identity reached (%d)", h.maxPerIdentity)
	}

	// Register.
	if identClients == nil {
		h.clients[client.Identity] = make(map[*Client]struct{})
	}
	h.clients[client.Identity][client] = struct{}{}
	h.totalConnections++

	h.logger.Info("client registered",
		"client_id", client.ID,
		"identity", client.Identity,
		"transport", client.Transport,
		"identity_connections", len(h.clients[client.Identity]),
		"total_connections", h.totalConnections,
	)

	return nil
}

// Unregister removes a client from the hub and closes it.
func (h *Hub) Unregister(client *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()

	identClients, exists := h.clients[client.Identity]
	if !exists {
		return
	}

	if _, ok := identClients[client]; !ok {
		return
	}

	delete(identClients, client)
	h.totalConnections--

	if len(identClients) == 0 {
		delete(h.clients, client.Identity)
	}

	client.Close()

	h.logger.Info("client unregistered",
		"client_id", client.ID,
		"identity", client.Identity,
		"transport", client.Transport,
		"total_connections", h.totalConnections,
	)
}

// Send delivers a message to all clients with the given identity.
// When a client's buffer is full, behavior depends on the slow consumer
// policy: drop_client disconnects the client; drop_newest_message silently
// discards the message for that client.
func (h *Hub) Send(identity string, data []byte) {
	h.mu.RLock()
	identClients, exists := h.clients[identity]
	if !exists {
		h.mu.RUnlock()
		return
	}

	// Snapshot the client set to avoid holding the lock during sends.
	clients := make([]*Client, 0, len(identClients))
	for c := range identClients {
		clients = append(clients, c)
	}
	h.mu.RUnlock()

	for _, c := range clients {
		select {
		case c.Send <- data:
			// Delivered.
		default:
			if h.dropNewest {
				h.messagesDropped.Add(1)
			} else {
				h.clientsDropped.Add(1)
				h.Unregister(c)
			}
		}
	}
}

// Broadcast delivers a message to ALL connected clients.
func (h *Hub) Broadcast(data []byte) {
	h.mu.RLock()
	identities := make([]string, 0, len(h.clients))
	for identity := range h.clients {
		identities = append(identities, identity)
	}
	h.mu.RUnlock()

	for _, identity := range identities {
		h.Send(identity, data)
	}
}

// ClientsForIdentity returns all active clients for an identity.
func (h *Hub) ClientsForIdentity(identity string) []*Client {
	h.mu.RLock()
	defer h.mu.RUnlock()

	identClients, exists := h.clients[identity]
	if !exists {
		return nil
	}

	clients := make([]*Client, 0, len(identClients))
	for c := range identClients {
		clients = append(clients, c)
	}
	return clients
}

// ActiveIdentities returns the set of currently connected identities.
func (h *Hub) ActiveIdentities() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	ids := make([]string, 0, len(h.clients))
	for id := range h.clients {
		ids = append(ids, id)
	}
	return ids
}

// Stats returns current connection and drop statistics.
func (h *Hub) Stats() Stats {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return Stats{
		Connections:     h.totalConnections,
		Identities:      len(h.clients),
		MessagesDropped: h.messagesDropped.Load(),
		ClientsDropped:  h.clientsDropped.Load(),
	}
}

// RunHeartbeat periodically sends heartbeat events to all clients
// and checks token expiry. Blocks until context is cancelled.
func (h *Hub) RunHeartbeat(ctx context.Context, interval time.Duration, authenticator *auth.Authenticator) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	heartbeatMsg := []byte("event: heartbeat\ndata: {}\n\n")

	var lastMsgDropped, lastCliDropped int64

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.mu.RLock()
			var allClients []*Client
			for _, identClients := range h.clients {
				for c := range identClients {
					allClients = append(allClients, c)
				}
			}
			h.mu.RUnlock()

			var expired []*Client
			for _, c := range allClients {
				claims := c.GetClaims()
				if authenticator.IsExpired(claims) {
					if authenticator.RefreshEnabled() && c.RefreshTok != "" {
						newToken, err := authenticator.Refresh(ctx, c.RefreshTok)
						if err != nil {
							h.logger.Warn("token refresh failed, expiring client",
								"client_id", c.ID,
								"identity", c.Identity,
								"error", err,
							)
							expired = append(expired, c)
							continue
						}

						newClaims, err := authenticator.Validate(ctx, newToken)
						if err != nil {
							h.logger.Warn("refreshed token invalid, expiring client",
								"client_id", c.ID,
								"error", err,
							)
							expired = append(expired, c)
							continue
						}

						c.SetClaims(newClaims)
						h.logger.Debug("token refreshed",
							"client_id", c.ID,
							"identity", c.Identity,
						)
					} else {
						expired = append(expired, c)
					}
				} else {
					// Send heartbeat.
					select {
					case c.Send <- heartbeatMsg:
					default:
						// Buffer full, will be caught by slow consumer logic.
					}
				}
			}

			// Notify and remove expired clients.
			expiredMsg := []byte("event: auth_expired\ndata: {\"message\":\"token expired, reconnect with fresh token\"}\n\n")
			for _, c := range expired {
				h.logger.Info("expiring client due to token expiry",
					"client_id", c.ID,
					"identity", c.Identity,
				)
				select {
				case c.Send <- expiredMsg:
				default:
				}
				go func(client *Client) {
					time.Sleep(100 * time.Millisecond)
					h.Unregister(client)
				}(c)
			}

			// Periodic cache cleanup.
			authenticator.ClearCache()

			// Log drop deltas since last tick.
			msgDropped := h.messagesDropped.Load()
			cliDropped := h.clientsDropped.Load()
			if deltaMsgs, deltaClis := msgDropped-lastMsgDropped, cliDropped-lastCliDropped; deltaMsgs > 0 || deltaClis > 0 {
				h.logger.Warn("drops since last heartbeat",
					"messages_dropped", deltaMsgs,
					"clients_dropped", deltaClis,
				)
			}
			lastMsgDropped = msgDropped
			lastCliDropped = cliDropped
		}
	}
}
