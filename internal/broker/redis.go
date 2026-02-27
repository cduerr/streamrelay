package broker

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/streamrelay/streamrelay/internal/config"
	"github.com/streamrelay/streamrelay/internal/hub"
)

// RedisBroker manages a single Redis pub/sub connection and routes
// incoming messages to the appropriate clients via the hub.
type RedisBroker struct {
	client        *redis.Client
	hub           *hub.Hub
	cfg           config.RedisConfig
	channelPrefix string
	logger        *slog.Logger
}

// New creates a RedisBroker connected to the configured Redis instance.
func New(cfg config.RedisConfig, h *hub.Hub, logger *slog.Logger) (*RedisBroker, error) {
	opts, err := redis.ParseURL(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("parsing redis URL: %w", err)
	}

	if cfg.Password != "" {
		opts.Password = cfg.Password
	}
	opts.DB = cfg.DB

	client := redis.NewClient(opts)

	// Verify connectivity.
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.PingTimeoutSeconds)*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis ping failed: %w", err)
	}

	logger.Info("connected to redis", "url", cfg.URL, "db", cfg.DB)

	return &RedisBroker{
		client:        client,
		hub:           h,
		cfg:           cfg,
		channelPrefix: cfg.ChannelPrefix,
		logger:        logger,
	}, nil
}

// Run subscribes to the channel pattern and routes messages to the hub.
// Blocks until context is cancelled. Automatically reconnects on failure.
func (b *RedisBroker) Run(ctx context.Context) error {
	pattern := fmt.Sprintf("%s:*", b.channelPrefix)
	b.logger.Info("subscribing to redis pattern", "pattern", pattern)

	for {
		err := b.subscribe(ctx, pattern)
		if ctx.Err() != nil {
			// Context cancelled — clean shutdown.
			return nil
		}

		delay := time.Duration(b.cfg.ReconnectDelaySeconds) * time.Second
		b.logger.Error("redis subscription lost, reconnecting",
			"error", err,
			"delay", delay,
		)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay):
			// Retry.
		}
	}
}

// subscribe manages a single pub/sub subscription lifecycle.
func (b *RedisBroker) subscribe(ctx context.Context, pattern string) error {
	pubsub := b.client.PSubscribe(ctx, pattern)
	defer pubsub.Close()

	// Wait for subscription confirmation.
	_, err := pubsub.Receive(ctx)
	if err != nil {
		return fmt.Errorf("subscription failed: %w", err)
	}

	b.logger.Info("redis subscription active", "pattern", pattern)

	ch := pubsub.Channel()
	for {
		select {
		case <-ctx.Done():
			return nil

		case msg, ok := <-ch:
			if !ok {
				return fmt.Errorf("redis channel closed")
			}

			// Extract identity from channel name.
			// Channel format: "{prefix}:{identity}"
			identity := b.extractIdentity(msg.Channel)
			if identity == "" {
				b.logger.Warn("could not extract identity from channel",
					"channel", msg.Channel,
				)
				continue
			}

			// Format as SSE event and deliver to hub.
			sseData := formatSSE(msg.Payload)
			b.hub.Send(identity, sseData)

			b.logger.Debug("relayed message",
				"channel", msg.Channel,
				"identity", identity,
				"size", len(msg.Payload),
			)
		}
	}
}

// Publish sends a message to a Redis channel. Used for WebSocket inbound
// message relay.
func (b *RedisBroker) Publish(ctx context.Context, channel string, data []byte) error {
	return b.client.Publish(ctx, channel, data).Err()
}

// Close cleanly shuts down the Redis connection.
func (b *RedisBroker) Close() error {
	return b.client.Close()
}

// extractIdentity parses the identity from a Redis channel name.
// Given "streams:42", returns "42".
func (b *RedisBroker) extractIdentity(channel string) string {
	prefix := b.channelPrefix + ":"
	if !strings.HasPrefix(channel, prefix) {
		return ""
	}
	return strings.TrimPrefix(channel, prefix)
}

// formatSSE wraps a payload as a Server-Sent Event message.
func formatSSE(payload string) []byte {
	// SSE format:
	//   event: message\n
	//   data: {payload}\n
	//   \n
	var b strings.Builder
	b.WriteString("event: message\n")

	// Handle multi-line payloads (each line needs its own "data:" prefix).
	lines := strings.Split(payload, "\n")
	for _, line := range lines {
		b.WriteString("data: ")
		b.WriteString(line)
		b.WriteByte('\n')
	}
	b.WriteByte('\n')

	return []byte(b.String())
}
