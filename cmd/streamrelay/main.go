package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/streamrelay/streamrelay/internal/auth"
	"github.com/streamrelay/streamrelay/internal/broker"
	"github.com/streamrelay/streamrelay/internal/config"
	"github.com/streamrelay/streamrelay/internal/hub"
	"github.com/streamrelay/streamrelay/internal/server"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to configuration file")
	flag.Parse()

	// Load configuration.
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "configuration error: %v\n", err)
		os.Exit(1)
	}

	// Reject known placeholder secrets.
	if cfg.IsPlaceholderSecret() {
		fmt.Fprintln(os.Stderr, "FATAL: jwt_secret is a placeholder value.")
		fmt.Fprintln(os.Stderr, "Set a strong secret via config or STREAMRELAY_AUTH_JWT_SECRET env var.")
		os.Exit(1)
	}

	// Set up structured logger.
	logger := initLogger(cfg.Logging)
	logger.Info("streamrelay starting",
		"sse", cfg.Transports.SSE,
		"websocket", cfg.Transports.WebSocket,
	)

	// Initialize authenticator.
	authenticator, err := auth.New(cfg.Auth)
	if err != nil {
		logger.Error("failed to initialize auth", "error", err)
		os.Exit(1)
	}
	logger.Info("authenticator initialized",
		"identity_claim", cfg.Auth.IdentityClaim,
		"expected_issuer", cfg.Auth.ExpectedIssuer,
		"expected_audience", cfg.Auth.ExpectedAudience,
		"verify_enabled", cfg.Auth.Verify != nil,
		"refresh_enabled", cfg.Auth.Refresh != nil,
	)

	// Initialize hub.
	h := hub.New(
		cfg.Server.MaxConnectionsPerIdent,
		cfg.Server.MaxConnectionsTotal,
		logger,
	)

	// Initialize Redis broker.
	redisBroker, err := broker.New(cfg.Redis, h, logger)
	if err != nil {
		logger.Error("failed to connect to redis", "error", err)
		os.Exit(1)
	}
	defer redisBroker.Close()

	// Initialize HTTP server.
	srv := server.New(cfg, h, authenticator, redisBroker, logger)

	// Context for coordinating shutdown.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start Redis subscriber in background.
	go func() {
		if err := redisBroker.Run(ctx); err != nil {
			logger.Error("redis broker stopped", "error", err)
		}
	}()

	// Start heartbeat loop in background.
	heartbeatInterval := time.Duration(cfg.Server.HeartbeatSeconds) * time.Second
	go h.RunHeartbeat(ctx, heartbeatInterval, authenticator)

	// Start HTTP server in background.
	errChan := make(chan error, 1)
	go func() {
		errChan <- srv.Start()
	}()

	logger.Info("streamrelay ready", "addr", cfg.Addr())

	// Wait for shutdown signal or server error.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigChan:
		logger.Info("received shutdown signal", "signal", sig)
	case err := <-errChan:
		logger.Error("server error", "error", err)
	}

	// Graceful shutdown.
	cancel() // Stop Redis subscriber and heartbeat.

	shutdownCtx, shutdownCancel := context.WithTimeout(
		context.Background(),
		time.Duration(cfg.Server.ShutdownTimeoutSeconds)*time.Second,
	)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown error", "error", err)
		os.Exit(1)
	}

	logger.Info("streamrelay stopped")
}

func initLogger(cfg config.LoggingConfig) *slog.Logger {
	var level slog.Level
	switch strings.ToLower(cfg.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: level}

	var handler slog.Handler
	if strings.ToLower(cfg.Format) == "json" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}

	return slog.New(handler)
}
