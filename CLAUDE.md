# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

StreamRelay is a stateless JWT-authenticated Redis-to-SSE/WebSocket relay written in Go 1.22. Backends publish to Redis channels keyed by user identity; StreamRelay routes messages to that user's connected browsers/devices. It knows nothing about the application — it's pure plumbing.

## General Notes

Please take no action (file changes or commands) unless requested to do so. If unsure, simply confirm with me.

### Git

Git is managed by me. You never use git, period.

## Build & Run

```bash
# Build both binaries
./compile.sh

# Or individually
go build -o streamrelay ./cmd/streamrelay
go build -o gentoken ./scripts/gentoken

# Run (requires Redis and a config with a real JWT secret)
./streamrelay --config config.yaml

# Docker
docker compose up

# Generate a test token
go run ./scripts/gentoken --identity 42 --secret <your-jwt-secret>
```

## Architecture

**Dependency flow** (outer depends on inner, never reverse):

```
main → server → transport → hub, auth, broker → config
```

- **config** — YAML loading, validation, defaults, env overrides. Depends on nothing.
- **auth** — JWT validation (local), optional remote verification + token refresh. Has an in-memory LRU cache for verification results.
- **hub** — In-memory connection map (`identity → set of *Client`). Handles registration, fan-out, slow consumer policy, heartbeat/token-expiry loop. Each client has a buffered `Send` channel.
- **broker** — Redis pub/sub. Single `PSUBSCRIBE` on `{prefix}:*`, extracts identity from channel name, calls `hub.Send()`. Also handles `Publish()` for WebSocket inbound relay.
- **transport** — SSE and WebSocket HTTP handlers. Each creates a `Client` via the hub, registers it, then runs a read/write loop.
- **server** — Wires HTTP routes, CORS middleware, logging middleware. Constructs `http.Server`.
- **cmd/streamrelay/main.go** — Initializes all components, starts goroutines (Redis subscriber, heartbeat, HTTP server), handles graceful shutdown on SIGINT/SIGTERM.

## Key Design Decisions

- **One Redis subscription** for all clients (pattern subscribe). No per-identity subscribe/unsubscribe.
- **Non-blocking fan-out** — `hub.Send()` uses `select` with `default` case. Slow consumers either get their message dropped or get disconnected, depending on `slow_consumer_policy`.
- **Stateless instances** — No shared in-memory state. Horizontal scaling works by running multiple instances behind a load balancer, all subscribed to the same Redis. No sticky sessions needed.
- **SSE framing is canonical** — Messages are stored/relayed in SSE format (`event: message\ndata: ...\n\n`). WebSocket transport strips the SSE framing before sending to clients.

## Conventions (from CONVENTIONS.md)

- **Errors**: Always wrap with context via `fmt.Errorf("doing thing: %w", err)`. Sentinel errors for categories.
- **Concurrency**: `sync.RWMutex` for shared state, `sync.Once` for cleanup, channels for communication. Always pass `context.Context` first for I/O functions.
- **Logging**: `log/slog` only (stdlib). Pass `*slog.Logger` as dependency. Structured fields, not sprintf.
- **HTTP**: Go 1.22+ routing (`"GET /health"`). JSON error bodies `{"error": "..."}`. Handlers implement `http.Handler`.
- **Config**: All loaded at startup from YAML. Env vars override secrets. Validate at startup, fail fast.
- **Deps**: Minimal. Only four direct: `golang-jwt`, `gorilla/websocket`, `go-redis`, `yaml.v3`.
- **Build**: Single static binary, `CGO_ENABLED=0`. Multi-stage Docker (golang:1.22-alpine → alpine:3.19).
