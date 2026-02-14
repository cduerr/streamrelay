# Go Conventions & Best Practices

This document captures the conventions used in this project and serves as a
reference for contributors and LLMs working on the codebase.

## Project Structure

```
cmd/            Entry points. Each subdirectory is a main package.
internal/       Private packages. Cannot be imported by external modules.
scripts/        CLI tools and utilities (also Go main packages).
```

The `internal/` layout uses domain-oriented packages:
- `config` — configuration loading, validation, defaults
- `auth` — authentication (JWT, remote verification, refresh)
- `hub` — connection management, fan-out, client lifecycle
- `broker` — Redis pub/sub (the only Redis-aware package)
- `transport` — HTTP handlers (SSE, WebSocket)
- `server` — HTTP server wiring, middleware, routing

## Dependency Flow

Dependencies flow inward. Outer packages depend on inner, never the reverse.

```
main → server → transport → hub, auth, broker → config
```

- `config` depends on nothing (only stdlib + yaml)
- `auth` depends on `config`
- `hub` depends on `auth` (for token expiry checks)
- `broker` depends on `config`, `hub`
- `transport` depends on `auth`, `hub`, `broker`, `config`
- `server` depends on everything (wiring layer)
- `main` depends on everything (initialization)

## Error Handling

- Always wrap errors with context: `fmt.Errorf("doing thing: %w", err)`
- Define sentinel errors for categories: `var ErrInvalidToken = errors.New(...)`
- Never ignore errors silently. Log them if they can't be returned.
- Use `errors.Is()` and `errors.As()` for error checking, never string comparison.

```go
// Good
if err := doThing(); err != nil {
    return fmt.Errorf("processing request: %w", err)
}

// Bad
if err := doThing(); err != nil {
    return err  // No context about where this happened.
}
```

## Concurrency

- Protect shared state with `sync.RWMutex`. Read-lock for reads, write-lock for writes.
- Prefer channels for communication, mutexes for state protection.
- Always use `sync.Once` for one-time cleanup (e.g., `Client.Close()`).
- Pass `context.Context` as the first parameter to any function that does I/O or may block.
- Check `ctx.Done()` in loops and select statements.

```go
// Good
func (h *Hub) Send(identity string, data []byte) {
    h.mu.RLock()
    // ... snapshot under lock ...
    h.mu.RUnlock()
    // ... do work outside lock ...
}
```

## Logging

- Use `log/slog` (Go 1.21+ stdlib). No third-party logging libraries.
- Pass `*slog.Logger` as a dependency, never use the global logger.
- Use structured fields, not string formatting:

```go
// Good
logger.Info("client registered", "identity", id, "transport", "sse")

// Bad
logger.Info(fmt.Sprintf("client %s registered via %s", id, "sse"))
```

- Log levels:
  - `Debug` — per-message relay, internal state changes
  - `Info` — connections, disconnections, startup, shutdown
  - `Warn` — slow consumers dropped, token refresh failures
  - `Error` — Redis failures, unrecoverable errors

## Configuration

- All config is loaded from YAML at startup. No runtime config changes.
- Environment variables override config file values for secrets.
- Validate all config at startup. Fail fast with clear messages.
- Provide sensible defaults for everything except secrets.

## HTTP Handlers

- Use Go 1.22+ enhanced routing patterns: `mux.HandleFunc("GET /health", ...)`
- Handlers implement `http.Handler` interface for testability.
- Extract auth tokens from both `Authorization: Bearer` header and `?token=` query param.
- Always set `Content-Type` headers explicitly.
- Return JSON error bodies: `{"error": "description"}`

## Testing (Conventions for Future Tests)

- Table-driven tests for functions with multiple cases.
- Use `httptest.NewServer` for handler tests.
- Mock Redis with an interface if needed, but prefer integration tests with a real Redis.
- Test files live next to the code they test: `auth.go` → `auth_test.go`

## Dependencies

- Minimize external dependencies. Prefer stdlib where reasonable.
- Current external deps:
  - `github.com/golang-jwt/jwt/v5` — JWT parsing/validation
  - `github.com/gorilla/websocket` — WebSocket upgrade and I/O
  - `github.com/redis/go-redis/v9` — Redis client with pub/sub
  - `gopkg.in/yaml.v3` — YAML config parsing

## Build & Deploy

- Single static binary. No CGO. `CGO_ENABLED=0 go build ...`
- Multi-stage Docker build: compile in `golang:1.22-alpine`, run in `alpine:3.19`.
- Binary includes no config — config is mounted or passed via environment.
- Health check at `GET /health` returns connection stats.
