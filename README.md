# StreamRelay

A generic, scalable JWT-authenticated Redis-to-SSE/WebSocket relay. 
One persistent connection per client. 

StreamRelay doesn't know anything about your application. 
It validates JWTs, extracts an identity, subscribes to a Redis 
channel for that identity, and relays messages. Your backend 
publishes, your frontend receives. StreamRelay is just plumbing.

## Disclaimer

Not peer-reviewed. Not tested at scale. Use at your own risk.

## Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Service A   │     │  Service B   │     │  Service C   │
│ (API server) │     │ (ML pipeline)│     │ (Chat bot)   │
└──────┬───────┘     └───────┬──────┘     └──────┬───────┘
       │ PUBLISH             │ PUBLISH           │ PUBLISH
       │ streams:42          │ streams:42        │ streams:42
       ▼                     ▼                     ▼
┌─────────────────────────────────────────────────────────┐
│                         Redis                           │
│                    (pub/sub channels)                   │
└────────────────────────┬────────────────────────────────┘
                         │ ONE subscription
                         │ pattern: streams:*
                         ▼
┌─────────────────────────────────────────────────────────┐
│                     StreamRelay                         │
│                                                         │
│  ┌─────────────────────────────────────┐                │
│  │  Connection Map (in-memory)         │                │
│  │  "42" → [client_a, client_b]        │                │
│  │  "99" → [client_c]                  │                │
│  └─────────────────────────────────────┘                │
│                                                         │
│  Validates JWT → extracts identity → routes events      │
└───────┬─────────────────────────────────┬───────────────┘
        │ SSE                             │ WebSocket
        ▼                                 ▼
   ┌─────────┐                       ┌─────────┐
   │ Browser │                       │ Browser │
   │ (user 4)│                       │ (user 4)│
   └─────────┘                       └─────────┘
```

**Key design decisions:**
- **One Redis subscription** for all clients (pattern subscribe on `{prefix}:*`)
- **In-memory fan-out** — Redis message arrives, lookup identity in a map, push to matching connections
- **One connection per client** — multiplexes all event types (progress, chat, notifications) over a single SSE or WebSocket connection
- **Auth via JWT** — validated locally (no network call). Optional remote verification and automatic token refresh.
- **Your backend publishes to `streams:{user_id}`** — StreamRelay never decides who sees what. Your application logic controls that.

## Quick Start

### 1. Clone and configure

```bash
git clone https://github.com/streamrelay/streamrelay.git
cd streamrelay
cp config.example.yaml config.yaml
# Edit config.yaml — at minimum, set auth.jwt_secret (32+ characters)
```

### 2. Run with Docker Compose

```bash
docker compose up
```

This starts StreamRelay on port 8080 and Redis on port 6379.

### 3. Generate a test token

```bash
# Using the included tool
go run ./scripts/gentoken --identity 42 --secret your-jwt-secret

# Or with Docker
docker compose exec streamrelay gentoken --identity 42 --secret your-jwt-secret
```

### 4. Connect as a client

**SSE (browser):**
```javascript
const token = "eyJ...";
const events = new EventSource(`http://localhost:8080/events?token=${token}`);

events.addEventListener("connected", (e) => {
  console.log("Connected:", JSON.parse(e.data));
});

events.addEventListener("message", (e) => {
  const payload = JSON.parse(e.data);
  console.log("Event:", payload);
});

events.addEventListener("auth_expired", (e) => {
  console.log("Token expired, reconnecting...");
  events.close();
  // Refresh token and reconnect.
});
```

**WebSocket (browser):**
```javascript
const token = "eyJ...";
const ws = new WebSocket(`ws://localhost:8080/ws?token=${token}`);

ws.onmessage = (e) => {
  const payload = JSON.parse(e.data);
  console.log("Event:", payload);
};

// Send a message (published to Redis at inbound:{identity})
ws.send(JSON.stringify({ type: "chat", message: "Hello!" }));
```

### 5. Publish an event

From any service that has Redis access:

**Python:**
```python
import redis
import json

r = redis.Redis()
r.publish("streams:42", json.dumps({
    "type": "notification",
    "title": "Processing complete",
    "media_id": 123
}))
```

**Go:**
```go
rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
rdb.Publish(ctx, "streams:42", `{"type":"progress","pct":75}`)
```

**CLI:**
```bash
redis-cli PUBLISH streams:42 '{"type":"ping","message":"hello"}'
```

The event appears instantly in the connected client's SSE stream or WebSocket.

## Configuration Reference

StreamRelay is configured via a YAML file (default: `config.yaml`). Secrets can be overridden via environment variables.

### `server`

| Key | Default | Description |
|-----|---------|-------------|
| `host` | `0.0.0.0` | Bind address |
| `port` | `8080` | Listen port |
| `heartbeat_seconds` | `30` | Interval for keepalive pings and token expiry checks |
| `max_connections_total` | `0` | Max concurrent connections (0 = unlimited) |
| `max_connections_per_identity` | `0` | Max connections per user (0 = unlimited) |
| `max_message_size_bytes` | `4096` | Max inbound WebSocket message size |
| `client_buffer_size` | `64` | Per-client send buffer (number of messages). When full, `slow_consumer_policy` determines behavior. |
| `slow_consumer_policy` | `drop_newest_message` | What happens when a client's buffer is full: `drop_newest_message` discards the message silently; `drop_client` disconnects the slow client. |
| `websocket_ping_seconds` | `30` | Seconds between WebSocket ping frames. Dead connections are detected after two missed pongs. |
| `websocket_write_timeout_ms` | `10000` | Max time in milliseconds for a WebSocket write to complete before the connection is closed. |
| `shutdown_timeout_seconds` | `10` | Graceful shutdown timeout |
| `allowed_origins` | `[]` | CORS allowed origins. Empty rejects all cross-origin requests. Use `["*"]` to allow all (not recommended). |
| `stats_identity` | — | If set, only this identity can access `/stats`. When empty, any authenticated user can access it. |

### `auth`

| Key | Default | Description |
|-----|---------|-------------|
| `jwt_secret` | — | HMAC signing secret, minimum 32 characters (set this OR `jwt_public_key`) |
| `jwt_public_key` | — | Path to PEM public key for RSA/ECDSA |
| `identity_claim` | `sub` | JWT claim used as the user identity. Must contain only alphanumeric, `.`, `-`, `_`. |
| `expected_issuer` | — | If set, reject tokens with a different `iss` claim. Prevents cross-service token reuse. |
| `expected_audience` | — | If set, reject tokens with a different `aud` claim. |
| `require_expiry` | `true` | Reject tokens without an `exp` (expiration) claim. |
| `service_token` | — | Service-to-service auth token. When set, sent as `Authorization: Bearer <token>` on verify/refresh requests. |

**Environment overrides:**
- `STREAMRELAY_AUTH_JWT_SECRET` → `auth.jwt_secret`
- `STREAMRELAY_AUTH_JWT_PUBLIC_KEY` → `auth.jwt_public_key`
- `STREAMRELAY_AUTH_SERVICE_TOKEN` → `auth.service_token`

### `auth.verify` (optional)

Remote token verification. Called in addition to local JWT validation.

| Key | Default | Description |
|-----|---------|-------------|
| `url` | — | Verification endpoint URL |
| `method` | `POST` | HTTP method |
| `token_param` | `token` | Parameter name for the JWT |
| `token_location` | `body` | Where to send the token: `body`, `header`, or `query` |
| `active_field` | `active` | Response JSON field that must be truthy |
| `identity_field` | `sub` | Response JSON field containing the identity |
| `cache_seconds` | `60` | Cache successful verifications for this duration |

### `auth.refresh` (optional)

Automatic token refresh. StreamRelay calls this endpoint proactively before tokens expire, keeping connections alive indefinitely.

| Key | Default | Description |
|-----|---------|-------------|
| `url` | — | Refresh endpoint URL |
| `method` | `POST` | HTTP method |
| `token_param` | `refresh_token` | Parameter name for the refresh token |
| `token_location` | `body` | Where to send the token: `body`, `header`, or `query` |
| `new_token_field` | `access_token` | Response JSON field containing the new JWT |
| `interval_seconds` | `1800` | Refresh this many seconds before expiry |

The client must provide a refresh token on connect via the `X-Refresh-Token` header.

### `redis`

| Key | Default | Description |
|-----|---------|-------------|
| `url` | `redis://localhost:6379` | Redis connection URL |
| `password` | — | Redis password (can also be in URL) |
| `db` | `0` | Redis database number |
| `channel_prefix` | `streams` | Subscribes to `{prefix}:*`, routes to identity |

**Environment overrides:**
- `STREAMRELAY_REDIS_URL` → `redis.url`
- `STREAMRELAY_REDIS_PASSWORD` → `redis.password`

### `transports`

| Key | Default | Description |
|-----|---------|-------------|
| `sse` | `true` | Enable SSE endpoint at `GET /events` |
| `websocket` | `true` | Enable WebSocket endpoint at `GET /ws` |
| `inbound_prefix` | — | Redis channel prefix for WebSocket inbound messages (`{prefix}:{identity}`). Empty or omitted disables inbound publishing. |

### `logging`

| Key | Default | Description |
|-----|---------|-------------|
| `level` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `format` | `text` | Log format: `text` or `json` |

## Endpoints

### `GET /events`

Server-Sent Events stream. Requires JWT authentication.

**Auth:** `Authorization: Bearer <token>` header or `?token=<token>` query param.

**Events:**
| Event | Description |
|-------|-------------|
| `connected` | Sent immediately on successful connection. Data: `{"identity":"42"}` |
| `message` | Application event relayed from Redis. Data: whatever was published. |
| `heartbeat` | Keepalive ping. Data: `{}` |
| `auth_expired` | Token expired, connection will close. Client should refresh and reconnect. |

### `GET /ws`

WebSocket connection. Requires JWT authentication.

**Auth:** `?token=<token>` query param (headers not supported for WebSocket upgrade in browsers).

**Inbound messages** (client → server) are published to Redis at `{inbound_prefix}:{identity}`. Consumers of inbound channels must treat all data as untrusted user input.

**Outbound messages** (server → client) are JSON payloads from Redis (SSE framing is stripped for WebSocket clients).

### `GET /health`

Minimal health check for load balancers. No authentication required.

**Response:**
```json
{"status":"ok"}
```

### `GET /stats`

Detailed connection statistics. Requires JWT authentication. If `stats_identity` is configured, only that identity can access this endpoint.

**Response:**
```json
{
  "status": "ok",
  "connections": 150,
  "identities": 42,
  "uptime": "2h30m15s"
}
```

## Security

- **Tokens are validated locally** — no network calls required for basic auth. The JWT secret/public key is the only shared state between StreamRelay and your auth system.
- **Expiry is required by default** — tokens without an `exp` claim are rejected. Prevents immortal tokens from circulating.
- **Users cannot subscribe to other users' channels.** The channel is derived from the JWT identity claim, never from user input.
- **Identity claims are validated** — only alphanumeric characters, dots, hyphens, and underscores are accepted. This prevents Redis channel injection.
- **Issuer/audience validation** — optionally reject tokens not minted for this service, preventing cross-service token reuse.
- **SSRF protection** — remote verify/refresh endpoint URLs are validated at startup, blocking private, link-local, and loopback addresses.
- **WebSocket inbound messages are published to a separate channel prefix** (`inbound:`) so they cannot interfere with outbound events.
- **Connection limits** prevent a single user from exhausting server resources.
- **CORS is locked down by default** — no origins are allowed unless explicitly configured.

### Token-in-URL Considerations

The SSE `EventSource` API does not support custom headers, so `?token=` query params are unavoidable for SSE. Be aware that URL query parameters may appear in load balancer access logs, browser history, and Referer headers. For production: configure your reverse proxy to strip or redact the `token` query parameter from access logs, use short-lived tokens, and use the refresh mechanism to limit exposure. Refresh tokens are accepted via the `X-Refresh-Token` header only, never via query parameter.

### Production Recommendations

- **TLS is required.** Run behind a reverse proxy (nginx, Caddy, Traefik) that handles TLS termination. Configure rate limiting at the load balancer level.
- Set `jwt_secret` via `STREAMRELAY_AUTH_JWT_SECRET` environment variable, not in the config file. Minimum 32 characters.
- Configure `expected_issuer` and/or `expected_audience` if the signing key is shared with other services.
- Configure `allowed_origins` to your frontend domain(s).
- Configure `max_connections_per_identity` (e.g., 5) to prevent abuse.
- Use `logging.format: json` for structured log aggregation.
- Monitor the `/health` endpoint for load balancer checks. Use `/stats` (authenticated) for operational monitoring.
- Set appropriate file descriptor limits on the host (`ulimit -n 65536`).
- Strip or redact `token` query parameters from reverse proxy access logs.

## Building from Source

```bash
# Build the server
go build -o streamrelay ./cmd/streamrelay

# Build the token generator
go build -o gentoken ./scripts/gentoken

# Run
./streamrelay --config config.yaml
```

### Requirements

- Go 1.22+
- Redis 6+

## Client Libraries

StreamRelay uses standard protocols. No client library needed.

**SSE:** Use the browser's native `EventSource` API, or any SSE client library.

**WebSocket:** Use the browser's native `WebSocket` API, or any WebSocket client.

### React Example

```javascript
// hooks/useStreamRelay.js
import { useEffect, useRef, useCallback } from 'react';

export function useStreamRelay(token, onEvent) {
  const sourceRef = useRef(null);

  useEffect(() => {
    if (!token) return;

    const url = `${process.env.REACT_APP_STREAM_URL}/events?token=${token}`;
    const source = new EventSource(url);
    sourceRef.current = source;

    source.addEventListener('message', (e) => {
      try {
        const payload = JSON.parse(e.data);
        onEvent(payload);
      } catch (err) {
        console.error('Failed to parse event:', err);
      }
    });

    source.addEventListener('auth_expired', () => {
      source.close();
      // Trigger token refresh in your auth system.
    });

    source.addEventListener('connected', (e) => {
      console.log('StreamRelay connected:', JSON.parse(e.data));
    });

    return () => source.close();
  }, [token, onEvent]);

  return sourceRef;
}

// Usage in a component:
function App() {
  const handleEvent = useCallback((payload) => {
    switch (payload.type) {
      case 'media_progress':
        // Update library card progress ring.
        break;
      case 'chat_token':
        // Append token to chat box
        break;
      case 'notification':
        // Show toast notification.
        break;
    }
  }, []);

  useStreamRelay(authToken, handleEvent);
}
```

### Python Publisher Example

```python
import redis
import json

class EventPublisher:
    """Publish events to StreamRelay via Redis."""

    def __init__(self, redis_url="redis://localhost:6379", prefix="streams"):
        self.redis = redis.from_url(redis_url)
        self.prefix = prefix

    def send(self, identity: str, event_type: str, data: dict):
        """Send an event to a specific user."""
        channel = f"{self.prefix}:{identity}"
        payload = json.dumps({"type": event_type, **data})
        self.redis.publish(channel, payload)

# Usage:
pub = EventPublisher()
pub.send("42", "media_progress", {"media_id": 123, "step": "whisperx", "pct": 45})
pub.send("42", "chat_token", {"conversation_id": 456, "token": "Bonjour"})
```

## TODO

- [ ] Max connection tracking should be global, not per-instance
- [ ] Prometheus metrics endpoint (global stats)
- [ ] Unit tests
- [ ] Dropped message counter
- [ ] Security audit

## License

MIT
