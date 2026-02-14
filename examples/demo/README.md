# StreamRelay Demo

A minimal Flask + vanilla JS demo showing real-time event delivery through StreamRelay.

Two demos in one page:
- **Progress** — a circular ring that counts from 0 to 100 (published to Redis at 50ms intervals)
- **Chat** — lorem ipsum streamed word-by-word with a blinking cursor (like an LLM chat response)

Both are triggered by API calls to the Flask backend, which publishes events to Redis. StreamRelay picks them up and delivers them to the browser via SSE.

## Setup

```
┌──────────┐     ┌───────┐     ┌─────────────┐     ┌─────────┐
│  Flask   │────▶│ Redis │────▶│ StreamRelay │────▶│ Browser │
│  :5000   │     │ :6379 │     │ :8080       │     │  (SSE)  │
└──────────┘     └───────┘     └─────────────┘     └─────────┘
```

### 1. Start Redis and StreamRelay

From the repo root:

```bash
docker compose up
```

Make sure `config.yaml` has:
```yaml
auth:
  jwt_secret: "your-32-character-secret-here!!"  # must match STREAMRELAY_SECRET below
server:
  allowed_origins:
    - "http://localhost:5000"
    - "http://127.0.0.1:5000"
```

### 2. Start the demo app

```bash
cd examples/demo
pip install -r requirements.txt
STREAMRELAY_SECRET="your-32-character-secret-here!!" python app.py
```

### 3. Open the demo

Navigate to [http://localhost:5000](http://localhost:5000) and click the buttons.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `STREAMRELAY_SECRET` | `dev-secret-...` | JWT signing secret (must match StreamRelay's `auth.jwt_secret`) |
| `REDIS_URL` | `redis://localhost:6379` | Redis connection URL |
| `CHANNEL_PREFIX` | `streams` | Must match StreamRelay's `redis.channel_prefix` |
| `STREAMRELAY_URL` | `http://localhost:8080` | StreamRelay's public URL (sent to the browser) |
