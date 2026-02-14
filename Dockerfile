# Build stage
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src

# Cache module downloads.
COPY go.mod go.sum ./
RUN go mod download

# Build the binary.
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /streamrelay \
    ./cmd/streamrelay

# Build the token generator.
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /gentoken \
    ./scripts/gentoken

# Runtime stage — minimal image.
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /streamrelay /usr/local/bin/streamrelay
COPY --from=builder /gentoken /usr/local/bin/gentoken

# Default config location — mount your own config at runtime.
# COPY config.example.yaml /etc/streamrelay/config.yaml
# ↑ Intentionally commented out. The example config contains a placeholder
#   secret. Mount a real config file or use environment variable overrides.

EXPOSE 8080

ENTRYPOINT ["streamrelay"]
CMD ["--config", "/etc/streamrelay/config.yaml"]
