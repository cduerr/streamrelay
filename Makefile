.PHONY: build release test lint clean

build:
	go build -o streamrelay ./cmd/streamrelay
	go build -o gentoken ./scripts/gentoken

release:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o streamrelay ./cmd/streamrelay
	CGO_ENABLED=0 go build -ldflags="-s -w" -o gentoken ./scripts/gentoken

test:
	go test ./...

lint:
	golangci-lint run ./...

clean:
	rm -f streamrelay gentoken
