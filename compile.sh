#!/usr/bin/env bash

echo "Compiling streamrelay..."
go build -o streamrelay ./cmd/streamrelay

echo "Compiling gentoken..."
go build -o gentoken ./scripts/gentoken
