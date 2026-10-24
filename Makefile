BINARY_NAME=mcp-guard
BIN_DIR=bin
VERSION?=v0.1.0-dev
COMMIT?=$(shell git rev-parse --short HEAD 2>nul || echo "none")
DATE?=$(shell date /t 2>nul || echo "unknown")
LDFLAGS=-s -w -X main.Version=$(VERSION) -X main.Commit=$(COMMIT) -X main.Date=$(DATE)

.PHONY: all build build-static test test-coverage lint clean demo

all: build test

build:
	go build -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME) ./cmd/mcp-guard

build-static:
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME) ./cmd/mcp-guard

test:
	go test -v -race ./...

test-coverage:
	go test -v -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -func=coverage.out

lint:
	go vet ./...
	golangci-lint run ./...

demo: build
	./$(BIN_DIR)/$(BINARY_NAME) demo

clean:
	rm -rf $(BIN_DIR) coverage.out dist
