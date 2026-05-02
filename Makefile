SHELL := /usr/bin/env bash

BIN_DIR    := bin
BIN_NAME   := astinus
PKG        := github.com/psyf8t/astinus
ENTRYPOINT := ./cmd/astinus

# Pin the toolchain so every `go` invocation in this Makefile uses the
# same version. Without this, GOTOOLCHAIN=auto re-resolves per
# subprocess and can mix the locally-installed `go tool cover` with an
# auto-downloaded compiler, producing
# `compile: version "X" does not match go tool version "Y"`.
# Read from the `go` directive in go.mod (always present;
# `go mod tidy` strips redundant `toolchain` lines).
export GOTOOLCHAIN := go$(shell awk '/^go [0-9]/{print $$2; exit}' go.mod 2>/dev/null)

# VERSION may be overridden in releases (e.g. `make build VERSION=v0.1.0`).
VERSION ?= v0.0.0-dev
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w -buildid= \
	-X $(PKG)/internal/version.Version=$(VERSION) \
	-X $(PKG)/internal/version.Commit=$(COMMIT) \
	-X $(PKG)/internal/version.Date=$(DATE)

GO_BUILD_FLAGS := -trimpath -ldflags="$(LDFLAGS)"

.PHONY: all build test test-race test-integration test-e2e lint fmt vet tidy clean docker tools help

all: build ## Build the binary (default target)

build: ## Build the astinus binary into ./bin
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build $(GO_BUILD_FLAGS) -o $(BIN_DIR)/$(BIN_NAME) $(ENTRYPOINT)

test: ## Run unit tests with race detector and coverage
	go test -race -coverprofile=coverage.out -covermode=atomic ./...

test-race: ## Alias of test, kept for clarity in CI logs
	go test -race ./...

test-integration: ## Run integration tests (requires -tags=integration)
	go test -tags=integration -race ./...

test-e2e: ## Run e2e tests (requires -tags=e2e)
	go test -tags=e2e ./test/e2e/...

lint: ## Run golangci-lint
	@if ! command -v golangci-lint >/dev/null 2>&1; then \
		echo "golangci-lint not installed; run 'make tools'" >&2; \
		exit 1; \
	fi
	golangci-lint run ./...

fmt: ## Run gofmt over the tree
	gofmt -s -w .

vet: ## Run go vet
	go vet ./...

tidy: ## Run go mod tidy
	go mod tidy

clean: ## Remove build artifacts and caches
	rm -rf $(BIN_DIR) coverage.out

docker: ## Build the distroless container image
	docker build -t $(BIN_NAME):$(VERSION) .

tools: ## Install developer tools (currently: golangci-lint)
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
