BIN_DIR := bin
BINARY := $(BIN_DIR)/raiwall
VERSION ?= 0.1.0
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -ldflags "-s -w -X main.Version=$(VERSION) -X main.Commit=$(COMMIT) -X main.BuildDate=$(BUILD_DATE)"

.PHONY: all build test test-race test-integration test-all lint run validate-config clean web-dev web-build web-test

DATA_DIR ?= $(CURDIR)/data

all: build

build:
	mkdir -p $(BIN_DIR)
	go build $(LDFLAGS) -o $(BINARY) ./cmd/raiwall

test:
	go test -v ./...

test-race:
	go test -v -race ./...

test-integration:
	go test -v -race -tags=integration ./tests/e2e/...

test-all:
	go test -v -race -tags=integration ./...

lint:
	go vet ./...

run: build
	RAIWALL_CONFIG=config/raiwall.yaml \
	RAIWALL_DATABASE_URL="file:$(DATA_DIR)/raiwall.db?_pragma=busy_timeout(5000)" \
	RAIWALL_CERTMAGIC_ROOT="$(DATA_DIR)/certmagic" \
	./$(BINARY) run --config config/raiwall.yaml

validate-config: build
	./$(BINARY) config validate --config config/raiwall.yaml
	./$(BINARY) config validate --config examples/raiwall.yaml

web-dev:
	cd web && pnpm dev

web-build:
	cd web && pnpm build

web-test:
	cd web && pnpm test

clean:
	rm -rf $(BIN_DIR)

