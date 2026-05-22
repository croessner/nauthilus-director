# Variables
APP_NAME := nauthilus-director
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null)
LDFLAGS := -ldflags "-X main.version=$(VERSION)"
BIN_DIR ?= ./bin
GOLANGCI_LINT ?= golangci-lint
GOLANGCI_NEW_FROM_REV ?= HEAD
GO ?= go
POC_DIR := poc
E2E_SCRIPT ?= ./test/e2e/run.sh

MODULE_DIRS := $(shell find . -name go.mod -not -path './poc/*' -not -path './vendor/*' -exec dirname {} \; | sort)

# Default target
all: build-check

# Build target
build:
	@if [ ! -f go.mod ]; then \
		echo "No production go.mod found yet; skipping build"; \
	elif [ ! -d cmd/$(APP_NAME) ]; then \
		echo "cmd/$(APP_NAME) is not present yet; running build-check instead"; \
		$(MAKE) build-check; \
	else \
		mkdir -p $(BIN_DIR); \
		$(GO) build -mod=vendor -trimpath $(LDFLAGS) -o $(BIN_DIR)/$(APP_NAME) ./cmd/$(APP_NAME); \
	fi

# Build check target
build-check:
	@if [ -z "$(MODULE_DIRS)" ]; then \
		echo "No production Go module found yet; skipping build-check"; \
	else \
		set -e; \
		for dir in $(MODULE_DIRS); do \
			echo "==> go build $$dir"; \
			(cd "$$dir" && $(GO) build -mod=vendor ./...); \
		done; \
	fi

# Clean target
clean:
	rm -rf $(BIN_DIR)

# Test and quality targets
fix:
	@if [ -z "$(MODULE_DIRS)" ]; then \
		echo "No production Go module found yet; skipping go fix"; \
	else \
		set -e; \
		for dir in $(MODULE_DIRS); do \
			echo "==> go fix $$dir"; \
			(cd "$$dir" && $(GO) fix ./...); \
		done; \
	fi

vet:
	@if [ -z "$(MODULE_DIRS)" ]; then \
		echo "No production Go module found yet; skipping go vet"; \
	else \
		set -e; \
		for dir in $(MODULE_DIRS); do \
			echo "==> go vet $$dir"; \
			(cd "$$dir" && $(GO) vet ./...); \
		done; \
	fi

lint-config:
	@command -v $(GOLANGCI_LINT) >/dev/null 2>&1 || { echo "$(GOLANGCI_LINT) not found. Install it and rerun make guardrails"; exit 1; }
	$(GOLANGCI_LINT) config verify

lint: lint-config
	@if [ -z "$(MODULE_DIRS)" ]; then \
		echo "No production Go module found yet; skipping golangci-lint run"; \
	else \
		set -e; \
		for dir in $(MODULE_DIRS); do \
			echo "==> golangci-lint $$dir"; \
			(cd "$$dir" && $(GOLANGCI_LINT) run --new-from-rev=$(GOLANGCI_NEW_FROM_REV) ./...); \
		done; \
	fi

test:
	@if [ -z "$(MODULE_DIRS)" ]; then \
		echo "No production Go module found yet; skipping go test"; \
	else \
		set -e; \
		for dir in $(MODULE_DIRS); do \
			echo "==> go test $$dir"; \
			(cd "$$dir" && $(GO) test -v ./...); \
		done; \
	fi

race:
	@if [ -z "$(MODULE_DIRS)" ]; then \
		echo "No production Go module found yet; skipping race tests"; \
	else \
		set -e; \
		for dir in $(MODULE_DIRS); do \
			echo "==> go test -race $$dir"; \
			(cd "$$dir" && $(GO) test -race -short ./...); \
		done; \
	fi

e2e:
	@if [ -x "$(E2E_SCRIPT)" ]; then \
		"$(E2E_SCRIPT)"; \
	else \
		echo "No E2E runner found yet; skipping e2e"; \
	fi

docs-check:
	@test -d docs || { echo "docs/ is required"; exit 1; }
	@test -d docs/specs || { echo "docs/specs/ is required for specifications"; exit 1; }
	@test -d docs/man || { echo "docs/man/ is required for manpages"; exit 1; }

generate-openapi:
	bash ./scripts/generate-openapi.sh

check-openapi:
	bash ./scripts/check-openapi.sh

copyright-check:
	sh ./scripts/check-go-headers.sh

guardrails: docs-check copyright-check check-openapi fix vet lint test race e2e build-check

# Optional proof-of-concept checks
poc-test:
	@if [ ! -f $(POC_DIR)/go.mod ]; then \
		echo "No POC Go module found"; \
	else \
		(cd $(POC_DIR) && $(GO) test -v ./...); \
	fi

poc-race:
	@if [ ! -f $(POC_DIR)/go.mod ]; then \
		echo "No POC Go module found"; \
	else \
		(cd $(POC_DIR) && $(GO) test -race -short ./...); \
	fi

# Print version
version:
	@echo $(VERSION)

.PHONY: all build build-check clean fix vet lint-config lint test race e2e docs-check generate-openapi check-openapi copyright-check guardrails poc-test poc-race version
