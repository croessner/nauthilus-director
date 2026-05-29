# Variables
APP_NAME := nauthilus-director
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null)
LDFLAGS := -ldflags "-X main.version=$(VERSION)"
BIN_DIR ?= ./bin
COMMANDS := $(APP_NAME) $(APP_NAME)ctl
MAN1_PAGES := docs/man/nauthilus-director.1 docs/man/nauthilus-directorctl.1
MAN5_PAGES := docs/man/nauthilus-director.yaml.5
DESTDIR ?=
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man
INSTALL ?= install
INSTALL_PROGRAM ?= $(INSTALL) -m 0755
INSTALL_DATA ?= $(INSTALL) -m 0644
GOLANGCI_LINT ?= golangci-lint
GOLANGCI_NEW_FROM_REV ?= HEAD
GO ?= go
POC_DIR := poc
E2E_SCRIPT ?= ./test/e2e/run.sh
E2E_INTEROP_SCRIPT ?= ./test/e2e/interop/run.sh
SCALE_SMOKE_SESSIONS ?= 1000
SCALE_SMOKE_HEARTBEAT_SAMPLE ?= 1000
SCALE_SMOKE_CLOSE_SAMPLE ?= 100
SCALE_SMOKE_REAP_EXPIRED ?= 100
SCALE_STRESS_SESSIONS ?= 100000
SCALE_STRESS_HEARTBEAT_SAMPLE ?= 10000
SCALE_STRESS_CLOSE_SAMPLE ?= 10000
SCALE_STRESS_REAP_EXPIRED ?= 10000

MODULE_DIRS := $(shell find . -name go.mod -not -path './poc/*' -not -path './vendor/*' -exec dirname {} \; | sort)

# Default target
all: build-check

# Build target
build:
	@if [ ! -f go.mod ]; then \
		echo "No production go.mod found yet; skipping build"; \
	else \
		mkdir -p $(BIN_DIR); \
		set -e; \
		for command in $(COMMANDS); do \
			test -d "cmd/$$command" || { echo "cmd/$$command is required"; exit 1; }; \
			echo "==> go build $$command"; \
			$(GO) build -mod=vendor -trimpath $(LDFLAGS) -o "$(BIN_DIR)/$$command" "./cmd/$$command"; \
		done; \
	fi

install: install-bin install-man

install-bin: build
	$(INSTALL) -d "$(DESTDIR)$(BINDIR)"
	@set -e; \
	for command in $(COMMANDS); do \
		$(INSTALL_PROGRAM) "$(BIN_DIR)/$$command" "$(DESTDIR)$(BINDIR)/$$command"; \
	done

install-man:
	$(INSTALL) -d "$(DESTDIR)$(MANDIR)/man1" "$(DESTDIR)$(MANDIR)/man5"
	@set -e; \
	for page in $(MAN1_PAGES); do \
		$(INSTALL_DATA) "$$page" "$(DESTDIR)$(MANDIR)/man1/$${page##*/}"; \
	done; \
	for page in $(MAN5_PAGES); do \
		$(INSTALL_DATA) "$$page" "$(DESTDIR)$(MANDIR)/man5/$${page##*/}"; \
	done

uninstall: uninstall-bin uninstall-man

uninstall-bin:
	@set -e; \
	for command in $(COMMANDS); do \
		rm -f "$(DESTDIR)$(BINDIR)/$$command"; \
	done

uninstall-man:
	@set -e; \
	for page in $(MAN1_PAGES); do \
		rm -f "$(DESTDIR)$(MANDIR)/man1/$${page##*/}"; \
	done; \
	for page in $(MAN5_PAGES); do \
		rm -f "$(DESTDIR)$(MANDIR)/man5/$${page##*/}"; \
	done

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

e2e-interop:
	@if [ -x "$(E2E_INTEROP_SCRIPT)" ]; then \
		"$(E2E_INTEROP_SCRIPT)"; \
	else \
		echo "No interop E2E runner found yet; skipping e2e-interop"; \
	fi

docs-check:
	@test -d docs || { echo "docs/ is required"; exit 1; }
	@test -d docs/specs || { echo "docs/specs/ is required for design documents"; exit 1; }
	@test -d docs/man || { echo "docs/man/ is required for manpages"; exit 1; }
	@$(MAKE) check-docs

generate-openapi:
	bash ./scripts/generate-openapi.sh

check-openapi:
	bash ./scripts/check-openapi.sh

generate-docs:
	bash ./scripts/generate-docs.sh

check-docs:
	bash ./scripts/check-docs.sh

copyright-check:
	sh ./scripts/check-go-headers.sh

guardrails: docs-check copyright-check check-openapi fix vet lint test race e2e build-check

scale-smoke:
	@if [ -z "$(SCALE_REDIS_ADDR)$(SCALE_REDIS_CLUSTER_ADDRS)" ]; then \
		echo "Set SCALE_REDIS_ADDR or SCALE_REDIS_CLUSTER_ADDRS for an explicit non-production Redis target"; \
		exit 2; \
	fi
	$(GO) run -mod=vendor ./test/scale \
		$(if $(SCALE_REDIS_ADDR),--redis-addr "$(SCALE_REDIS_ADDR)",) \
		$(if $(SCALE_REDIS_CLUSTER_ADDRS),--redis-cluster-addrs "$(SCALE_REDIS_CLUSTER_ADDRS)",) \
		$(if $(SCALE_REDIS_USERNAME),--redis-username "$(SCALE_REDIS_USERNAME)",) \
		$(if $(SCALE_REDIS_PASSWORD_FILE),--redis-password-file "$(SCALE_REDIS_PASSWORD_FILE)",) \
		$(if $(SCALE_REDIS_TLS),--tls,) \
		--sessions "$(SCALE_SMOKE_SESSIONS)" \
		--heartbeat-sample "$(SCALE_SMOKE_HEARTBEAT_SAMPLE)" \
		--close-sample "$(SCALE_SMOKE_CLOSE_SAMPLE)" \
		--reap-expired "$(SCALE_SMOKE_REAP_EXPIRED)"

scale-stress:
	@if [ -z "$(SCALE_REDIS_ADDR)$(SCALE_REDIS_CLUSTER_ADDRS)" ]; then \
		echo "Set SCALE_REDIS_ADDR or SCALE_REDIS_CLUSTER_ADDRS for an explicit Redis sizing target"; \
		exit 2; \
	fi
	$(GO) run -mod=vendor ./test/scale \
		$(if $(SCALE_REDIS_ADDR),--redis-addr "$(SCALE_REDIS_ADDR)",) \
		$(if $(SCALE_REDIS_CLUSTER_ADDRS),--redis-cluster-addrs "$(SCALE_REDIS_CLUSTER_ADDRS)",) \
		$(if $(SCALE_REDIS_USERNAME),--redis-username "$(SCALE_REDIS_USERNAME)",) \
		$(if $(SCALE_REDIS_PASSWORD_FILE),--redis-password-file "$(SCALE_REDIS_PASSWORD_FILE)",) \
		$(if $(SCALE_REDIS_TLS),--tls,) \
		$(if $(SCALE_ALLOW_PRODUCTION_TARGET),--allow-production-target,) \
		--sessions "$(SCALE_STRESS_SESSIONS)" \
		--heartbeat-sample "$(SCALE_STRESS_HEARTBEAT_SAMPLE)" \
		--close-sample "$(SCALE_STRESS_CLOSE_SAMPLE)" \
		--reap-expired "$(SCALE_STRESS_REAP_EXPIRED)"

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

.PHONY: all build install install-bin install-man uninstall uninstall-bin uninstall-man build-check clean fix vet lint-config lint test race e2e e2e-interop docs-check generate-openapi check-openapi generate-docs check-docs copyright-check guardrails scale-smoke scale-stress poc-test poc-race version
