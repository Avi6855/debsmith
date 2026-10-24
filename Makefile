# SPDX-FileCopyrightText: 2026 Avinash Rajendra Patil
# SPDX-License-Identifier: MIT

GO ?= go
BINARY := bin/debsmith
ifeq ($(OS),Windows_NT)
BINARY := bin/debsmith.exe
endif

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X github.com/Avi6855/debsmith/internal/version.Version=$(VERSION) \
	-X github.com/Avi6855/debsmith/internal/version.Commit=$(COMMIT) \
	-X github.com/Avi6855/debsmith/internal/version.Date=$(DATE)

EPOCH ?= 1700000000
EXAMPLE := examples/hello
ARTIFACT := $(EXAMPLE)/dist/hello_1.0.0-1_all.deb

.PHONY: all build test cover fmt fmt-check vet lint verify e2e clean install

all: fmt-check vet test build

build:
	@mkdir -p bin
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/debsmith

install:
	$(GO) install -trimpath -ldflags "$(LDFLAGS)" ./cmd/debsmith

test:
	$(GO) test -count=1 ./...

cover:
	$(GO) test -count=1 -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "coverage report: coverage.html"

fmt:
	gofmt -w cmd internal

fmt-check:
	@test -z "$$(gofmt -l cmd internal)" || \
		{ echo "gofmt needed:"; gofmt -l cmd internal; exit 1; }

vet:
	$(GO) vet ./...

lint:
	golangci-lint run ./...

verify: build
	rm -rf $(EXAMPLE)/dist
	$(BINARY) build $(EXAMPLE) --epoch $(EPOCH) --sbom
	$(BINARY) lint $(ARTIFACT) --fail-on warning
	$(BINARY) inspect $(ARTIFACT) --verify
	$(BINARY) verify-repro $(EXAMPLE) --epoch $(EPOCH)
	$(BINARY) source $(EXAMPLE) --epoch $(EPOCH)
	$(BINARY) repo $(EXAMPLE)/dist --epoch $(EPOCH)

e2e:
	docker run --rm -v "$(CURDIR):/work" -w /work ubuntu:24.04 \
		bash scripts/verify-container.sh

clean:
	rm -rf bin coverage.out coverage.html $(EXAMPLE)/dist
