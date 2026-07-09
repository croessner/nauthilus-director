# syntax=docker/dockerfile:1.7
#
# Copyright (C) 2026 Christian Rößner
#
# SPDX-License-Identifier: AGPL-3.0-only

ARG GO_IMAGE=golang:1.26.5-alpine3.23
ARG CERTS_IMAGE=alpine:3.23
ARG RUNTIME_IMAGE=scratch

FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS builder

ARG TARGETOS=linux
ARG TARGETARCH
ARG VERSION=dev

WORKDIR /src

ENV CGO_ENABLED=0 \
    GOFLAGS=-mod=vendor

COPY go.mod go.sum ./
COPY vendor/ ./vendor/
COPY cmd/nauthilus-director/ ./cmd/nauthilus-director/
COPY internal/ ./internal/

RUN --mount=type=cache,target=/root/.cache/go-build \
    set -eux; \
    target_os="${TARGETOS:-linux}"; \
    target_arch="${TARGETARCH:-$(go env GOARCH)}"; \
    GOOS="$target_os" GOARCH="$target_arch" go build \
        -trimpath \
        -buildvcs=false \
        -ldflags="-s -w -buildid= -X main.version=${VERSION}" \
        -o "/out/nauthilus-director" \
        "./cmd/nauthilus-director"

FROM --platform=$BUILDPLATFORM ${CERTS_IMAGE} AS runtime-files

RUN set -eux; \
    apk add --no-cache ca-certificates; \
    addgroup -S -g 10001 director; \
    adduser -S -D -H -u 10001 -G director -s /sbin/nologin director; \
    mkdir -p /etc/nauthilus-director /run/nauthilus-director /tmp; \
    chown 10001:10001 /run/nauthilus-director; \
    chmod 0755 /etc/nauthilus-director /run/nauthilus-director; \
    chmod 1777 /tmp

FROM ${RUNTIME_IMAGE}

ARG VERSION=dev
ARG REVISION=unknown
ARG BUILD_DATE=unknown
ARG SOURCE=https://github.com/croessner/nauthilus-director

LABEL org.opencontainers.image.title="nauthilus-director" \
      org.opencontainers.image.description="Production nauthilus-director server image" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.source="${SOURCE}" \
      org.opencontainers.image.licenses="AGPL-3.0-only"

COPY --from=runtime-files /etc/passwd /etc/passwd
COPY --from=runtime-files /etc/group /etc/group
COPY --from=runtime-files /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=runtime-files --chown=10001:10001 /etc/nauthilus-director /etc/nauthilus-director
COPY --from=runtime-files --chown=10001:10001 /run/nauthilus-director /run/nauthilus-director
COPY --from=runtime-files /tmp /tmp
COPY --from=builder --chmod=0555 /out/nauthilus-director /usr/local/bin/nauthilus-director

ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    TMPDIR=/tmp

WORKDIR /
VOLUME ["/etc/nauthilus-director", "/run/nauthilus-director", "/tmp"]

USER 10001:10001

EXPOSE 9090 10143 10993 10024 11024 10110 10995 14190 14490

ENTRYPOINT ["/usr/local/bin/nauthilus-director"]
CMD ["--config", "/etc/nauthilus-director/nauthilus-director.yml", "serve"]
