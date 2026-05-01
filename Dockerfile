# syntax=docker/dockerfile:1.7

# ─── Build stage ────────────────────────────────────────────────────────────
# Pin a specific Go minor; bump deliberately.
FROM golang:1.22-alpine AS build

WORKDIR /src

# Cache module downloads.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

# Bring in the rest of the source.
COPY . .

ARG VERSION=v0.0.0-dev
ARG COMMIT=unknown
ARG DATE=unknown

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 go build \
        -trimpath \
        -ldflags="-s -w -buildid= \
            -X github.com/psyf8t/astinus/internal/version.Version=${VERSION} \
            -X github.com/psyf8t/astinus/internal/version.Commit=${COMMIT} \
            -X github.com/psyf8t/astinus/internal/version.Date=${DATE}" \
        -o /astinus ./cmd/astinus

# ─── Runtime stage ──────────────────────────────────────────────────────────
# Distroless static so the image contains nothing but the binary, CA certs,
# and timezone data — and runs as a non-root user.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /astinus /usr/local/bin/astinus

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/astinus"]
