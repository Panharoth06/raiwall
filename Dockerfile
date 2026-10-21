# ==============================================================================
# Multi-Stage Build: Raiwall WAF Gateway (Go Backend + Embedded Vue 3 Frontend)
# ==============================================================================

# ------------------------------------------------------------------------------
# Stage 1: Build Vue 3 + TypeScript Frontend Dashboard
# ------------------------------------------------------------------------------
FROM node:22-alpine AS frontend-builder

WORKDIR /app/web

# Enable corepack and prepare pnpm (pinned to v9 to match lockfileVersion 9.0)
RUN corepack enable && corepack prepare pnpm@9.15.9 --activate

# Copy dependency manifests and install dependencies
COPY web/package.json web/pnpm-lock.yaml* web/.npmrc* ./
RUN pnpm install --frozen-lockfile

# Copy frontend source code and compile production assets to web/dist
COPY web/ ./
RUN pnpm build

# ------------------------------------------------------------------------------
# Stage 2: Build Go WAF Gateway & Control Plane Binary
# ------------------------------------------------------------------------------
FROM golang:alpine AS backend-builder

WORKDIR /src

RUN apk add --no-cache git ca-certificates

# Cache Go modules
COPY go.mod go.sum ./
RUN go mod download

# Patch Caddy v2.8.4 for Go 1.27+ compatibility (encoding/json.RawMessage is jsontext.Value)
RUN chmod -R u+w /go/pkg/mod/github.com/caddyserver/caddy/v2@v2.8.4 && \
    sed -i 's/typ.PkgPath() == "encoding\/json" && typ.Name() == "RawMessage"/(typ.PkgPath() == "encoding\/json" \&\& typ.Name() == "RawMessage") || (typ.PkgPath() == "encoding\/json\/jsontext" \&\& typ.Name() == "Value")/' /go/pkg/mod/github.com/caddyserver/caddy/v2@v2.8.4/modules.go

# Copy full source tree
COPY . .

# Copy compiled frontend from Stage 1 into web/dist for go:embed
COPY --from=frontend-builder /app/web/dist ./web/dist

ARG VERSION=0.1.0
ARG COMMIT=docker
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT}" \
    -trimpath \
    -o /bin/raiwall ./cmd/raiwall

# ------------------------------------------------------------------------------
# Stage 3: Lightweight Production Runner (<50MB image)
# ------------------------------------------------------------------------------
FROM alpine:3.20

RUN apk --no-cache add ca-certificates tzdata curl \
    && addgroup -S -g 1000 raiwall \
    && adduser -S -u 1000 -G raiwall -s /bin/sh raiwall \
    && mkdir -p /etc/raiwall /var/lib/raiwall /var/log/raiwall \
    && chown -R raiwall:raiwall /etc/raiwall /var/lib/raiwall /var/log/raiwall

COPY --from=backend-builder /bin/raiwall /usr/local/bin/raiwall
COPY --chown=raiwall:raiwall examples/Caddyfile /etc/raiwall/Caddyfile

USER raiwall:raiwall
WORKDIR /etc/raiwall

# Expose HTTP gateway & web console (8080) and HTTPS (8443)
EXPOSE 8080 8443

VOLUME ["/var/lib/raiwall"]

ENTRYPOINT ["/usr/local/bin/raiwall"]
CMD ["run", "--config", "/etc/raiwall/Caddyfile"]
