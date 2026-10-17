# Multi-stage build for Raiwall reverse proxy & WAF gateway
# Stage 1: Builder
FROM golang:1.27-alpine AS builder

WORKDIR /src

RUN apk add --no-cache git make ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=0.1.0
ARG COMMIT=docker
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT}" \
    -trimpath \
    -o /bin/raiwall ./cmd/raiwall

# Stage 2: Production Runner (<50MB image)
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata \
    && addgroup -S -g 1000 raiwall \
    && adduser -S -u 1000 -G raiwall -s /bin/sh raiwall \
    && mkdir -p /etc/raiwall /var/log/raiwall \
    && chown -R raiwall:raiwall /etc/raiwall /var/log/raiwall

COPY --from=builder /bin/raiwall /usr/local/bin/raiwall

USER raiwall:raiwall
WORKDIR /etc/raiwall

COPY --chown=raiwall:raiwall examples/Caddyfile /etc/raiwall/Caddyfile

EXPOSE 8080 8443 2019

ENTRYPOINT ["/usr/local/bin/raiwall"]
CMD ["run", "--config", "/etc/raiwall/Caddyfile"]
