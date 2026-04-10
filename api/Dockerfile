# Build context: repository root (see docker-compose.yml api.build).
# Build stage
FROM golang:1.22-bookworm AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

COPY api/go.mod api/go.sum ./
RUN go mod download

COPY api/ ./

RUN go mod tidy && CGO_ENABLED=0 GOOS=linux go build -o hydra-api .

# Runtime — bookworm + DuckDB CLI for metrics (postgres_scanner)
FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates tzdata curl unzip python3 \
    && curl -fsSL -o /tmp/duck.zip https://github.com/duckdb/duckdb/releases/download/v1.1.3/duckdb_cli-linux-amd64.zip \
    && unzip -q -p /tmp/duck.zip duckdb > /usr/local/bin/duckdb \
    && chmod +x /usr/local/bin/duckdb \
    && rm -f /tmp/duck.zip \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/hydra-api .
COPY migrations/ /app/migrations/

EXPOSE 8090

ENTRYPOINT ["./hydra-api"]
