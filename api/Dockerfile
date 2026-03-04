# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Download Go modules
COPY go.mod ./
# Copy source code
COPY . .

# Generate go.sum and download modules
RUN go mod tidy
RUN go mod download

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o hydra-api .

# Runtime stage
FROM alpine:latest

WORKDIR /app

# Add CA certificates for HTTPS requests if needed by Temporal/LiteLLM calls
RUN apk --no-cache add ca-certificates tzdata

COPY --from=builder /app/hydra-api .

# Expose port (as per requirement, using 8090)
EXPOSE 8090

ENTRYPOINT ["./hydra-api"]
