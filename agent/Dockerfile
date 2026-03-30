FROM python:3.12-slim

# Install Docker CLI (official binary), psql, redis-cli, curl
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates postgresql-client redis-tools \
    && curl -fsSL https://download.docker.com/linux/static/stable/x86_64/docker-27.5.1.tgz \
    | tar xz --strip-components=1 -C /usr/local/bin docker/docker \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY healer.py .

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8081/api/health || exit 1

CMD ["python3", "-u", "healer.py"]
