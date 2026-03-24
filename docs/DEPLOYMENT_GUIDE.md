# Deployment Guide

**Version: v1.5.1 | Date: 2026-03-24**

This guide is intended for DevOps engineers and IT Administrators responsible for deploying Project Hydra in air-gapped environments.

> **Note (v1.5.0+):** The LLM runs on the host (via llama.cpp or Ollama), not inside Docker.
> The worker connects to it at `http://host.docker.internal:11434/v1/chat/completions`.
> Optional services (NATS, LiteLLM, TEI) have been moved to `docker-compose.optional.yml`
> and are no longer required for the core pipeline. Core services: postgres, redis, pgbouncer,
> temporal, api, worker (6 containers).

## System Requirements

Hydra requires significant local compute due to the Zero-Egress, sovereign nature of its AI engines.

**Minimum Viable Specification (Testing / Homelab):**
- CPU: 8 Cores (x86_64 or ARM64)
- RAM: 16 GB DDR4
- GPU: Minimum 4GB VRAM (NVIDIA RTX 3050 or comparable) using a quantized 14B parameter model (Q4_K_M).
- Storage: 100 GB SSD

**Enterprise Production Specification:**
- CPU: 32 Cores
- RAM: 64 GB
- GPU: 2x NVIDIA RTX 4090 (24GB VRAM each) or A100/H100 series for running 7B to 14B parameter context-heavy models.
- Storage: 1 TB NVMe SSD (Database & S3 Object volume)

## Pre-Requisites

1. **Docker Engine v24+**
2. **Docker Compose v2+**
3. **NVIDIA Container Toolkit** (If GPU inference is leveraged)
4. Offline installation media for local inference (Ollama / vLLM weights).

## Step-by-Step Installation

1. **Clone or Extract the Repository:**
   Access the server via SSH and unpack the `hydra-mvp` deployment package.

2. **Configure Environment Variables:**
   Copy `.env.example` to `.env` and configure internal passwords.
   ```bash
   cp .env.example .env
   vim .env
   # Set POSTGRES_PASSWORD, LITELLM_MASTER_KEY, MINIO_ROOT_PASSWORD
   ```

   **JWT_SECRET is REQUIRED and must be at least 32 characters.** The API server will refuse to start if this value is missing or too short. Generate a strong secret:
   ```bash
   openssl rand -base64 64
   ```
   Copy the output and set it in `.env`:
   ```
   JWT_SECRET=<paste-generated-value-here>
   ```

3. **Configure the Inference Proxy (LiteLLM):**
   The `litellm_config.yaml` file routes internal calls from the Temporal Worker to the actual inference engine.
   ```yaml
   model_list:
     - model_name: fast
       litellm_params:
         model: ollama_chat/qwen2.5-coder
         api_base: "http://ollama:11434"
   ```

4. **Spin up the Core Stack:**
   Initialize the database, message queues, and API gateways. Core services only (NATS, LiteLLM, TEI are optional — see `docker-compose.optional.yml`).
   ```bash
   docker compose up -d postgres redis temporal pgbouncer api worker dashboard
   ```

5. **Spin up the Python Worker:**
   The worker requires access to the Docker socket to spin up sandboxes.
   ```bash
   docker compose build worker
   docker compose up -d worker
   ```

6. **Verify Services:**
   Ensure all health checks pass.
   ```bash
   docker compose ps
   ```

## Security Configuration

As of v1.5.1, Hydra follows a hardened network posture by default.

**Exposed Ports (host-accessible):**

| Service   | Port | Purpose           |
|-----------|------|-------------------|
| API       | 8090 | REST API gateway  |
| Dashboard | 3000 | Web UI            |

**Internal-only Services (not reachable from host):**

PostgreSQL (5432), Redis (6379), Temporal (7233), NATS (4222), LiteLLM (4000), MinIO (9000), PgBouncer, and the embedding server are all bound to the `hydra-internal` Docker network using `expose` only. They are not accessible outside the Docker network.

**OIDC Single Sign-On (optional):**

To enable OIDC-based authentication, set the following in `.env`:
```
OIDC_ISSUER_URL=https://idp.example.com
OIDC_CLIENT_ID=hydra-app
OIDC_CLIENT_SECRET=<your-client-secret>
```
When configured, ID tokens are verified against the provider's JWKS endpoint (RSA). If these variables are unset, OIDC is disabled and only local login is available.

**Monitoring Stack (optional):**

Prometheus, Grafana, Jaeger, and associated exporters are gated behind a Docker Compose profile. To include them:
```bash
docker compose --profile monitoring up -d
```
This adds Prometheus (9090), Grafana (3001), and exporters for PostgreSQL, Redis, and Temporal.

## Disaster Recovery

### Database Backup (Including pgvector)

To logically backup the tenants, workflows, Intelligence Fabric, and Episodic Security Memory:

```bash
docker exec hydra-postgres pg_dump -U hydra -F c -b -v -f /var/lib/postgresql/data/hydra_backup.dump hydra
```

### Database Restore

```bash
docker exec hydra-postgres pg_restore -U hydra -d hydra -v -1 /var/lib/postgresql/data/hydra_backup.dump
```
