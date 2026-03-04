# Deployment Guide

This guide is intended for DevOps engineers and IT Administrators responsible for deploying Project Hydra in air-gapped environments.

## System Requirements

Hydra requires significant local compute due to the Zero-Egress, sovereign nature of its AI engines.

**Minimum Viable Specification (Testing / Homelab):**
- CPU: 8 Cores (x86_64 or ARM64)
- RAM: 16 GB DDR4
- GPU: Minimum 4GB VRAM (NVIDIA RTX 3050 or comparable) using a quantized 1.5B or 3B parameter model.
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
   # Set POSTGRES_PASSWORD, JWT_SECRET, LITELLM_MASTER_KEY, MINIO_ROOT_PASSWORD
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
   Initialize the database, message queues, and API gateways.
   ```bash
   docker compose up -d postgres redis temporal temporal-ui api dashboard litellm minio embedding-server
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
