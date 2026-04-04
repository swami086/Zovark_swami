# Third-Party Licenses

This directory contains license and attribution files for third-party
software and AI models used by Zovark.

## Structure

| Path | Contents |
|------|----------|
| `THIRD_PARTY/` | Standard license texts for key open-source dependencies |
| `MODELS/` | AI model licenses and attribution |

## Dependencies

| Component | License | File |
|-----------|---------|------|
| Valkey (Redis replacement) | BSD-3-Clause | `THIRD_PARTY/valkey-BSD.txt` |
| Temporal SDK | MIT | `THIRD_PARTY/temporal-MIT.txt` |
| Gin web framework | MIT | `THIRD_PARTY/gin-MIT.txt` |
| Pydantic | MIT | `THIRD_PARTY/pydantic-MIT.txt` |
| PostgreSQL | PostgreSQL License | `THIRD_PARTY/postgresql-LICENSE.txt` |
| Signoz | MIT | `THIRD_PARTY/signoz-MIT.txt` |
| Docker | Apache 2.0 | `THIRD_PARTY/docker-APACHE-2.0.txt` |

## AI Models

| Model | License | File |
|-------|---------|------|
| Meta Llama 3.2 (3B) | Llama 3 Community License | `MODELS/llama-COMMUNITY-LICENSE.txt` |
| Meta Llama 3.1 (8B) | Llama 3 Community License | `MODELS/llama-COMMUNITY-LICENSE.txt` |

See `MODELS/ATTRIBUTION.md` for usage details.

## Note on Valkey

Zovark uses Valkey, the Linux Foundation fork of Redis. Valkey is
licensed under BSD-3-Clause, which has no distribution restrictions
(unlike Redis's SSPL/dual-license model). This simplifies air-gapped
and commercial deployments.
