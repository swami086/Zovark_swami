# HYDRA MCP Server

MCP (Model Context Protocol) server that lets any MCP-compatible client operate the HYDRA SOC automation platform through natural language.

## Prerequisites

- Node.js >= 18
- HYDRA stack running (`docker compose up -d`)
- Postgres accessible on localhost:5432
- API accessible on localhost:8090

## Setup

```bash
cd mcp-server
npm install
npm run build
```

## Registration

### Claude Code

```bash
claude mcp add hydra -- node C:/Users/vinay/Desktop/HYDRA/hydra-mvp/mcp-server/dist/index.js
```

Or with environment variables:

```bash
claude mcp add hydra -e HYDRA_DB_URL=postgresql://hydra:hydra_dev_2026@localhost:5432/hydra -e HYDRA_API_URL=http://localhost:8090 -e HYDRA_PROJECT_DIR=C:/Users/vinay/Desktop/HYDRA/hydra-mvp -- node C:/Users/vinay/Desktop/HYDRA/hydra-mvp/mcp-server/dist/index.js
```

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "hydra": {
      "command": "node",
      "args": ["C:/Users/vinay/Desktop/HYDRA/hydra-mvp/mcp-server/dist/index.js"],
      "env": {
        "HYDRA_DB_URL": "postgresql://hydra:hydra_dev_2026@localhost:5432/hydra",
        "HYDRA_API_URL": "http://localhost:8090",
        "HYDRA_PROJECT_DIR": "C:/Users/vinay/Desktop/HYDRA/hydra-mvp"
      }
    }
  }
}
```

### Cursor

Add to MCP settings with the same command and args as above.

## Tools (7)

| Tool | Description |
|------|-------------|
| `hydra_submit_alert` | Submit a security alert for automated investigation |
| `hydra_get_report` | Fetch investigation report by task_id, investigation_id, or latest |
| `hydra_create_tenant` | Onboard a new customer tenant with admin user |
| `hydra_query` | Read-only SQL access to HYDRA's database (SELECT only) |
| `hydra_health` | Check health of all HYDRA services |
| `hydra_logs` | Tail and filter Docker Compose service logs |
| `hydra_trigger_workflow` | Start a Temporal workflow (detection, self_healing, etc.) |

## Resources (6)

| URI | Description |
|-----|-------------|
| `hydra://investigations/recent` | Last 10 investigations |
| `hydra://entities/top-threats` | Top 20 entities by threat score |
| `hydra://detection/rules` | Active Sigma detection rules |
| `hydra://playbooks/active` | Active SOAR playbooks |
| `hydra://health/summary` | System health overview |
| `hydra://metrics/llm` | LLM call statistics |

## Prompts (6)

| Prompt | Description |
|--------|-------------|
| `hydra-investigate-brute-force` | Brute force attack investigation template |
| `hydra-investigate-ransomware` | Ransomware incident investigation |
| `hydra-investigate-c2` | C2 beacon investigation |
| `hydra-daily-health-check` | Comprehensive daily health check |
| `hydra-onboard-customer` | Customer onboarding workflow |
| `hydra-generate-demo` | Run 3 demo investigations |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HYDRA_DB_URL` | `postgresql://hydra:hydra_dev_2026@localhost:5432/hydra` | Postgres connection string |
| `HYDRA_API_URL` | `http://localhost:8090` | Go API base URL |
| `HYDRA_PROJECT_DIR` | `C:/Users/vinay/Desktop/HYDRA/hydra-mvp` | Project root for docker compose |

## Self-Test

```bash
node dist/index.js --test
```

## Security Notes

- `hydra_query` rejects all write operations (INSERT, UPDATE, DELETE, DROP, etc.)
- All DB queries have a 10-second statement timeout
- JWT tokens are cached for 55 minutes to avoid re-authentication
- Docker compose commands require the host Docker daemon
