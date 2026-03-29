# Zovark Python SDK

Python client library for the Zovark SOC automation platform. Uses only Python stdlib (no external dependencies).

## Installation

```bash
pip install -e sdk/python/
```

## Quick Start

```python
from zovark import ZovarkClient

# Initialize client with credentials
client = ZovarkClient(
    "http://localhost:8090",
    email="admin@test.local",
    password="TestPass2026",
)

# Login (stores JWT internally)
client.login()

# Create an investigation task
task = client.create_task(
    input={
        "prompt": "Analyze these logs for brute force attacks",
        "log_data": open("suspicious.log").read(),
    },
    task_type="log_analysis",
)
print(f"Task created: {task.task_id}")

# Wait for completion
result = client.wait_for_completion(task.task_id, timeout=120)
print(f"Status: {result.status}")
print(f"Output: {result.output}")
```

## API Reference

### Authentication

```python
# Login with email/password
token = client.login()

# Or use a pre-existing token
client = ZovarkClient("http://localhost:8090", api_key="your-jwt-token")

# Register a new user
user = client.register(
    email="analyst@company.com",
    password="SecurePass123",
    display_name="Jane Analyst",
    tenant_id="my-tenant",
)
```

### Tasks

```python
# Create task
task = client.create_task(
    input={"prompt": "Investigate this alert", "log_data": "..."},
    task_type="log_analysis",
)

# Get task details
task = client.get_task("task-uuid")

# List tasks with pagination and filters
task_list = client.list_tasks(page=1, per_page=20, status="completed")
for t in task_list.tasks:
    print(f"{t.task_id}: {t.status}")

# Get investigation steps
steps = client.get_task_steps("task-uuid")

# Get audit trail
audit = client.get_task_audit("task-uuid")

# Wait for completion
result = client.wait_for_completion("task-uuid", timeout=120)
```

### Alerts

```python
# List SIEM alerts
alerts = client.list_alerts()

# Trigger investigation for an alert
task = client.investigate_alert("alert-uuid")
```

### Stats

```python
stats = client.get_stats()
print(f"Total: {stats.total_tasks}, Success rate: {stats.success_rate:.1%}")
```

### Health

```python
health = client.health_check()
print(health["status"])  # "ok"
```

## Error Handling

```python
from zovark.exceptions import (
    ZovarkAPIError,
    AuthenticationError,
    RateLimitError,
    NotFoundError,
)

try:
    task = client.get_task("nonexistent-id")
except NotFoundError:
    print("Task not found")
except AuthenticationError:
    print("Login required")
    client.login()
except RateLimitError as e:
    print(f"Rate limited, retry after {e.retry_after}s")
except ZovarkAPIError as e:
    print(f"API error {e.status_code}: {e.message}")
```

## Data Models

- `Task` — Investigation task with status, input/output, timing
- `Alert` — SIEM alert with severity, source, indicators
- `User` — Authenticated user with role and tenant
- `Stats` — Platform statistics and metrics
- `TaskList` — Paginated task results
