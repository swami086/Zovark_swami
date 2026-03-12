# HYDRA Mock LLM Server

A lightweight mock server that mimics the LiteLLM API for offline testing. Uses only Python stdlib (`http.server`) with no external dependencies.

## Endpoints

| Method | Path                    | Description                          |
|--------|-------------------------|--------------------------------------|
| POST   | /v1/chat/completions    | Returns canned investigation results |
| POST   | /v1/embeddings          | Returns random 768-dim vectors       |
| GET    | /health/liveliness      | Returns 200 OK                       |
| GET    | /v1/models              | Lists available mock models          |

## Usage

### Standalone

```bash
python tests/mock_llm/server.py --port 4001
```

### Docker

```bash
docker build -t hydra-mock-llm tests/mock_llm/
docker run -p 4000:4000 hydra-mock-llm
```

### In E2E Test Stack

The mock LLM server is included in `tests/e2e/docker-compose.test.yml` and replaces the real LiteLLM gateway during E2E tests.

## Canned Responses

The server selects responses based on keywords in the input messages:

| Keyword Match          | Response Type              |
|------------------------|----------------------------|
| "generate python"      | Python code generation     |
| "followup"             | Follow-up check response   |
| "entity" / "extract"   | Entity extraction response |
| "report" / "executive" | Incident report response   |
| (default)              | Investigation response     |

All responses return valid JSON matching HYDRA's expected schemas.

## Configuration

| Env / Flag | Default  | Description        |
|------------|----------|--------------------|
| `--port`   | 4000     | Port to listen on  |
| `--host`   | 0.0.0.0  | Host to bind to    |
