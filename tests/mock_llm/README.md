# Zovark Mock LLM Server

A lightweight mock server that mimics the Ollama-compatible LLM API for offline testing. Uses only Python stdlib (`http.server`) with no external dependencies.

> **Note:** LiteLLM was previously used as the LLM proxy but has been removed due to supply chain risk. Zovark now communicates directly with Ollama. This mock server emulates the same `/v1/chat/completions` endpoint.

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
docker build -t zovark-mock-llm tests/mock_llm/
docker run -p 4000:4000 zovark-mock-llm
```

### In E2E Test Stack

The mock LLM server is included in `tests/e2e/docker-compose.test.yml` and replaces the real LLM endpoint during E2E tests.

## Canned Responses

The server selects responses based on keywords in the input messages:

| Keyword Match          | Response Type              |
|------------------------|----------------------------|
| "generate python"      | Python code generation     |
| "followup"             | Follow-up check response   |
| "entity" / "extract"   | Entity extraction response |
| "report" / "executive" | Incident report response   |
| (default)              | Investigation response     |

All responses return valid JSON matching Zovark's expected schemas.

## Configuration

| Env / Flag | Default  | Description        |
|------------|----------|--------------------|
| `--port`   | 4000     | Port to listen on  |
| `--host`   | 0.0.0.0  | Host to bind to    |
