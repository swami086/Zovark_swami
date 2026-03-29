@echo off
echo ============================================================
echo   Zovark SOC Platform — Starting...
echo ============================================================
echo.

REM Check Docker
docker info >nul 2>&1
if errorlevel 1 (
    echo ERROR: Docker is not running. Start Docker Desktop first.
    exit /b 1
)
echo Docker: OK

REM Start services
echo Starting Docker services...
docker compose up -d
timeout /t 10 /nobreak >nul

REM Check health
echo.
echo Checking services...

curl -s http://localhost:8090/health | findstr "ok" >nul 2>nul
if errorlevel 1 (
    echo API: STARTING (wait 30 seconds)
) else (
    echo API: OK (http://localhost:8090)
)

curl -s http://localhost:3000 >nul 2>nul
if errorlevel 1 (
    echo Dashboard: NOT RUNNING
    echo   Start with: cd dashboard ^&^& npx vite --port 5173
) else (
    echo Dashboard: OK (http://localhost:3000)
)

curl -s http://localhost:11434/v1/models >nul 2>nul
if errorlevel 1 (
    echo LLM: NOT RUNNING
    echo   Start with: C:\Users\vinay\llama-cpp\llama-server.exe -m C:\Users\vinay\models\Qwen2.5-14B-Instruct-Q4_K_M.gguf -ngl 20 --port 11434
) else (
    echo LLM: OK (http://localhost:11434)
)

echo.
echo ============================================================
echo   Zovark is running!
echo   API:       http://localhost:8090
echo   Dashboard: http://localhost:3000 (Docker) or :5173 (dev)
echo   Health:    http://localhost:8090/health
echo   Login:     admin@test.local / TestPass2026
echo ============================================================
echo.
echo To stop: docker compose down
