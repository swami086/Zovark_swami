# SPRINT 6: Investigation Dashboard — Claude Code Prompt
## CTO-Corrected, Ready to Paste

> **Instructions:** Paste PROMPT 1 (Primer) first. Then paste PROMPT 2 (Sprint) immediately after.

---

## PROMPT 1: THE PRIMER

```
You are now operating under AGGRESSIVE SPRINT MODE — QUALITY EDITION.

MANDATE: Build fast. Ship faster. If it doesn't directly lead to a demoable feature or customer conversation, it's waste. But "fast" ≠ "sloppy." We ship focused quality where revenue is at risk.

RULES:
1. NO future-timeline planning — only "what ships today?"
2. Ruthless scope control — >3 days = kill it or cut it
3. Quality gates are NON-NEGOTIABLE:
   - Demo must not crash
   - Demo must complete in <30 seconds
   - Demo must look professional (UI polish matters for MSSP sales)
4. Code elegance is NEGOTIABLE — ugly working code > beautiful broken code
5. 30-day death clock — LOI by Day 30 or kill project

TOOLS — USE THESE:
✅ ripgrep — 0 setup, code navigation
✅ Manual testing — fastest feedback loop for demo path

TOOLS — SKIP FOR THIS SPRINT (REVIEW AFTER):
⏸️ Axon — code intelligence MCP, valuable post-sprint for future sessions
⏸️ CodeRabbit — useful but setup time not justified for 7-day sprint

DECISION FRAMEWORK:
- Does this help get an LOI in 30 days? No = kill it.
- Can we ship this today? No = cut scope until we can.
- Is this preventing a demo crash? Yes = mandatory.
- Is this optimizing for scale we don't have? Yes = delete it.

TONE: Aggressive. Impatient. Pragmatic. "Ship it now. Optimize later (if we survive). But don't ship broken."

CURRENT SPRINT (Days 1-7):
MUST HAVE: InvestigationWaterfall component, ONE demo scenario (C2 Beacon), working demo flow
NICE TO HAVE: Entity graph (only if waterfall <3 days), Report viewer (only if entity graph <1 day)
EXPLICITLY KILLED: Multi-scenario demos, cache hardening, 2-year planning

CRITICAL CONVENTIONS (FOLLOW ALL):
- Windows host, no Python on host — ALL Python runs in Docker containers
- Use semicolons (;) not && for bash command chaining
- Postgres access: docker compose exec -T postgres psql -U hydra -d hydra
- Worker access: docker compose exec -T worker python -c "..."
- NEVER use bare psql or python commands — they don't exist on the host
- Go API builds inside Docker — use docker compose build api
- LF line endings enforced via .gitattributes

Now execute the following sprint.
```

---

## PROMPT 2: THE SPRINT

```
# SPRINT 6: Investigation Dashboard (Days 1-7)

## PROJECT CONTEXT

Repo: C:\Users\vinay\Desktop\HYDRA\hydra-mvp
Branch: master
Stack: Go API (Gin, port 8090), Python worker (Temporal, 7 workflows, 58 activities), PostgreSQL+pgvector, Redis, LiteLLM, React dashboard (port 3000)
Latest work: Sprint 5 added LLM fallback chains, dry-run validation gate, investigation memory, alert deduplication

The dashboard currently exists but is minimal — it does NOT show investigations, entity graphs, or reports visually. This sprint makes it sellable.

---

## Phase 0: Verify Sprint 5 Bug Fix (15 minutes)

Check if the Go API dedup SQL bug was already fixed:

```bash
grep -n "dedup_window_seconds" api/handlers.go
```

If you see this (BROKEN):
```sql
AND last_seen > NOW() - (dedup_window_seconds || ' seconds')::interval
```

Replace with (FIXED):
```sql
AND last_seen > NOW() - (dedup_window_seconds * interval '1 second')
```

If you see the fixed version already, move on.

Verify these imports exist in the import block of api/handlers.go:
- "sort"
- "strings"
- "crypto/sha256"
- "encoding/hex"

Test:
```bash
docker compose build api
```

Also commit Sprint 5 if uncommitted:
```bash
git status
# If uncommitted changes exist:
git add -A
git commit -m "Sprint 5: LLM reliability, dry-run validation, investigation memory, alert dedup

- litellm_config.yaml: 3-tier fallback (Groq/OpenRouter/Anthropic/OpenAI)
- worker/validation/dry_run.py: 5s subprocess sandbox gate
- worker/investigation_memory.py: Two-pass entity matching
- worker/prompts/investigation_prompt.py: JSON-enforced prompt
- migrations/015-016: audit_events, alert_fingerprints
- api/handlers.go: SHA-256 alert deduplication
- 7 workflows, 58 activities, 16 prompts, 30 tables"
git push
```

---

## Phase 1: Discovery & Endpoint Mapping (30 min — CRITICAL)

DO NOT skip this phase. Build against what actually exists.

```bash
# 1. Inventory frontend — what React app exists?
ls -la dashboard/ 2>/dev/null; ls -la frontend/ 2>/dev/null; ls -la ui/ 2>/dev/null
cat dashboard/package.json 2>/dev/null; cat frontend/package.json 2>/dev/null

# 2. Find EXACT API endpoints (don't assume /investigations/ — might be /tasks/)
grep -E "timeline|steps|investigation|tasks" api/handlers.go api/routes.go 2>/dev/null | head -30
grep -E "(GET|POST|PUT|DELETE).*\"/" api/*.go 2>/dev/null | head -40

# 3. Check database schema
docker compose exec -T postgres psql -U hydra -d hydra -c "\dt" | grep -E "(task|investigation|entity|report)"
docker compose exec -T postgres psql -U hydra -d hydra -c "\d agent_task_steps"
docker compose exec -T postgres psql -U hydra -d hydra -c "\d investigations"
docker compose exec -T postgres psql -U hydra -d hydra -c "SELECT column_name, data_type FROM information_schema.columns WHERE table_name='agent_task_steps' ORDER BY ordinal_position"

# 4. Check what data exists
docker compose exec -T postgres psql -U hydra -d hydra -c "SELECT count(*) FROM agent_task_steps"
docker compose exec -T postgres psql -U hydra -d hydra -c "SELECT count(*) FROM investigations"
docker compose exec -T postgres psql -U hydra -d hydra -c "SELECT status, count(*) FROM agent_tasks GROUP BY status"

# 5. Check Temporal UI accessibility
curl -s http://localhost:8233/api/v1/namespaces 2>/dev/null | head -5
```

**Record findings and make decisions:**

| Question | Answer | Action |
|---|---|---|
| Does React app exist? | Check ls output | Extend or scaffold |
| Is it Vite or CRA? | Check package.json | Migrate or work with it |
| Does /tasks/:id/steps exist? | Check grep output | Use it or create it |
| Does /tasks/:id/timeline exist? | Check grep output | Use it or create /steps |
| Does /investigations/ route exist? | Check grep output | Map frontend accordingly |
| Does agent_task_steps have data? | Check count | Use real data or need demo seed |

---

## Phase 2: React + Vite + Tailwind Setup (30 min — only if no existing React app)

**If existing React app found:** Skip to Phase 3. Install missing deps only:
```bash
cd dashboard  # or whatever the frontend folder is called
npm install react-router-dom @tanstack/react-query axios date-fns
```

**If no existing React app — scaffold fresh:**

```bash
mkdir -p dashboard; cd dashboard
npm create vite@latest . -- --template react-ts
npm install
npm install -D tailwindcss postcss autoprefixer
npx tailwindcss init -p
npm install react-router-dom @tanstack/react-query axios date-fns
npm install -D @types/node
```

**tailwind.config.js:**
```javascript
/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        hydra: {
          50: '#eff6ff', 100: '#dbeafe', 200: '#bfdbfe',
          500: '#3b82f6', 600: '#2563eb', 700: '#1d4ed8', 900: '#1e3a8a'
        }
      }
    },
  },
  plugins: [],
}
```

**src/index.css:**
```css
@tailwind base;
@tailwind components;
@tailwind utilities;
@layer base { body { @apply bg-gray-50 text-gray-900 antialiased; } }
```

**vite.config.ts** (proxy API to Go backend):
```typescript
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://localhost:8090',
        changeOrigin: true,
      }
    }
  }
})
```

---

## Phase 3: Go API Endpoints (2 hours — create what's missing)

Check Phase 1 findings. Create ONLY endpoints that don't already exist.
If endpoints exist at /tasks/ instead of /investigations/, use those — don't duplicate.

**Required endpoints (create in api/handlers_dashboard.go if missing):**

```go
// GET /api/v1/investigations
// List investigations with filtering
// Query params: status (string), limit (int, default 25), offset (int), search (string)
// Returns: {"investigations": [...], "total": N, "has_more": bool}
// SQL: SELECT i.*, at.task_type, at.input FROM investigations i
//      JOIN agent_tasks at ON at.id = i.task_id
//      ORDER BY i.created_at DESC LIMIT $1 OFFSET $2

// GET /api/v1/investigations/:id/timeline
// Returns workflow steps for the waterfall view
// Returns: {"steps": [WorkflowStep...], "investigation": {...}}
// SQL: SELECT * FROM agent_task_steps WHERE task_id = $1 ORDER BY step_number ASC
// NOTE: If /tasks/:id/steps already exists and returns the same data, skip this

// GET /api/v1/investigations/:id/entities
// Returns entities extracted during this investigation
// Returns: {"entities": [...], "edges": [...]}
// SQL: SELECT e.* FROM entities e
//      JOIN entity_observations eo ON eo.entity_id = e.id
//      WHERE eo.investigation_id = $1

// GET /api/v1/investigations/:id/report
// Returns the investigation report
// Returns: {"title": "...", "severity": "high", "summary": "...", "findings": [...], "recommendations": [...]}
// SQL: SELECT * FROM investigation_reports WHERE investigation_id = $1

// POST /api/v1/investigations/demo
// Triggers a demo investigation with pre-loaded scenario
// Body: {"scenario": "c2_beacon"}
// Action: Creates agent_task with is_demo=true, triggers Temporal ExecuteTaskWorkflow
// Returns: {"investigation_id": "...", "task_id": "..."}
// FALLBACK: If this is too complex, just use the existing POST /api/v1/tasks endpoint
//           with a special task_type "demo_c2_beacon"
```

**CORS: Ensure the Go API allows requests from localhost:3000:**
```go
// Check if CORS middleware exists. If not, add:
func corsMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
        c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        c.Writer.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
        if c.Request.Method == "OPTIONS" {
            c.AbortWithStatus(204)
            return
        }
        c.Next()
    }
}
```

Register endpoints in router. Rebuild:
```bash
docker compose build api; docker compose up -d api
```

---

## Phase 4: Core Components (2-3 days)

### 4.1 InvestigationWaterfall.tsx (MUST HAVE — Day 1-2)

This is the "jaw-drop" component. It MUST work perfectly for the demo.

```typescript
// src/components/InvestigationWaterfall.tsx

interface WorkflowStep {
  id: string;
  name: string;  // parse_alert, generate_python, execute_sandbox, extract_entities, guardrail_check, generate_report, complete
  status: 'pending' | 'running' | 'completed' | 'failed';
  started_at?: string;
  completed_at?: string;
  duration_ms?: number;
  input?: Record<string, unknown>;
  output?: Record<string, unknown>;
  error?: string;
  guardrail_score?: number;
  guardrail_threshold?: number;  // default 50
  retry_count?: number;
  model_name?: string;
}

// Requirements:
// 1. Vertical timeline of steps — each step is a card with:
//    - Status icon: ⏳ pending, 🔵 running (with pulse animation), ✅ completed, ❌ failed, 🔄 retry
//    - Step name (human-readable: "Parse Alert", "Generate Investigation Code", etc.)
//    - Duration badge (e.g., "4.2s") — appears when completed
//    - Model name badge (e.g., "hydra-standard") — small, gray
//    - Connecting line between steps (solid if complete, dashed if pending)
//
// 2. Click any step → StepDetailPanel slides in from right:
//    - Input JSON (syntax highlighted, collapsible)
//    - Output JSON (syntax highlighted, collapsible)
//    - Error message if failed (red box)
//    - "Copy JSON" button
//
// 3. Guardrail step special rendering:
//    - GuardrailScoreBar component: horizontal bar, green if >= threshold, red if < threshold
//    - Score number displayed: "87 / 100"
//    - Threshold marker at 50 (vertical line)
//    - If failed → show retry indicator and second attempt
//
// 4. Progress bar at top: % of steps completed
//
// 5. Real-time polling:
//    - Use @tanstack/react-query with refetchInterval: 1000 while status !== 'completed' && status !== 'failed'
//    - Auto-scroll to latest running/completed step
//    - Stop polling when investigation completes
//
// 6. Demo mode:
//    - If data comes from demo scenario, show banner: "[DEMO MODE] Simulated investigation"
//    - Steps appear with realistic timing delays (not all at once)

// DATA SOURCE (use whatever endpoint exists from Phase 1 discovery):
// Option A: GET /api/v1/tasks/:id/steps
// Option B: GET /api/v1/tasks/:id/timeline
// Option C: GET /api/v1/investigations/:id/timeline
// Option D: Direct query to agent_task_steps table via API

// HUMAN-READABLE STEP NAMES:
const STEP_LABELS: Record<string, string> = {
  'parse_alert': 'Parse Alert',
  'generate_python': 'Generate Investigation Code',
  'generate_code': 'Generate Investigation Code',
  'execute_sandbox': 'Execute in Sandbox',
  'execute_code': 'Execute in Sandbox',
  'extract_entities': 'Extract Entities',
  'guardrail_check': 'Quality Validation',
  'validate_generated_code': 'Quality Validation',
  'generate_report': 'Generate Report',
  'generate_incident_report': 'Generate Report',
  'complete': 'Investigation Complete',
};
```

### 4.2 StepDetailPanel.tsx (MUST HAVE)

```typescript
// Slide-out panel from right side
// Props: step: WorkflowStep, onClose: () => void
// Shows:
//   - Step name + status badge
//   - Duration
//   - Model used
//   - Input JSON (collapsible, syntax highlighted with <pre> + tailwind)
//   - Output JSON (collapsible, syntax highlighted)
//   - Error (red alert box if present)
//   - "Copy to Clipboard" button for each JSON block
```

### 4.3 GuardrailScoreBar.tsx (MUST HAVE)

```typescript
// Props: score: number, threshold: number (default 50), passed: boolean
// Renders:
//   - Horizontal bar (full width of container)
//   - Fill color: green (>=threshold) or red (<threshold)
//   - Fill width: score% of bar
//   - Threshold marker: vertical dashed line at threshold%
//   - Label: "87 / 100" on the right
//   - Status: "✅ PASSED" or "❌ FAILED — triggering retry"
```

### 4.4 InvestigationList.tsx (MUST HAVE — 30 min)

```typescript
// Table view of all investigations
// Columns: ID (truncated) | Alert Type | Severity | Status | Duration | Started
// Status badges: pending=gray, running=blue+pulse, completed=green, failed=red
// Click row → navigate to /investigations/:id (which shows waterfall)
// Sort by date (newest first)
// Filter dropdown: All / Running / Completed / Failed
```

### 4.5 EntityGraph.tsx (NICE TO HAVE — only if waterfall done in <2 days)

```typescript
// If you have time:
// npm install cytoscape react-cytoscapejs @types/cytoscape
// Cytoscape.js force-directed graph
// Node colors: IP=blue, Domain=green, Hash=red, URL=orange, Email=purple, User=yellow
// Edges: labeled with relationship type
// Click node → side panel with entity details
// Skip if waterfall takes >2 days
```

### 4.6 ReportViewer.tsx (NICE TO HAVE — only if entity graph done in <4 hours)

```typescript
// Markdown rendering of investigation report
// Severity badge (critical=red, high=orange, medium=yellow, low=gray)
// Findings list (collapsible)
// Recommendations checklist
// Skip if this pushes beyond Day 7
```

---

## Phase 5: Demo Mode Wiring (2 hours)

### 5.1 C2 Beacon Demo Scenario (hardcoded in frontend)

Create `src/demo/c2BeaconScenario.ts`:

```typescript
// Hardcoded demo data — NO API call needed for demo mode
// This makes the demo work even without a running backend

export const C2_BEACON_STEPS: WorkflowStep[] = [
  {
    id: 'step-1',
    name: 'parse_alert',
    status: 'completed',
    started_at: '2026-03-10T10:00:00Z',
    completed_at: '2026-03-10T10:00:00.500Z',
    duration_ms: 500,
    input: {
      alert_type: 'c2_beacon',
      source: 'Splunk SIEM',
      raw_data: 'Outbound DNS request to updateservice-cdn.net from 10.0.1.42, repeated every 30s for 4 hours'
    },
    output: {
      extracted_iocs: ['updateservice-cdn.net', '185.220.101.42', '10.0.1.42'],
      alert_severity: 'high',
      classification: 'potential_c2_communication'
    }
  },
  {
    id: 'step-2',
    name: 'generate_python',
    status: 'completed',
    started_at: '2026-03-10T10:00:00.500Z',
    completed_at: '2026-03-10T10:00:04.700Z',
    duration_ms: 4200,
    model_name: 'hydra-standard',
    input: { prompt: 'Investigate C2 beacon to updateservice-cdn.net...' },
    output: {
      code_lines: 47,
      libraries_used: ['requests', 'dns.resolver', 'whois'],
      investigation_strategy: 'DNS resolution → WHOIS lookup → VirusTotal check → beacon pattern analysis'
    }
  },
  {
    id: 'step-3',
    name: 'execute_sandbox',
    status: 'completed',
    started_at: '2026-03-10T10:00:04.700Z',
    completed_at: '2026-03-10T10:00:05.800Z',
    duration_ms: 1100,
    input: { sandbox: 'Docker --network=none --read-only --memory=512m', timeout: '30s' },
    output: {
      exit_code: 0,
      vt_detections: '18/90 engines flagged as malicious',
      whois_registrant: 'Privacy Protected, registered 3 days ago',
      dns_resolution: '185.220.101.42 (Tor exit node)',
      beacon_interval: '30.2s ± 0.8s (consistent C2 pattern)'
    }
  },
  {
    id: 'step-4',
    name: 'extract_entities',
    status: 'completed',
    started_at: '2026-03-10T10:00:05.800Z',
    completed_at: '2026-03-10T10:00:06.100Z',
    duration_ms: 300,
    input: { raw_output: '...' },
    output: {
      entities_found: 5,
      entities: [
        { type: 'domain', value: 'updateservice-cdn.net', threat_score: 92 },
        { type: 'ip', value: '185.220.101.42', threat_score: 88 },
        { type: 'ip', value: '10.0.1.42', threat_score: 15 },
        { type: 'process', value: 'svchost_update.exe', threat_score: 95 },
        { type: 'user', value: 'WORKSTATION-042\\admin', threat_score: 40 }
      ]
    }
  },
  {
    id: 'step-5',
    name: 'guardrail_check',
    status: 'completed',
    started_at: '2026-03-10T10:00:06.100Z',
    completed_at: '2026-03-10T10:00:06.500Z',
    duration_ms: 400,
    guardrail_score: 87,
    guardrail_threshold: 50,
    input: { validation_checks: ['json_schema', 'entity_coverage', 'verdict_confidence', 'no_hallucination'] },
    output: {
      score: 87,
      threshold: 50,
      passed: true,
      checks: {
        json_schema: { passed: true, score: 95 },
        entity_coverage: { passed: true, score: 82 },
        verdict_confidence: { passed: true, score: 88 },
        no_hallucination: { passed: true, score: 83 }
      }
    }
  },
  {
    id: 'step-6',
    name: 'generate_report',
    status: 'completed',
    started_at: '2026-03-10T10:00:06.500Z',
    completed_at: '2026-03-10T10:00:08.600Z',
    duration_ms: 2100,
    model_name: 'hydra-standard',
    input: { template: 'incident_report_v1' },
    output: {
      severity: 'high',
      verdict: 'malicious',
      confidence: 0.94,
      title: 'C2 Beacon Communication — updateservice-cdn.net',
      recommendation: 'Block domain at DNS/firewall, isolate WORKSTATION-042, investigate lateral movement'
    }
  },
  {
    id: 'step-7',
    name: 'complete',
    status: 'completed',
    started_at: '2026-03-10T10:00:08.600Z',
    completed_at: '2026-03-10T10:00:08.700Z',
    duration_ms: 100,
    output: {
      total_duration_ms: 8700,
      entities_extracted: 5,
      verdict: 'malicious',
      confidence: 0.94,
      report_generated: true,
      playbook_triggered: 'c2_response'
    }
  }
];
```

### 5.2 Demo Mode Hook

```typescript
// src/hooks/useDemo.ts
// When demo mode is active:
//   - Don't poll API — use hardcoded C2_BEACON_STEPS
//   - Reveal steps one at a time with realistic timing delays
//   - Step 1 appears at T+0.5s, Step 2 at T+4.7s, etc.
//   - This ensures the waterfall "animates" even without a backend

// Usage:
// const { steps, isDemo, startDemo } = useDemo('c2_beacon');
// If isDemo: render steps from demo data with timed reveals
// If not demo: poll real API endpoint
```

### 5.3 DemoSelector Component

```typescript
// src/components/DemoSelector.tsx
// Simple card with:
//   - Title: "Run Demo Investigation"
//   - Description: "See HYDRA investigate a C2 beacon in real-time"
//   - Button: "Start Demo" (blue, prominent)
//   - On click: navigate to /investigations/demo-001/waterfall?demo=true
```

### 5.4 DemoBanner Component

```typescript
// Sticky banner at top when ?demo=true or investigation.is_demo=true
// Yellow/amber background
// Text: "🔬 DEMO MODE — This is simulated data for demonstration purposes"
// Right side: "Run Real Investigation →" link
```

---

## Phase 6: Routing & Layout (1 hour)

```typescript
// src/App.tsx
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchInterval: (query) => {
        // Poll every 1s while investigation is running
        const data = query.state.data as any;
        if (data?.status === 'running' || data?.steps?.some((s: any) => s.status === 'running')) {
          return 1000;
        }
        return false;
      },
      staleTime: 0,
    },
  },
});

// Routes:
// /                          → InvestigationList (or redirect to /demo if no investigations)
// /investigations            → InvestigationList
// /investigations/:id        → InvestigationDetail (tabs: waterfall, graph, report)
// /demo                      → DemoSelector
```

**Navbar.tsx:**
```typescript
// Simple top nav:
// Logo: "HYDRA" (bold, blue)
// Links: Investigations | Demo
// Right side: "SOC Automation Platform" tagline
// Professional, clean, minimal — this is what MSSPs see first
```

---

## Phase 7: Docker Integration (30 min)

Add to docker-compose.yml (or update existing dashboard service):

```yaml
  dashboard:
    build:
      context: ./dashboard
      dockerfile: Dockerfile
    ports:
      - "3000:3000"
    environment:
      - VITE_API_URL=http://api:8090
    depends_on:
      - api
    restart: unless-stopped
```

Create `dashboard/Dockerfile`:
```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
# Dev mode for now — production build later
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
```

Or if extending existing dashboard service, just rebuild:
```bash
docker compose build dashboard; docker compose up -d dashboard
```

---

## Phase 8: Verification (1 hour)

### Build Verification
```bash
cd dashboard
npm run build          # Must pass with zero errors
npx tsc --noEmit       # Must pass (strict mode)
npm run dev            # Starts on http://localhost:3000 (or 5173)
```

### Functional Verification Checklist

```
[ ] Dashboard loads at localhost:3000 without console errors
[ ] Navbar shows "HYDRA" branding and navigation links
[ ] /demo page shows "Run Demo Investigation" card
[ ] Click "Start Demo" → navigates to waterfall view
[ ] Demo banner shows "[DEMO MODE]" at top
[ ] Waterfall shows 7 steps appearing with realistic timing
[ ] Each step shows: icon, name, duration badge
[ ] Steps animate in sequence (not all at once)
[ ] Guardrail step shows score bar: 87/100, green, threshold at 50
[ ] Click any step → slide-out panel with JSON input/output
[ ] "Copy to Clipboard" works on JSON blocks
[ ] Progress bar at top fills as steps complete
[ ] Investigation completes in ~9 seconds
[ ] /investigations page shows table (even if empty for now)
[ ] No TypeScript errors (npx tsc --noEmit)
[ ] No build errors (npm run build)
```

### Demo Flow Test (run 3 times)
```
1. Open localhost:3000
2. Click "Demo" in navbar
3. Click "Start Demo"
4. Watch waterfall animate
5. Click "Execute in Sandbox" step → verify JSON panel
6. Click "Quality Validation" step → verify guardrail score
7. Wait for completion
8. Verify total time: 8-10 seconds
9. No crashes, no console errors
```

---

## Definition of Done (Day 7)

### MUST PASS (blocks shipping):
- [ ] Dashboard builds without errors (npm run build)
- [ ] TypeScript strict mode passes (npx tsc --noEmit)
- [ ] Waterfall view works end-to-end with demo data
- [ ] C2 beacon demo runs in 8-10 seconds
- [ ] Demo flow tested 3 times without crashes
- [ ] Professional UI (not ugly, would show to a CISO)

### NICE TO HAVE (don't block on these):
- [ ] Entity graph view with Cytoscape.js
- [ ] Report viewer with markdown rendering
- [ ] Real API integration (vs. hardcoded demo data)
- [ ] Additional demo scenarios

### KILL CONDITIONS:
- If waterfall takes >3 days → ship waterfall only, skip everything else
- If any critical bug prevents demo → fix bug before adding features
- If not demo-ready by Day 7 → cut scope, extend max 2 days

---

## Target File Structure

```
dashboard/
├── src/
│   ├── api/
│   │   └── client.ts              # Axios instance with API base URL
│   ├── components/
│   │   ├── InvestigationWaterfall.tsx   # MUST HAVE — the money component
│   │   ├── StepDetailPanel.tsx          # MUST HAVE — slide-out JSON viewer
│   │   ├── GuardrailScoreBar.tsx        # MUST HAVE — score visualization
│   │   ├── InvestigationList.tsx        # MUST HAVE — table view
│   │   ├── DemoSelector.tsx             # MUST HAVE — demo launcher
│   │   ├── DemoBanner.tsx               # MUST HAVE — demo mode indicator
│   │   ├── Navbar.tsx                   # MUST HAVE — top navigation
│   │   ├── EntityGraph.tsx              # NICE TO HAVE
│   │   └── ReportViewer.tsx             # NICE TO HAVE
│   ├── hooks/
│   │   ├── useInvestigation.ts          # React Query hook for investigation data
│   │   ├── useTimeline.ts              # Polling hook for waterfall steps
│   │   └── useDemo.ts                  # Demo mode with timed step reveals
│   ├── types/
│   │   └── index.ts                    # All TypeScript interfaces
│   ├── demo/
│   │   └── c2BeaconScenario.ts         # Hardcoded C2 beacon demo data
│   ├── App.tsx                         # Router + QueryClient setup
│   ├── main.tsx                        # Entry point
│   └── index.css                       # Tailwind imports
├── index.html
├── package.json
├── tailwind.config.js
├── tsconfig.json
├── vite.config.ts
└── Dockerfile
```

---

## Git Commit (after all verification passes)

```bash
git add -A
git commit -m "Sprint 6: Investigation Dashboard — waterfall, demo mode, MSSP-ready UI

- dashboard/: React 18 + Vite + Tailwind + React Query
- InvestigationWaterfall: Real-time step-by-step visualization
- GuardrailScoreBar: Quality validation with threshold marker
- StepDetailPanel: Click-to-inspect input/output JSON
- DemoSelector + DemoBanner: Self-guided demo mode
- C2 beacon demo scenario: 8-10s autonomous investigation
- Go API: dashboard endpoints (if created)
- Professional UI ready for MSSP demo presentations"
git push
```

Execute. Start with Phase 0, then Phase 1 discovery. Report findings before proceeding to Phase 2+.
```
