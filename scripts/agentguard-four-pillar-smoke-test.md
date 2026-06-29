# AgentGuard Four-Pillar Smoke Test — Script Documentation

Documentation for `scripts/agentguard-four-pillar-smoke-test.ps1`.

This harness validates AgentGuard's four pillars — **Observability, Prompt Management, Evaluations, Security & Governance** — by exercising the public HTTP API end to end (ingest → wait for the async worker → verify via API). It is **not** just an "API returned 200" check; each test verifies that the data actually became visible/queryable.

---

## What it does

- Authenticates to AgentGuard's public API using **Basic Auth** (`publicKey:secretKey`, base64-encoded).
- Sends synthetic-but-realistic traces, generations, prompts, and scores.
- Attaches a **shared metadata block** to every trace so test data is easy to filter in the dashboard.
- **Polls** for asynchronously-processed data (ingestion is handled by a background worker).
- Prints `PASS` / `FAIL` / `SKIP` per test and **exits non-zero if any required test fails**.
- Tests that depend on functionality **not exposed by the public API** are reported as honest `SKIP` (with a reason) instead of being faked as `PASS`.

---

## Requirements

- Windows PowerShell 5.1+ (or PowerShell 7+).
- A running AgentGuard instance reachable at `-BaseUrl`.
- A valid project **public/secret API key pair**.

---

## Parameters

| Parameter | Default | Purpose |
|---|---|---|
| `-BaseUrl` | `http://localhost:3001` | AgentGuard instance base URL (trailing slash trimmed). |
| `-PublicKey` | `$env:AG_PUBLIC_KEY` | Public API key (`pk-...`). |
| `-SecretKey` | `$env:AG_SECRET_KEY` | Secret API key (`sk-...`). |
| `-ProjectId` | `""` | Printed in the header only; auth scoping rides on the key pair. |
| `-Environment` | `default` | Environment tag applied to traces/observations/scores. |
| `-TimeoutSeconds` | `60` | Max wait per poll loop for async data to appear. |
| `-TestRunId` | `run-<yyyyMMddHHmmss>` | Correlation id stamped into all test metadata. |
| `-SecondaryPublicKey` | `$env:AG_SECONDARY_PUBLIC_KEY` | Optional 2nd project key — upgrades GOV-03 to a real cross-project isolation check. |
| `-SecondarySecretKey` | `$env:AG_SECONDARY_SECRET_KEY` | Secret for the secondary project. |

The script exits with an error immediately if `-PublicKey` / `-SecretKey` are missing.

---

## How to run

```powershell
# Using environment variables for keys
$env:AG_PUBLIC_KEY = "pk-..."
$env:AG_SECRET_KEY = "sk-..."
.\scripts\agentguard-four-pillar-smoke-test.ps1 -BaseUrl "https://app.agentguard.ai"

# Passing keys explicitly
.\scripts\agentguard-four-pillar-smoke-test.ps1 `
  -BaseUrl "https://app.agentguard.ai" `
  -PublicKey "pk-..." `
  -SecretKey "sk-..." `
  -Environment "smoke"

# With cross-project isolation verification (GOV-03 strong mode)
.\scripts\agentguard-four-pillar-smoke-test.ps1 `
  -PublicKey "pk-A" -SecretKey "sk-A" `
  -SecondaryPublicKey "pk-B" -SecondarySecretKey "sk-B"
```

---

## Shared metadata

Every trace/observation carries this block (via `New-SharedMetadata`), making test data filterable in the dashboard:

```json
{
  "testRunId":   "run-20260629...",
  "tenantId":    "customer-<slug>-<suffix>",
  "businessId":  "workspace-<slug>-<suffix>",
  "featureId":   "<workflow>-<capability>-<suffix>",
  "environment": "default",
  "source":      "agentguard-api-validation"
}
```

`tenantId`, `businessId`, and a per-run `RunSuffix` are randomized each run from realistic customer/workflow slug pools so repeated runs don't collide.

---

## API endpoints used

| Purpose | Method & path |
|---|---|
| Ingest traces/generations (batch) | `POST /api/public/ingestion` |
| Read a trace | `GET /api/public/traces/{id}` |
| List traces (filter by userId/env) | `GET /api/public/traces?userId=&environment=` |
| Read an observation | `GET /api/public/observations/{id}` |
| Metrics (cost by dimension) | `GET /api/public/metrics?query=<urlencoded json>` |
| Create prompt / new version | `POST /api/public/v2/prompts` |
| Read prompt version | `GET /api/public/v2/prompts/{name}?version=N` |
| Create score | `POST /api/public/scores` |
| Read score | `GET /api/public/v2/scores/{id}` |
| Score config (human review) | `POST /api/public/score-configs` |
| Annotation queue + items | `POST /api/public/annotation-queues`, `.../items` |

---

## Key helper functions

- **`Invoke-AgRequest` / `Invoke-AgGet` / `Invoke-AgPost` / `Invoke-AgPatch`** — HTTP wrappers returning a uniform `{ Ok, Data, StatusCode, Error }` object (never throw).
- **`New-TraceEvent` / `New-GenerationEvent`** — build ingestion event envelopes (`trace-create` / `generation-create`).
- **`Send-IngestionBatch`** — posts an array of events to the ingestion endpoint.
- **`Wait-For`** — generic poll-until-non-null with deadline; base for the waiters below.
- **`Wait-ForTrace` / `Wait-ForObservation` / `Wait-ForScore` / `Wait-ForMetricRow`** — poll until a specific object/metric row appears.
- **`New-MetadataRunFilter`** — builds the `testRunId` metadata filter used by metric queries.
- **`Report-Pass` / `Report-Fail` / `Report-Skip`** — record + print results; `Report-Fail` accepts a `Required` flag.

---

## Test coverage (as currently implemented)

> Note: Prompt Management and Evaluations IDs in the script were renumbered and do **not** line up 1:1 with the original notes. See the "vs. spec" column.

### [Observability]

| Script ID | Check | Mode | vs. spec |
|---|---|---|---|
| OBS-01 | Trace ingested and visible | real | = OBS-01 |
| OBS-02 | Observation latency populated (`>0ms`) | real | = OBS-02 |
| OBS-03 | Cost by feature (`name` dimension, `sum_totalCost > 0`) | real | = OBS-03 |
| OBS-04 | Cost by tenant (`userId` dimension, `sum_totalCost > 0`) | real | = OBS-04 |
| OBS-05 | Error observation captured (`level = ERROR`) | real | = OBS-05 |
| OBS-06 | Spend alert threshold | **SKIP** — tRPC/session-auth only | = OBS-06 |
| — | App performance dashboard data | **not present** | OBS-07 missing |

### [Prompt Management]

| Script ID | Check | Mode | vs. spec |
|---|---|---|---|
| PROMPT-01 | Create prompt v1 + re-fetch & verify text | real | covers spec PROMPT-01 + PROMPT-02 |
| PROMPT-02 | Create prompt v2 (version increments) | real | = spec PROMPT-03 |
| PROMPT-03 | Fetch latest version, verify content | real | = spec PROMPT-04 |
| PROMPT-04 | Test prompt with sample input | **SKIP** — playground is session-auth only | = spec PROMPT-05 |
| — | Compare / validate version history | **not present** | spec PROMPT-06 missing |

### [Evaluations]

| Script ID | Check | Mode | vs. spec |
|---|---|---|---|
| EVAL-01 | Create numeric score on the OBS-01 trace | real | = EVAL-01 |
| EVAL-02 | Read score back, verify value & name | real | = EVAL-02 |
| EVAL-03 | Human review: score-config → annotation queue → queue item | real | = EVAL-03 |
| EVAL-04 | LLM-as-a-Judge evaluator config/run | **SKIP** — internal-only API | = EVAL-04 |
| — | Run evaluator on sample trace | **not present** | spec EVAL-05 missing |
| — | Verify evaluation result in dashboard/API | **not present** | spec EVAL-06 missing |

### [Security & Governance]

| Script ID | Check | Mode | vs. spec |
|---|---|---|---|
| GOV-01 | PII redaction — asserts raw email/phone **absent** from stored input | real (requires server-side redaction enabled) | = GOV-01 |
| GOV-02 | Prompt-injection input round-trips with marker tag | **marker only** — not a detection/blocking assertion | = GOV-02 |
| GOV-03 | Tenant isolation — userId-scoped query excludes other tenant; cross-project invisibility if secondary key supplied | real | = GOV-03 |
| GOV-04 | Access control / RBAC | **SKIP** — no scoped test user configured | = GOV-04 |
| GOV-05 | Audit trail / activity | **SKIP** — no public read endpoint | = GOV-05 |
| GOV-06 | Policy/risk tags round-trip | **marker only** — not an enforcement assertion | = GOV-06 |
| GOV-07 | Toxic/harmful content blocking | **SKIP** — no public endpoint (extra) | beyond spec |
| GOV-08 | Secrets & token scanner | **SKIP** — no public endpoint (extra) | beyond spec |
| GOV-09 | Output schema enforcement | **SKIP** — not exposed via public API (extra) | beyond spec |

---

## Output format

Results are grouped by pillar and printed live, e.g.:

```
AgentGuard Four Pillar Smoke Test
BaseUrl: https://app.agentguard.ai
Environment: default
TestRunId: run-20260629...

[Observability]
PASS OBS-01 Trace ingestion visible
PASS OBS-02 Latency tracking (latency=1840ms)
...
SKIP OBS-06 Spend alert threshold - API not available ...

Result:
Required Passed: 12/12
Skipped: 8
Failed: 0
```

A test recorded via `Report-Pass` is counted as **required**; `Report-Skip` is **not required** (and never fails the run); `Report-Fail` is required unless explicitly marked optional.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No **required** test failed (skips are OK). |
| `1` | At least one required test failed, **or** missing keys at startup. |

---

## Known caveats

1. **GOV-01 depends on server-side PII redaction.** It asserts the raw email/phone is *not* present in the stored trace input. On an instance without masking/redaction configured, the input round-trips verbatim and GOV-01 fails (a correct result, but it tests server config as much as the harness).
2. **`-ProjectId` is cosmetic** — printed in the header but not used in requests; project scoping comes from the API key pair.
3. **GOV-02 / GOV-06 are marker-only** — they confirm the trace carries the marker/tags, not that injection or policy was actually detected/enforced.
4. **Prompt/Eval IDs are renumbered** relative to the original notes (see "vs. spec" columns above).
5. **Summary format differs** from the notes' `Result: N/N passed` line — it prints `Required Passed / Skipped / Failed` instead.
6. **Missing suggested cases:** OBS-07 (app performance), PROMPT-06 (version history), EVAL-05 (run evaluator), EVAL-06 (verify eval result).
