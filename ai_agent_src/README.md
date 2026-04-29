# NexusSOC — Backend (`ai_agent_src/`)

FastAPI service that triages security alerts with a multi-LLM router, stores cases as pgvector embeddings, executes response playbooks, and exposes everything through a JWT/RBAC-protected API.

> Root `README.md` covers the full platform (frontend, Grafana, screenshots, quick start). This document is the backend-only reference.

---

## Architecture

```
SIEM webhook ─► POST /ingest/{connector}
                        │ normalize → SecurityAlert
                        ▼
                  Redis queue ──► Worker ──► retry (2/4/8 s) ──► DLQ on 3rd fail
                        │
                        ▼
            ┌──────────────────────────┐
            │  /analyze-case (sync)    │
            │   or worker (async)      │
            │                          │
            │  ┌────────────────────┐  │
            │  │   LLM Router       │  │
            │  │ primary + fallback │  │
            │  │ Ollama / OpenAI /  │  │
            │  │ Anthropic          │  │
            │  └─────────┬──────────┘  │
            │            ▼             │
            │   pgvector memory        │
            │   skills (EMA α=0.15)    │
            │   correlator → incidents │
            │   playbooks → notif      │
            └──────────────────────────┘
                        │
                        ▼
                Discord / Slack / Teams · STIX 2.1 · MITRE Navigator
```

Embeddings stay pinned to Ollama (`nomic-embed-text`). Changing the embed model invalidates every stored vector — pick once, keep forever.

---

## Modules

| File | Role |
|---|---|
| `main.py` | FastAPI app, all endpoints, prompt build, embedding/skill flow |
| `auth.py` | JWT (access + refresh), bcrypt hashing, `require_role`, `/auth/*` + `/users/*` routers, `seed_admin` |
| `security.py` | Middlewares: SecurityHeaders, RequestSize 1 MB, RateLimit (Redis sliding window), AuditLog. Helpers: `sanitize_str`, `is_safe_webhook_url` (SSRF guard) |
| `worker.py` | Standalone Redis worker. `MAX_RETRIES=3`, exponential backoff, DLQ `nexussoc:dlq`, heartbeat key `nexussoc:worker:heartbeat` |
| `playbooks.py` | Playbook engine. `_safe_format` regex avoids JSON-brace `KeyError` |
| `correlator.py` | Groups related alerts into incidents by shared indicators |
| `llm/{base,ollama,openai,anthropic,router}.py` | LLM abstraction. Router walks `LLM_FALLBACK_CHAIN` on `LLMError` |
| `connectors/{wazuh,elastic,splunk,qradar,generic}.py` | Normalize raw SIEM payloads → `SecurityAlert`. `CONNECTOR_REGISTRY` exposes them |
| `plugins/loader.py` | Hard-coded whitelist registry. `PLUGIN_*_ENABLED` env toggles |
| `plugins/notification/*` | Discord, Slack, Teams webhook senders |
| `plugins/enrichment/*` | VirusTotal, AbuseIPDB (passive stubs — extend via `EnrichmentPlugin`) |
| `plugins/export/*` | MITRE ATT&CK Navigator layer JSON, STIX 2.1 bundle |
| `migrations/versions/0001_initial_schema.py` | Alembic async migrations — runs in Docker `CMD` before uvicorn |
| `shuffle_simulation.py` | End-to-end SOAR pipeline simulation (16 scenarios) |
| `seed_playbooks.py` | Loads 8 default response playbooks |

---

## API surface (versioned in `main.py`)

All endpoints require JWT and a minimum role (`viewer < analyst < admin`) when `AUTH_ENABLED=true`.

### Auth
| Method | Path | Notes |
|---|---|---|
| `POST` | `/auth/login` | Returns access + refresh token. Rate limited 5/min |
| `POST` | `/auth/refresh` | Rotates refresh token |
| `POST` | `/auth/logout` | Revokes JTI in Redis |
| `GET` | `/auth/me` | Current user info |

### User management (admin)
| Method | Path |
|---|---|
| `GET` `POST` | `/users` |
| `PATCH` | `/users/{username}/role` |
| `PATCH` | `/users/{username}/password` |
| `DELETE` | `/users/{username}` |

Guards: no self-demote, no self-delete, no last-admin-delete.

### Ingestion
| Method | Path | Role | Notes |
|---|---|---|---|
| `POST` | `/ingest` | analyst | Async — pre-normalized payload, returns `job_id` |
| `POST` | `/ingest/{connector_name}` | analyst | Webhook ingress per SIEM. 404/422/202 |
| `POST` | `/ingest/batch` | analyst | Bulk JSON. Optional `connector_name`, auto-detect when omitted. Cap `BATCH_MAX_ALERTS` (default 100) → 413; empty array → 422 |
| `GET` | `/jobs/{job_id}` | analyst | Poll status |
| `GET` | `/connectors` | viewer | Names list |

### Analysis
| Method | Path | Role | Notes |
|---|---|---|---|
| `POST` | `/analyze-case` | analyst | Sync. 503 on `LLMError` (router exhausted) |
| `POST` | `/feedback/{case_id}` | analyst | Updates skill confidence via EMA (α=0.15) |
| `GET` | `/memory` | viewer | Recent analyzed cases |

### Skills
| Method | Path | Role |
|---|---|---|
| `GET` | `/skills` | viewer |
| `POST` | `/skills/{id}/feedback` | analyst |
| `DELETE` | `/skills/{id}` | admin |

### Incidents
| Method | Path | Role |
|---|---|---|
| `GET` | `/incidents` | viewer |
| `GET` | `/incidents/{id}` | viewer |
| `PATCH` | `/incidents/{id}/status` | analyst |

### Playbooks
| Method | Path | Role |
|---|---|---|
| `GET` `POST` `DELETE` | `/playbooks{,/{id}}` | viewer / admin / admin |
| `GET` | `/playbooks/executions` | viewer |

### Queue + DLQ
| Method | Path | Role |
|---|---|---|
| `GET` | `/queue/depth` | viewer |
| `GET` | `/queue/dlq` | admin |
| `POST` | `/queue/dlq/clear` | admin |
| `POST` | `/queue/dlq/requeue-all` | admin |

### Plugins, exports, audit, system
| Method | Path | Role |
|---|---|---|
| `GET` | `/plugins` | viewer |
| `GET` | `/mitre/export` | viewer |
| `GET` | `/export/case/{case_id}/stix2` | analyst |
| `GET` | `/admin/audit-logs` | admin |
| `GET` | `/health` | open — per-dependency `{status, latency_ms}` for db / redis / ollama / worker / plugins / connectors / llm |
| `GET` | `/metrics` | open — Prometheus instrumentator + custom metrics |

Custom Prometheus metrics: `nexussoc_alerts_total{decision,source}`, `nexussoc_analysis_duration_seconds`, `nexussoc_confidence_score`, `nexussoc_queue_depth`.

---

## Configuration

All config is environment-driven. See `.env.example` for the full template.

| Section | Variables |
|---|---|
| Database | `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASS`, `DB_NAME` |
| Redis | `REDIS_URL` |
| LLM router | `LLM_BACKEND`, `LLM_FALLBACK_CHAIN` |
| Ollama | `OLLAMA_HOST`, `OLLAMA_PORT`, `OLLAMA_MODEL`, `EMBED_MODEL` |
| OpenAI | `OPENAI_API_KEY`, `OPENAI_MODEL`, `OPENAI_BASE_URL` |
| Anthropic | `ANTHROPIC_API_KEY`, `ANTHROPIC_MODEL`, `ANTHROPIC_MAX_TOKENS` |
| Auth | `AUTH_ENABLED`, `JWT_SECRET` (≥32 chars when auth on), `ACCESS_TOKEN_EXPIRE_MINUTES`, `REFRESH_TOKEN_EXPIRE_DAYS`, `ADMIN_USERNAME`, `ADMIN_PASSWORD`, `API_KEY` |
| CORS / HTTPS | `CORS_ORIGINS`, `HTTPS_ONLY` |
| Plugins | `PLUGIN_*_ENABLED` (Discord, Slack, Teams, VT, AbuseIPDB, MITRE, STIX2) plus `*_WEBHOOK` / `*_API_KEY` companions |
| Batch ingest | `BATCH_MAX_ALERTS` (default `100`) |
| Playbooks | `PLAYBOOK_DRY_RUN` (default `true`) |

> Changing `EMBED_MODEL` after first boot invalidates every embedded case. Pick once, keep forever.

---

## Hardware sizing for local LLMs

| RAM | Suggested Ollama model |
|---|---|
| 4 GB | `qwen3:1.7b` *(default)* |
| 8 GB | `mistral:7b`, `llama3.1:8b` |
| 16 GB | `qwen3:14b`, `mistral-nemo:12b` |
| 24 GB+ | `qwen3:32b`, quantized `llama3.1:70b` |

Switch via `OLLAMA_MODEL` after `ollama pull`.

---

## Example alert payload

```json
{
  "sourceRef": "CASE-001",
  "title": "Outbound C2 beacon",
  "description": "EDR detected periodic connections to flagged IP.",
  "source": "Endpoint Detection and Response (EDR)",
  "severity": "high",
  "attack_type": "malware",
  "hostname": "WORKSTATION-42",
  "user": "jdoe",
  "network": {
    "source_ip": "192.168.1.42",
    "destination_ip": "185.220.101.5",
    "protocol": "TCP",
    "port": 443
  },
  "file_analysis": {
    "file_name": "svchost32.exe",
    "file_hash_sha256": "a3f1...c9d2",
    "c2_infrastructure": "185.220.101.5:443"
  },
  "kill_chain_phase": "c2",
  "mitre_techniques": ["T1071.001", "T1055"],
  "ip_abuse_score": 97,
  "vt_malicious": 42,
  "vt_total": 68
}
```

Connector-specific raw payloads (Wazuh, Elastic, Splunk, QRadar) are normalized before reaching this shape — see `connectors/*.py` for each format.

---

## Security baseline

- JWT with refresh-token rotation; Redis blocklist for revoked JTIs (`nexussoc:revoked:{jti}`)
- Sliding-window rate limiter per IP and per path
- 1 MB request size cap; OWASP security headers; opt-in HSTS
- SSRF guard on every outbound webhook (RFC1918, link-local, IPv6 ULA)
- Pydantic v2 with `extra="forbid"` on every input model
- Hard-coded plugin registry — no dynamic import paths
- No `eval`, `exec`, `pickle`, `yaml.load`, or `shell=True`
- Audit log middleware persists every state-changing call
- Non-root container (`appuser`, uid 1001), backend / frontend network isolation
- Worker uses an `X-API-Key` header instead of full login flow
- Playbook actions default to `DRY_RUN` — real webhooks require `PLAYBOOK_DRY_RUN=false`

---

## Run locally (without Docker)

```bash
cp .env.example .env
pip install -r requirements.txt
alembic upgrade head
uvicorn main:app --host 0.0.0.0 --port 8001
```

Worker (separate process):

```bash
python worker.py
```

For the full stack (Postgres + Redis + Grafana + Ollama + frontend), use `docker compose up --build` from the repo root.

---

## License

MIT — see root `LICENSE`.
