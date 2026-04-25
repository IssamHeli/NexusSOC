# NexusSOC — AI-Powered SOC Analyst Agent

An autonomous Security Operations Center analyst that triages alerts, learns from analyst feedback, correlates incidents, and executes response playbooks — all running locally with no cloud LLM dependency.

## Overview

NexusSOC receives security alerts from any source (SIEM, EDR, IDS, TheHive), analyzes them with a local LLM, groups related alerts into incidents, and automatically triggers response playbooks. Every decision is stored as a vector embedding, giving the agent a persistent memory that improves accuracy over time.

```
Alert Source (SIEM / TheHive / manual)
        │
        ▼
POST /ingest ──► Redis Queue ──► Worker
                                    │
                      ┌─────────────┼──────────────┐
                      ▼             ▼              ▼
                  Embedding     Memory          Skills
                  (Ollama)    (pgvector)      (pgvector)
                      │             │              │
                      └─────────────┴──────────────┘
                                    │
                                    ▼
                            Local LLM (Ollama)
                                    │
                          ┌─────────┴─────────┐
                          ▼                   ▼
                      Correlator         Playbook Executor
                    (incidents)       (Discord / Webhook)
                          │                   │
                          ▼                   ▼
                      PostgreSQL           Notifications
```

## Features

### Alert Analysis
- Classifies alerts as **True Positive** or **False Positive** with a calibrated confidence score
- Enrichment-aware: reads pre-computed **AbuseIPDB** and **VirusTotal** scores from the alert payload
- Evidence-based confidence ceiling — score is capped based on available context (no enrichment = max 0.74, missing one source = max 0.88)
- Supports rich alert schema: network IOCs, file hashes, YARA rules, AV detections, C2 infrastructure, data exfiltration details, privilege escalation chains, Sigma rules, kill chain phase, MITRE ATT&CK techniques

### Memory & Self-Learning
- Every analyzed case is embedded (768-dim via `nomic-embed-text`) and stored in PostgreSQL with **pgvector**
- Similar past cases are retrieved at analysis time via cosine similarity (threshold ≥ 0.72)
- Analyst feedback via `POST /feedback/{case_id}` updates skill confidence using **EMA** (Exponential Moving Average)
- Skills with confidence ≥ 0.85 are automatically extracted and reused in future analyses

### Incident Correlation
- Groups related alerts into incidents by shared: source IP, hostname, user, file hash, or explicit `correlated_cases` field
- Tracks kill chain progression and MITRE techniques per incident
- Incident lifecycle: `open` → `investigating` → `closed`

### Automated Playbooks
8 default playbooks included (seeded via `seed_playbooks.py`):

| Playbook | Trigger |
|---|---|
| Brute Force — Block & Notify | brute_force, conf ≥ 0.80 |
| Data Exfiltration — Isolate & Escalate | data_exfiltration, conf ≥ 0.85 |
| Malware — Quarantine Endpoint | malware, conf ≥ 0.85 |
| Privilege Escalation — Lock Account | privilege_escalation, conf ≥ 0.88 |
| Lateral Movement — Network Isolation | lateral_movement, conf ≥ 0.85 |
| Reconnaissance — Log & Monitor | reconnaissance, conf ≥ 0.75 |
| Denial of Service — Rate-Limit & NOC Alert | denial_of_service, conf ≥ 0.80 |
| High-Confidence Unknown — Generic Escalation | unknown, conf ≥ 0.90 |

Playbook action types: `log`, `discord`, `webhook`. Set `PLAYBOOK_DRY_RUN=true` to test without executing real webhooks.

### MITRE ATT&CK Export
`GET /mitre/export` generates a ready-to-import **Navigator layer JSON** aggregating all detected techniques from learned skills and analyzed cases, color-coded by frequency and confidence.

### Async Queue
`POST /ingest` is non-blocking — pushes to Redis and returns a `job_id` immediately. The worker processes jobs in the background. Poll status with `GET /jobs/{job_id}`.

## Tech Stack

| Component | Technology |
|---|---|
| API | FastAPI + Uvicorn |
| Database | PostgreSQL + pgvector (HNSW index) |
| Queue | Redis |
| LLM inference | Ollama (`qwen3:1.7b` default) |
| Embeddings | Ollama (`nomic-embed-text`, 768 dim) |
| Notifications | Discord webhooks |
| Container | Docker |

## Requirements

- Docker & Docker Compose
- [Ollama](https://ollama.ai) running locally with the following models pulled:
  ```bash
  ollama pull qwen3:1.7b
  ollama pull nomic-embed-text
  ```

## Choosing a Model for Your Hardware

NexusSOC runs entirely locally — no cloud API needed. The LLM model is fully configurable via the `OLLAMA_MODEL` environment variable. Pick the model that fits your hardware:

| RAM / VRAM | Recommended Model | Notes |
|---|---|---|
| 4 GB | `qwen3:1.7b` *(default)* | Fast, low resource, good for basic triage |
| 8 GB | `mistral:7b` or `llama3.1:8b` | Better reasoning, more accurate analysis |
| 16 GB | `qwen3:14b` or `mistral-nemo:12b` | Strong accuracy, handles complex alerts well |
| 24 GB+ | `qwen3:32b` or `llama3.1:70b` (quantized) | Near-professional SOC analyst quality |

To switch model, pull it with Ollama then set the env var:
```bash
ollama pull mistral:7b
```
```env
OLLAMA_MODEL=mistral:7b
```

> **Note:** The embedding model (`nomic-embed-text`) must stay fixed — changing it invalidates all stored vector embeddings in the database and breaks memory/skill retrieval. Only change it on a fresh install.

## Quick Start

**1. Clone and configure**
```bash
git clone <repo-url>
cd SocAnalyst_Ai_Agent
cp ai_agent_src/.env.example .env   # edit with your values
```

**2. Environment variables**

| Variable | Required | Default | Description |
|---|---|---|---|
| `DB_HOST` | yes | — | PostgreSQL host |
| `DB_USER` | yes | — | PostgreSQL user |
| `DB_PASS` | yes | — | PostgreSQL password |
| `DB_NAME` | yes | — | PostgreSQL database name |
| `DB_PORT` | no | `5432` | PostgreSQL port |
| `REDIS_URL` | no | — | Redis URL (disables async ingest if unset) |
| `OLLAMA_HOST` | no | `host.docker.internal` | Ollama host |
| `OLLAMA_PORT` | no | `11434` | Ollama port |
| `OLLAMA_MODEL` | no | `qwen3:1.7b` | LLM model name |
| `EMBED_MODEL` | no | `nomic-embed-text` | Embedding model name |
| `DISCORD_WEBHOOK` | no | — | Discord webhook URL for alerts |
| `PLAYBOOK_DRY_RUN` | no | `true` | Set to `false` to execute real webhooks |

**3. Start the full stack**

The `docker-compose.yml` lives in the project root and wires up all services:

```bash
docker compose up --build
```

This starts:
| Service | URL |
|---|---|
| AI Agent API | http://localhost:8001 |
| API Docs (Swagger) | http://localhost:8001/docs |
| SOC Frontend | http://localhost:5173 |
| Grafana | http://localhost:3000 |
| PostgreSQL | localhost:5432 |
| Redis | localhost:6379 |

**4. Seed default playbooks**
```bash
python ai_agent_src/seed_playbooks.py http://localhost:8001
```

## API Reference

### Alert Ingestion

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/ingest` | Queue alert for async analysis (returns `job_id`) |
| `POST` | `/analyze-case` | Synchronous analysis |
| `GET` | `/jobs/{job_id}` | Poll async job status and result |
| `GET` | `/queue/depth` | Number of alerts waiting in queue |

### Analysis & Feedback

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/feedback/{case_id}` | Submit analyst verdict (correct/incorrect) — updates skill confidence |
| `GET` | `/memory` | View recent analyzed cases |

### Skills

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/skills` | List learned skills (filter by `min_confidence`) |
| `POST` | `/skills/{id}/feedback` | Rate a skill directly — updates confidence via EMA (α=0.15) |
| `DELETE` | `/skills/{id}` | Remove a bad or irrelevant skill |

`POST /skills/{id}/feedback` body:
```json
{ "correct": true, "analyst_note": "optional note" }
```
Returns `confidence_before` and `confidence_after` so the UI can update in real time.

### Incidents

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/incidents` | List incidents (filter by `status`) |
| `GET` | `/incidents/{id}` | Incident detail |
| `PATCH` | `/incidents/{id}/status` | Update status: `open` / `investigating` / `closed` |

### Playbooks

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/playbooks` | List all playbooks |
| `POST` | `/playbooks` | Create a playbook |
| `DELETE` | `/playbooks/{id}` | Delete a playbook |
| `GET` | `/playbooks/executions` | Execution audit log |

### System

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | DB status, model names, skill/memory counts, playbook mode |
| `GET` | `/mitre/export` | Download MITRE ATT&CK Navigator layer JSON |

## Example Alert Payload

```json
{
  "sourceRef": "CASE-001",
  "title": "Suspicious outbound connection to known C2",
  "description": "EDR detected process making repeated connections to flagged external IP.",
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

## Simulation & Testing

Run the built-in simulation harness to validate the full pipeline against 12 pre-defined scenarios (APT chains, ransomware, false positives):

```bash
python advanced_soc_simulation.py
```

Results are saved to `sim_results.json` (gitignored — generated output only).

## Alert Sources Supported

- Suricata IDS
- Splunk DLP
- Endpoint Detection and Response (EDR)
- NetFlow Analysis
- Windows Event Logs + Sigma Rules
- SIEM
- Web Application Firewall

## Project Structure

```
SocAnalyst_Ai_Agent/
├── docker-compose.yml         # Full stack: API + worker + DB + Redis + Grafana + frontend
├── .env                       # Your environment variables (gitignored)
├── ai_agent_src/              # This repo — AI agent backend
│   ├── main.py                # FastAPI app — endpoints, LLM analysis, skill learning
│   ├── correlator.py          # Alert → incident correlation logic
│   ├── playbooks.py           # Playbook execution engine
│   ├── seed_playbooks.py      # Seeds 8 default response playbooks
│   ├── worker.py              # Redis queue worker
│   ├── advanced_soc_simulation.py  # End-to-end simulation harness
│   ├── Dockerfile
│   ├── requirements.txt
│   └── .env.example
├── grafana/                   # Grafana dashboard config
└── soc-frontend/              # SOC dashboard frontend
```

## License

MIT
