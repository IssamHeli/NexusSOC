---
name: NexusSOC project overview
description: Core facts about the NexusSOC graduation project — stack, paths, purpose, key design decisions
type: project
---

Fully local AI-powered SOC analyst platform built as a cybersecurity graduation project (projet fin de formation).

**Root path:** `/Users/macgr/Desktop/cyber_security/project_fin_de_formation/SocAnalyst_Ai_Agent/`
**Agent source:** `ai_agent_src/` (FastAPI backend)
**Frontend:** `soc-frontend/` (React + TypeScript + Vite)
**Grafana dashboards:** `grafana/dashboards/`

**Why:** Graduation project demonstrating autonomous alert triage, self-learning via analyst feedback, and automated incident response — all running locally with no cloud LLM dependency.

**How to apply:** When the user asks about this project, all paths, services, and design decisions below are already established — don't suggest alternatives unless asked.

## Stack
| Service | Tech | Port |
|---|---|---|
| AI Agent API | FastAPI + Uvicorn | 8001 |
| SOC Frontend | React/Vite | 5173 |
| Grafana | Grafana OSS | 3000 |
| Database | PostgreSQL 15 + pgvector | 5432 |
| Queue | Redis 7 | 6379 |
| LLM + Embeddings | Ollama | 11434 |

Default LLM: `qwen3:1.7b` (configurable via `OLLAMA_MODEL` env var)
Embedding model: `nomic-embed-text` (768-dim, MUST NOT change after first run — invalidates all pgvector data)

## Key design decisions
- Evidence-based confidence ceiling: no enrichment → max 0.74, missing one source → max 0.88 (prevents LLM overconfidence)
- EMA for skill confidence updates: α=0.15 — `new = old + 0.15 * (target - old)`
- pgvector HNSW index for cosine similarity memory/skill retrieval (threshold ≥ 0.72)
- asyncpg returns embeddings as string, not list — requires `isinstance(emb, str)` check before formatting
- Redis queue: `/ingest` is non-blocking (returns `job_id`), `/analyze-case` is synchronous

## Docker
Stack starts with: `docker compose up --build` from root
Rebuild single service: `docker compose up --build -d ai-agent-api`
