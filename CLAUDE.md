# NexusSOC — Claude Code Instructions

## Project
AI-powered SOC analyst platform. FastAPI backend (`ai_agent_src/`) + React frontend (`soc-frontend/`) + PostgreSQL/pgvector + Redis + Ollama (local LLM). See `memory/` for full context.

## Memory

Memory files live at `memory/` inside this project folder. At the **start of every session**, read all files in `memory/` to restore full project context. At the **end of every session** (before stopping), update the relevant memory files with any new decisions, features implemented, bugs fixed, or path changes.

### When to update memory
- New feature implemented → update `memory/project_completed_features.md`
- New design decision made → update `memory/project_nexussoc.md`
- New user preference observed → update `memory/user_profile.md`
- Push / deployment status changes → update `memory/project_push_status.md`
- New topic needs tracking → create a new file and add it to `memory/MEMORY.md`

## Stack quick reference
| Service | Port |
|---|---|
| AI Agent API (FastAPI) | 8001 |
| SOC Frontend (React) | 5173 |
| Grafana | 3000 |
| PostgreSQL + pgvector | 5432 |
| Redis | 6379 |
| Ollama | 11434 |

## Key invariants
- Embedding model (`nomic-embed-text`) must never change after first run — breaks all pgvector data
- EMA alpha = 0.15 for all confidence updates
- asyncpg returns embeddings as string — always use `isinstance(emb, str)` check before formatting
- Confidence ceiling: no enrichment → max 0.74, one source missing → max 0.88
