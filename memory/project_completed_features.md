---
name: NexusSOC completed features
description: All implemented endpoints, frontend panels, files created, and bugs fixed — use to avoid re-implementing
type: project
---

All features below are implemented and verified working as of 2026-04-25.

## Backend (ai_agent_src/main.py)
- `POST /analyze-case` — synchronous alert analysis with TP/FP classification
- `POST /ingest` — async alert ingestion via Redis queue (returns job_id)
- `GET /jobs/{job_id}` — poll async job status
- `POST /feedback/{case_id}` — analyst feedback on a case, updates skill confidence via EMA
- `GET /skills` — list learned skills with `min_confidence` filter
- `POST /skills/{id}/feedback` — direct skill rating, updates confidence via EMA, returns `confidence_before` + `confidence_after`
- `DELETE /skills/{id}` — remove a skill
- `GET /memory` — recent analyzed cases
- `GET /incidents`, `GET /incidents/{id}`, `PATCH /incidents/{id}/status`
- `GET /playbooks`, `POST /playbooks`, `DELETE /playbooks/{id}`
- `GET /playbooks/executions` — audit log
- `GET /mitre/export` — MITRE ATT&CK Navigator layer JSON
- `GET /health`, `GET /queue/depth`

## Frontend panels (soc-frontend/src/components/)
- **Dashboard.tsx** — health, counters, recent activity; has error state
- **KillChainTimeline.tsx** — incidents across kill chain phases
- **IncidentsPanel.tsx** — list + status management
- **MemoryPanel.tsx** — cases table + MemoryDetail drill-in view; localStorage feedback (`nexussoc:feedback`)
- **SkillsPanel.tsx** — skills table + SkillDetail drill-in view; localStorage feedback (`nexussoc:skill-feedback`); real-time confidence update via `res.confidence_after`
- **PlaybooksPanel.tsx** — playbooks + executions + create/delete; has detail view
- **SimulationPanel.tsx** — trigger simulation harness

## Files present
- `ai_agent_src/.env.example` — full env var template
- `ai_agent_src/.gitignore`
- `ai_agent_src/LICENSE` (MIT)
- `ai_agent_src/README.md` — full API reference
- Root `README.md` — platform overview + quick start
- Root `.gitignore` — covers .env, .DS_Store, .claude/, sim_results.json, node_modules, dist
- `soc-frontend/README.md` — panel docs + dev/build instructions

## Known quirks / bugs fixed
- asyncpg embedding returned as string — fixed with isinstance check in `update_skill_feedback()`
- Skill feedback was silently failing until Docker rebuild after code change
- SkillsPanel stale closure — fixed with useCallback + useEffect([load]) pattern
