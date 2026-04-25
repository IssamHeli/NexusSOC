# NexusSOC — AI-Powered Security Operations Platform

A fully local, autonomous SOC platform that triages security alerts with a local LLM, correlates incidents, executes response playbooks, and visualizes threat intelligence — no cloud dependency, no API keys.

## Platform Overview

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         Real SOC Tool Stack                              │
│                                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐                │
│  │  Wazuh   │  │ Suricata │  │  Arkime  │  │   Zeek   │                │
│  │  (SIEM)  │  │  (IDS)   │  │ (Packet) │  │(Network) │                │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘                │
│       └─────────────┴─────────────┴──────────────┘                      │
│                              │ alerts                                    │
│                              ▼                                           │
│                    ┌──────────────────┐                                  │
│                    │  Shuffle  SOAR   │  orchestration & automation      │
│                    └────────┬─────────┘                                  │
│            ┌───────────────┬┴────────────────┐                           │
│            ▼               ▼                 ▼                           │
│     ┌────────────┐  ┌────────────┐   ┌─────────────┐                    │
│     │    MISP    │  │   Cortex   │   │  OpenCTI    │                    │
│     │(Threat     │  │ VT+AbuseIP │   │(GraphQL CTI)│                    │
│     │  Intel)    │  │    DB      │   │             │                    │
│     └────────────┘  └────────────┘   └─────────────┘                    │
│            └───────────────┬─────────────────┘                           │
│                            ▼                                             │
│                    ┌──────────────────┐                                  │
│                    │    TheHive       │  case management                 │
│                    └────────┬─────────┘                                  │
│                             │ enriched case                              │
│                             ▼                                            │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                       NexusSOC                                    │   │
│  │                                                                   │   │
│  │  ┌─────────────────┐   ┌──────────┐   ┌──────────────────────┐  │   │
│  │  │  AI Agent API   │──►│  Redis   │──►│  Background Worker   │  │   │
│  │  │  (FastAPI:8001) │   │  Queue   │   │                      │  │   │
│  │  └────────┬────────┘   └──────────┘   └──────────────────────┘  │   │
│  │           │                                                       │   │
│  │           ▼                                                       │   │
│  │  ┌─────────────────┐   ┌──────────────────────────────────────┐  │   │
│  │  │  Ollama (local) │   │  PostgreSQL + pgvector               │  │   │
│  │  │  LLM + Embed    │   │  Memory · Skills · Incidents         │  │   │
│  │  └─────────────────┘   └──────────────────────────────────────┘  │   │
│  │           │                                                       │   │
│  │           ▼                                                       │   │
│  │  ┌─────────────────┐   ┌──────────────────────────────────────┐  │   │
│  │  │  SOC Frontend   │   │  Grafana Dashboards                  │  │   │
│  │  │  (React:5173)   │   │  Overview · Kill Chain · Skills      │  │   │
│  │  └─────────────────┘   └──────────────────────────────────────┘  │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────┘
```

## SOC Tool Stack

NexusSOC sits at the end of a real enterprise SOC pipeline. Each layer has a defined role:

| Layer | Tool | Role |
|---|---|---|
| Detection | **Wazuh** | SIEM — host-based detection, log aggregation, rule-based alerting |
| Detection | **Suricata** | IDS/IPS — network signature detection (EVE JSON) |
| Detection | **Arkime** | Full-packet capture and session indexing |
| Detection | **Zeek** | Network traffic analysis — DNS, HTTP, notice logs |
| Orchestration | **Shuffle SOAR** | Central automation hub — receives raw alerts, coordinates enrichment, creates cases, forwards to NexusSOC |
| Threat Intel | **MISP** | Event-based IOC lookup (`/events/restSearch`) |
| Enrichment | **Cortex** | Runs VirusTotal (file/IP reputation) and AbuseIPDB analyzers |
| Threat Intel | **OpenCTI** | GraphQL-based CTI observable lookup |
| Case Management | **TheHive** | Creates structured cases with enriched context |
| AI Triage | **NexusSOC** | Final autonomous TP/FP classification, playbook execution, self-learning |

The `shuffle_simulation.py` script simulates this full pipeline end-to-end for testing and demo purposes.

## Components

### AI Agent (`ai_agent_src/`)
The core of the platform. A FastAPI service that:
- Receives enriched cases from Shuffle/TheHive and classifies them as **True Positive** or **False Positive**
- Uses a local LLM via Ollama — no data leaves your machine
- Builds a vector memory of every past case and retrieves similar ones at analysis time
- Learns from analyst feedback and stores reusable detection patterns (skills)
- Correlates related alerts into incidents tracking kill chain progression and MITRE techniques
- Executes automated response playbooks (block IP, quarantine endpoint, Discord alert)
- Exports MITRE ATT&CK Navigator layers from all detected techniques

→ See [`ai_agent_src/README.md`](ai_agent_src/README.md) for full API reference and configuration.

### SOC Frontend (`soc-frontend/`)
A React dashboard providing real-time visibility into the agent:
- **Overview** — health status, TP/FP rate, memory count, playbook mode indicator
- **Kill Chain Timeline** — incident progression visualized across kill chain phases
- **Incidents Panel** — open incidents with severity, attack types, MITRE techniques, and status management
- **Memory Panel** — analyzed cases with decisions, confidence scores, full analysis summaries, and drill-in detail view
- **Skills Panel** — learned detection patterns with confidence bars, success rates, MITRE tags, and drill-in detail view
- **Playbooks Panel** — active playbooks, execution history, and create/delete playbooks from the UI
- **Simulation Runner** — trigger the Shuffle pipeline simulation from the UI

Both Memory and Skills panels support **analyst feedback** (✓ / ✗ buttons) directly in the table and in the detail view. Feedback is persisted in `localStorage` so it survives page refresh.

### Shuffle Simulation (`ai_agent_src/shuffle_simulation.py`)
A fully scripted simulation of the SOC pipeline for demo and testing:
- Generates native-format alerts from Wazuh (EVE JSON), Suricata (EVE JSON), Arkime (session record), and Zeek (notice.log)
- Runs mock enrichment: MISP event lookup, Cortex VirusTotal + AbuseIPDB, OpenCTI observables
- Creates TheHive cases with enriched context
- Assembles and POSTs enriched payloads to NexusSOC `/analyze-case`
- 16 scenarios across 5 threat groups: ransomware, APT, insider threat, web attacks, DNS exfiltration

```bash
python ai_agent_src/shuffle_simulation.py
```

Results are saved to `sim_results.json`.

### Grafana (`grafana/`)
Three pre-built dashboards powered directly by PostgreSQL:
| Dashboard | What it shows |
|---|---|
| SOC Overview | Alert volume, TP/FP ratio, confidence trends |
| Incidents & Kill Chain | Open incidents, severity, kill chain phase distribution |
| Skills & Playbooks | Skill confidence over time, playbook execution count |

## Stack

| Service | Technology | Port |
|---|---|---|
| AI Agent API | FastAPI + Uvicorn | 8001 |
| SOC Frontend | React (Vite) | 5173 |
| Grafana | Grafana OSS | 3000 |
| Database | PostgreSQL 15 + pgvector | 5432 |
| Queue | Redis 7 | 6379 |
| LLM & Embeddings | Ollama | 11434 |

## Requirements

- Docker & Docker Compose
- [Ollama](https://ollama.ai) running locally

Pull the required models:
```bash
ollama pull qwen3:1.7b        # default LLM (swap for a bigger model if your hardware allows)
ollama pull nomic-embed-text  # embedding model — do not change after first run
```

> **Choose your LLM based on your hardware:**
>
> | RAM / VRAM | Model |
> |---|---|
> | 4 GB | `qwen3:1.7b` |
> | 8 GB | `mistral:7b` or `llama3.1:8b` |
> | 16 GB | `qwen3:14b` |
> | 24 GB+ | `qwen3:32b` |
>
> Change it via `OLLAMA_MODEL` in your `.env` file.

## Quick Start

**1. Clone and configure**
```bash
git clone <repo-url>
cd SocAnalyst_Ai_Agent
cp ai_agent_src/.env.example .env
```
Edit `.env` with your database credentials and optional Discord webhook.

**2. Start the full stack**
```bash
docker compose up --build
```

**3. Seed default playbooks** (first run only)
```bash
python ai_agent_src/seed_playbooks.py http://localhost:8001
```

**4. Access the platform**

| Interface | URL |
|---|---|
| SOC Frontend | http://localhost:5173 |
| API Docs (Swagger) | http://localhost:8001/docs |
| Grafana | http://localhost:3000 |

Grafana default login: `admin` / your `DB_PASS` from `.env`

**5. Run the SOC pipeline simulation** (optional)
```bash
python ai_agent_src/shuffle_simulation.py
```

## Project Structure

```
NexusSOC/
├── docker-compose.yml              # Wires all services together
├── .env                            # Your credentials (gitignored — never commit)
├── .gitignore
│
├── ai_agent_src/                   # AI agent backend (FastAPI)
│   ├── main.py                     # API routes, alert intake, analysis pipeline
│   ├── correlator.py               # Incident correlation & kill chain tracking
│   ├── playbooks.py                # Playbook engine (block IP, quarantine, notify)
│   ├── worker.py                   # Background queue worker (Redis)
│   ├── shuffle_simulation.py       # Full SOC pipeline simulation (Shuffle SOAR)
│   ├── seed_playbooks.py           # Seeds default playbooks on first run
│   ├── requirements.txt
│   ├── .env.example                # Template — copy to .env and fill in
│   ├── Dockerfile
│   └── README.md                   # Full API reference & configuration
│
├── grafana/
│   └── dashboards/                 # Pre-built Grafana dashboard JSON files
│       ├── soc-overview.json
│       ├── incidents-killchain.json
│       └── skills-playbooks.json
│
└── soc-frontend/                   # React dashboard (Vite + TypeScript)
    ├── index.html
    ├── vite.config.ts
    ├── tsconfig.json
    ├── package.json
    ├── Dockerfile
    ├── nginx.conf
    ├── public/
    │   ├── favicon.svg
    │   └── icons.svg
    └── src/
        ├── main.tsx
        ├── App.tsx
        ├── types.ts
        ├── components/
        │   ├── Dashboard.tsx
        │   ├── StatusBar.tsx
        │   ├── KillChainTimeline.tsx
        │   ├── MemoryPanel.tsx
        │   ├── SkillsPanel.tsx
        │   ├── PlaybooksPanel.tsx
        │   └── SimulationRunner.tsx
        ├── data/
        │   └── alerts.ts
        ├── lib/
        │   └── api.ts
        └── styles/
            └── global.css
```

## Security Notes

- All LLM inference runs **locally via Ollama** — no alert data is sent to any external service
- Playbooks run in `DRY_RUN` mode by default — set `PLAYBOOK_DRY_RUN=false` only when your SOC stack is connected


## License

MIT
