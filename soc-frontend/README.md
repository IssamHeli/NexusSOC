# NexusSOC — SOC Frontend

React + TypeScript + Vite dashboard for the NexusSOC AI agent. Provides real-time visibility into alert triage decisions, incidents, skills, and playbook executions.

## Panels

| Panel | Description |
|---|---|
| **Overview** | Agent health, TP/FP counters, memory count, playbook mode |
| **Kill Chain Timeline** | Active incidents mapped across kill chain phases |
| **Incidents** | Open/investigating/closed incidents with severity, MITRE techniques, and status controls |
| **Memory** | Analyzed cases — decision, confidence, full summary, recommended action, analyst feedback |
| **Skills** | Learned detection patterns — confidence bar, success rate, MITRE tags, analyst feedback |
| **Playbooks** | Active playbooks and execution audit log — create and delete playbooks from the UI |
| **Simulation** | Trigger the built-in alert simulation harness |

## Analyst Feedback

Every case in Memory and every skill in Skills supports inline ✓ / ✗ feedback:
- Feedback is sent to the backend and updates skill confidence via EMA (α=0.15)
- Sent feedback is persisted in `localStorage` so buttons are not shown again after a page refresh
- Click any row (or the **View** button) to open a detail view with the full text and larger feedback controls

## Development

```bash
npm install
npm run dev        # http://localhost:5173
```

The API base URL is configured via `VITE_API_URL` (defaults to `http://localhost:8001`):

```env
VITE_API_URL=http://localhost:8001
```

## Build

```bash
npm run build      # output in dist/
```

In production the frontend is served as a static build inside the Docker Compose stack — no separate Node process needed.

## Stack

- React 18 + TypeScript
- Vite
- Custom CSS (no UI framework — design tokens via CSS variables)
