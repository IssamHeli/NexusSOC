# NexusSOC — SOC Frontend (`soc-frontend/`)

React + TypeScript + Vite dashboard for the NexusSOC AI agent. JWT-protected, theme-aware, plugin- and connector-aware UI for the full V2 backend.

> Root `README.md` covers the full platform. This document is the frontend-only reference.

---

## Panels

Tab order matches `App.tsx` `TABS`. Every panel is wrapped by `AuthProvider` and re-renders on token refresh.

| Tab | Component | Role gate | Description |
|---|---|---|---|
| `dashboard` | `Dashboard.tsx` | viewer | Health pills (db, redis, ollama, worker, plugins, connectors, llm), TP/FP counters, recent activity |
| (in dashboard) | `KillChainTimeline.tsx` | viewer | Active incidents mapped across kill chain phases |
| `incidents` | (inline) | viewer | Open / investigating / closed incidents with status controls |
| `memory` | `MemoryPanel.tsx` | viewer | Analyzed cases — decision, confidence, full summary, recommended action, inline ✓/✗ feedback |
| `skills` | `SkillsPanel.tsx` | viewer | Learned detection patterns — confidence bar, MITRE tags, inline feedback (`localStorage` deduped) |
| `playbooks` | `PlaybooksPanel.tsx` | viewer / admin | Playbooks + execution audit log; create / delete from UI |
| `simulation` | `SimulationRunner.tsx` | analyst | Trigger backend simulation harness |
| `plugins` | `PluginsPanel.tsx` | viewer | Plugin registry status (`loaded`, `reason`) per category |
| `connectors` | `ConnectorsPanel.tsx` | viewer | Loaded SIEM connectors |
| `dlq` | `DlqPanel.tsx` | admin | Dead-letter queue inspector — view / clear / requeue-all |
| `analyze` | `AnalyzeForm.tsx` | analyst | Submit one alert or a batch (paste JSON or upload `.json`); calls `POST /ingest/batch`; per-result cards with success / failure |
| `audit` | `AuditPanel.tsx` | admin | Paginated audit log — method / status color-coded, graceful 403 |
| `users` | `UsersPanel.tsx` | admin | User CRUD — inline role / password edit, deactivate. Self-demote / self-delete / last-admin-delete blocked server-side |

Login surface: `LoginPage.tsx` (rendered when `AUTH_ENABLED=true` and no valid token).
Header: `StatusBar.tsx` shows global state and theme toggle.

---

## State management

| Concern | Where |
|---|---|
| Auth (token + user) | `contexts/AuthContext.tsx` (`useAuth`, `AUTH_ENABLED`, login/logout, 401 → forced logout) |
| API client | `lib/api.ts` — single `api` object, every backend call. Bearer header, refresh-on-401 retry, `setUnauthorizedHandler` |
| Local feedback dedup | `localStorage` keys `nexussoc:feedback`, `nexussoc:skill-feedback` |
| Tab routing | `App.tsx` `TABS` array + `tab` state in `AppShell` |

`types.ts` exports every shared type. `TabId` is the union of all tab ids; the `ServiceHealth` type is split into 6 sub-interfaces matching `/health` shape.

---

## Theme

Theme tokens live in `styles/global.css` as CSS variables. The header toggle flips a `data-theme` attribute. Both light and dark are first-class — pick whichever the screenshot strategy needs.

> `AnalyzeForm.tsx` currently uses inline styles instead of CSS vars. Refactor target — see root project memory.

---

## Development

```bash
npm install
npm run dev        # http://localhost:5173
```

API base URL is configured via `VITE_API_URL` (defaults to `http://localhost:8001`):

```env
VITE_API_URL=http://localhost:8001
VITE_AUTH_ENABLED=false   # set true for the JWT login flow
```

When `VITE_AUTH_ENABLED=false` the UI skips the login screen and sends no Bearer token — useful for local backend dev.

---

## Build

```bash
npm run build      # output in dist/
```

In production the frontend is served as a static build inside the Docker Compose stack — no separate Node process needed. The `Dockerfile` handles `vite build` + nginx.

---

## Stack

- React 18 + TypeScript
- Vite (HMR + production build)
- Custom CSS with design tokens via CSS variables — no UI framework
- JWT context with refresh-token rotation (handled by `api.ts`)
- localStorage for feedback dedup only

---

## Common tasks

- **Add a new panel** — create the component under `components/`, add a `TabId` value in `types.ts`, register it in `App.tsx` `TABS` plus the switch in `AppShell`
- **Add an API call** — extend the `api` object in `lib/api.ts`; the shared `request<T>` handles auth, refresh, and JSON `detail` error surfacing
- **Add a new route role gate** — backend already enforces; surface `403` gracefully in the panel like `AuditPanel.tsx`
