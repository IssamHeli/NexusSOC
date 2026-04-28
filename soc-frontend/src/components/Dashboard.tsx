import { useCallback, useEffect, useState } from 'react'
import { api } from '../lib/api'
import type {
  HealthStatus, Memory,
  WorkerHealth, PluginsHealth, ConnectorsHealth,
} from '../types'

type SvcStatus = 'ok' | 'down' | 'degraded' | 'disabled' | 'stale' | 'unknown'

function statusColor(s: SvcStatus) {
  if (s === 'ok')                          return 'var(--green)'
  if (s === 'degraded' || s === 'stale')   return 'var(--amber)'
  if (s === 'disabled' || s === 'unknown') return 'var(--text-3)'
  return 'var(--red)'
}
function statusBg(s: SvcStatus) {
  if (s === 'ok')                          return 'rgba(0,230,118,.08)'
  if (s === 'degraded' || s === 'stale')   return 'rgba(255,179,0,.08)'
  if (s === 'disabled' || s === 'unknown') return 'rgba(255,255,255,.04)'
  return 'rgba(255,61,87,.08)'
}

function ServicePill({ label, status, sub, latencyMs }: {
  label: string; status: SvcStatus; sub?: string; latencyMs?: number | null
}) {
  const color = statusColor(status)
  const bg    = statusBg(status)
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 6,
      padding: '5px 12px', borderRadius: 6, border: `1px solid ${color}33`,
      background: bg, fontSize: 12, fontFamily: 'var(--mono)',
    }}>
      <span style={{
        width: 7, height: 7, borderRadius: '50%', background: color, flexShrink: 0,
        boxShadow: status === 'ok' ? `0 0 5px ${color}` : 'none',
      }} />
      <span style={{ color: 'var(--text-2)' }}>{label}</span>
      <span style={{ color, marginLeft: 2 }}>{status.toUpperCase()}</span>
      {latencyMs != null && (
        <span style={{ color: 'var(--text-3)', fontSize: 10 }}>{latencyMs}ms</span>
      )}
      {sub && <span style={{ color: 'var(--text-3)', marginLeft: 2, fontSize: 11 }}>· {sub}</span>}
    </div>
  )
}

function WorkerPill({ worker }: { worker: WorkerHealth }) {
  const color = statusColor(worker.status as SvcStatus)
  const bg    = statusBg(worker.status as SvcStatus)
  const sub   = worker.last_heartbeat_s != null ? `hb ${worker.last_heartbeat_s}s ago` : undefined
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 6,
      padding: '5px 12px', borderRadius: 6, border: `1px solid ${color}33`,
      background: bg, fontSize: 12, fontFamily: 'var(--mono)',
    }}>
      <span style={{
        width: 7, height: 7, borderRadius: '50%', background: color, flexShrink: 0,
        boxShadow: worker.status === 'ok' ? `0 0 5px ${color}` : 'none',
      }} />
      <span style={{ color: 'var(--text-2)' }}>worker</span>
      <span style={{ color }}>{worker.status.toUpperCase()}</span>
      {sub && <span style={{ color: 'var(--text-3)', fontSize: 10 }}>· {sub}</span>}
    </div>
  )
}

function PluginPill({ plugins }: { plugins: PluginsHealth }) {
  const s     = plugins.status === 'ok' ? 'ok' : plugins.status === 'partial' ? 'degraded' : 'disabled' as SvcStatus
  const color = statusColor(s)
  const bg    = statusBg(s)
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 6,
      padding: '5px 12px', borderRadius: 6, border: `1px solid ${color}33`,
      background: bg, fontSize: 12, fontFamily: 'var(--mono)',
    }}>
      <span style={{ width: 7, height: 7, borderRadius: '50%', background: color, flexShrink: 0 }} />
      <span style={{ color: 'var(--text-2)' }}>plugins</span>
      <span style={{ color }}>{plugins.loaded}/{plugins.total}</span>
    </div>
  )
}

function ConnectorsPill({ connectors }: { connectors: ConnectorsHealth }) {
  const color = connectors.registered > 0 ? 'var(--cyan)' : 'var(--text-3)'
  const bg    = connectors.registered > 0 ? 'rgba(0,229,255,.08)' : 'rgba(255,255,255,.04)'
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 6,
      padding: '5px 12px', borderRadius: 6, border: `1px solid ${color}33`,
      background: bg, fontSize: 12, fontFamily: 'var(--mono)',
    }}>
      <span style={{ width: 7, height: 7, borderRadius: '50%', background: color, flexShrink: 0 }} />
      <span style={{ color: 'var(--text-2)' }}>connectors</span>
      <span style={{ color }}>{connectors.registered}</span>
      {connectors.names.length > 0 && (
        <span style={{ color: 'var(--text-3)', fontSize: 10 }}>· {connectors.names.join(' · ')}</span>
      )}
    </div>
  )
}

export function Dashboard() {
  const [health,        setHealth]        = useState<HealthStatus | null>(null)
  const [memories,      setMemories]      = useState<Memory[]>([])
  const [incidentCount, setIncidentCount] = useState<number | null>(null)
  const [loading,       setLoading]       = useState(true)
  const [error,         setError]         = useState<string | null>(null)
  const [lastRefresh,   setLastRefresh]   = useState<Date>(new Date())

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    Promise.all([
      api.health(),
      api.getMemory(10),
      api.getIncidents(undefined, 1),
    ])
      .then(([h, m, inc]) => {
        setHealth(h)
        setMemories(m.memories)
        setIncidentCount(inc.total)
        setLastRefresh(new Date())
      })
      .catch(e => setError(e.message ?? 'Failed to load dashboard'))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => { load() }, [load])

  const tp     = memories.filter(m => m.ai_decision === 'True Positive').length
  const fp     = memories.filter(m => m.ai_decision === 'False Positive').length
  const tpRate = memories.length > 0 ? Math.round((tp / memories.length) * 100) : 0

  return (
    <div>
      <div className="section-header">
        <div>
          <div className="section-title">SOC Overview</div>
          <div className="section-sub">
            Last refresh: {lastRefresh.toLocaleTimeString()}
            {health?.playbook_mode && (
              <span style={{
                marginLeft: 10, padding: '1px 7px', borderRadius: 3, fontSize: 10,
                background: health.playbook_mode === 'live' ? 'var(--red-dim)' : 'var(--amber-dim)',
                color: health.playbook_mode === 'live' ? 'var(--red)' : 'var(--amber)',
                border: `1px solid ${health.playbook_mode === 'live' ? 'rgba(255,61,87,.3)' : 'rgba(255,179,0,.3)'}`,
                fontFamily: 'var(--mono)',
              }}>
                {health.playbook_mode === 'live' ? '⚡ LIVE' : '🔒 DRY RUN'}
              </span>
            )}
          </div>
        </div>
        <button className="btn btn-ghost" onClick={load} disabled={loading}>
          {loading ? '⟳' : '↺'} Refresh
        </button>
      </div>

      {error && (
        <div className="empty-state" style={{ color: 'var(--red)' }}>⚠ {error}</div>
      )}

      {loading && memories.length === 0 ? (
        <div className="empty-state"><span className="log-info">Loading…</span></div>
      ) : (
        <>
          <div className="stats-grid">
            <div className="stat-card accent-cyan">
              <span className="stat-label">Agent Status</span>
              <span className="stat-value" style={{ fontSize: 18, color: health?.status === 'healthy' ? 'var(--green)' : 'var(--red)' }}>
                {health?.status === 'healthy' ? 'ONLINE' : 'OFFLINE'}
              </span>
              <span className="stat-sub">{health?.database === 'ok' ? 'DB connected' : 'DB disconnected'}</span>
            </div>

            <div className="stat-card accent-green">
              <span className="stat-label">Skills Learned</span>
              <span className="stat-value">{health?.skills_learned ?? '—'}</span>
              <span className="stat-sub">EMA α=0.15 · from experience</span>
            </div>

            <div className="stat-card accent-amber">
              <span className="stat-label">Memories Indexed</span>
              <span className="stat-value">{health?.memories_indexed ?? '—'}</span>
              <span className="stat-sub">vector dim 768 · cosine HNSW</span>
            </div>

            <div className="stat-card accent-red">
              <span className="stat-label">TP Rate</span>
              <span className="stat-value">{tpRate}%</span>
              <span className="stat-sub">{tp} TP · {fp} FP · last {memories.length} cases</span>
            </div>

            <div className="stat-card" style={{ borderColor: 'rgba(96,165,250,.2)', background: 'linear-gradient(135deg, var(--bg-surface), rgba(96,165,250,.08))' }}>
              <span className="stat-label">Open Incidents</span>
              <span className="stat-value" style={{ color: 'var(--cyan)' }}>
                {incidentCount ?? '—'}
              </span>
              <span className="stat-sub">correlated · 24h window</span>
            </div>

            <div className="stat-card">
              <span className="stat-label">Model</span>
              <span className="stat-value" style={{ fontSize: 13, color: 'var(--text-2)', fontFamily: 'var(--mono)', paddingTop: 4 }}>
                {health?.ollama_model ?? '—'}
              </span>
              <span className="stat-sub">{health?.embed_model ?? '—'}</span>
            </div>
          </div>

          {health?.services && (
            <div className="card" style={{ marginBottom: 16 }}>
              <p className="card-title" style={{ marginBottom: 10 }}>Service Status</p>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                <ServicePill
                  label="database"
                  status={health.services.database.status}
                  latencyMs={health.services.database.latency_ms}
                  sub={health.services.database.pgvector ? 'pgvector ✓' : 'pgvector ✗'}
                />
                <ServicePill
                  label="redis"
                  status={health.services.redis.status}
                  latencyMs={health.services.redis.latency_ms}
                  sub={`q:${health.services.redis.queue_depth} dlq:${health.services.redis.dlq_depth}`}
                />
                <ServicePill
                  label="ollama"
                  status={health.services.ollama.status}
                  latencyMs={health.services.ollama.latency_ms}
                  sub={health.services.ollama.active_model ?? `${health.ollama_model} (on-demand)`}
                />
                <WorkerPill     worker={health.services.worker} />
                <PluginPill     plugins={health.services.plugins} />
                <ConnectorsPill connectors={health.services.connectors} />
              </div>
            </div>
          )}

          <div className="card">
            <p className="card-title">Recent Cases</p>
            {memories.length === 0 ? (
              <div className="empty-state">
                <span className="icon">◎</span>
                <span>No cases yet — run the simulation</span>
              </div>
            ) : (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Case ID</th><th>Decision</th><th>Confidence</th>
                    <th>Summary</th><th>Embedding</th><th>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {memories.map(m => (
                    <tr key={m.case_id + m.timestamp}>
                      <td style={{ fontFamily: 'var(--mono)', fontSize: 12 }}>{m.case_id}</td>
                      <td>
                        <span className={`badge ${m.ai_decision === 'True Positive' ? 'tp' : 'fp'}`}>
                          {m.ai_decision === 'True Positive' ? '⚡ TP' : '✓ FP'}
                        </span>
                      </td>
                      <td>
                        <div className="conf-bar">
                          <div className="track">
                            <div className="fill" style={{
                              width: `${(m.confidence ?? 0) * 100}%`,
                              background: m.ai_decision === 'True Positive' ? 'var(--red)' : 'var(--green)',
                            }} />
                          </div>
                          <span className="label">{((m.confidence ?? 0) * 100).toFixed(0)}%</span>
                        </div>
                      </td>
                      <td style={{ maxWidth: 320, color: 'var(--text-2)', fontSize: 12 }}>
                        {(m.analysis_summary ?? '').slice(0, 100)}{(m.analysis_summary ?? '').length > 100 ? '…' : ''}
                      </td>
                      <td style={{ fontFamily: 'var(--mono)', fontSize: 11, color: m.has_embedding ? 'var(--green)' : 'var(--text-3)' }}>
                        {m.has_embedding ? '● vec' : '○'}
                      </td>
                      <td style={{ color: 'var(--text-3)', fontFamily: 'var(--mono)', fontSize: 11 }}>
                        {new Date(m.timestamp).toLocaleTimeString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </>
      )}
    </div>
  )
}
