import { useEffect, useState } from 'react'
import { api } from '../lib/api'
import type { Incident } from '../types'

const KILL_CHAIN_PHASES = [
  { id: 'recon',    label: 'Recon',    icon: '🔍' },
  { id: 'delivery', label: 'Delivery', icon: '📨' },
  { id: 'exploit',  label: 'Exploit',  icon: '💥' },
  { id: 'install',  label: 'Install',  icon: '⚙' },
  { id: 'c2',       label: 'C2',       icon: '📡' },
  { id: 'lateral',  label: 'Lateral',  icon: '↔' },
  { id: 'exfil',    label: 'Exfil',    icon: '📤' },
  { id: 'actions',  label: 'Actions',  icon: '⚡' },
]

const SEVERITY_COLOR: Record<string, string> = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#22c55e',
}

function SeverityDot({ severity }: { severity: string }) {
  return (
    <span style={{
      display: 'inline-block', width: 10, height: 10, borderRadius: '50%',
      background: SEVERITY_COLOR[severity] ?? '#6b7280', marginRight: 6, flexShrink: 0,
    }} />
  )
}

function PhaseCell({ active, icon }: { active: boolean; icon: string }) {
  return (
    <div style={{
      width: 40, height: 40, borderRadius: 8,
      background: active ? 'rgba(59,130,246,.25)' : '#1e293b',
      border: `2px solid ${active ? '#60a5fa' : '#334155'}`,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      fontSize: active ? 16 : 13, transition: 'all 0.2s',
      boxShadow: active ? '0 0 10px rgba(59,130,246,.3)' : 'none',
    }}>
      {active ? icon : '·'}
    </div>
  )
}

export function KillChainTimeline() {
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [selected,  setSelected]  = useState<Incident | null>(null)
  const [filter,    setFilter]    = useState<string>('open')
  const [loading,   setLoading]   = useState(true)
  const [error,     setError]     = useState<string | null>(null)
  const [updating,  setUpdating]  = useState(false)
  const mitreUrl = api.getMitreExportUrl()

  async function load() {
    setLoading(true)
    setError(null)
    try {
      const data = await api.getIncidents(filter || undefined)
      setIncidents(data.incidents)
      if (selected) {
        const fresh = data.incidents.find(i => i.incident_id === selected.incident_id)
        setSelected(fresh ?? null)
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load incidents')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [filter])

  async function handleStatusChange(incidentId: string, newStatus: string) {
    setUpdating(true)
    try {
      await api.updateIncidentStatus(incidentId, newStatus)
      await load()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Update failed')
    } finally {
      setUpdating(false)
    }
  }

  const progressPct = selected
    ? Math.round((selected.kill_chain_phases.length / KILL_CHAIN_PHASES.length) * 100)
    : 0

  return (
    <div style={{ display: 'flex', gap: 16, height: '100%', minHeight: 0 }}>

      {/* Incident list */}
      <div style={{ width: 300, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 8 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
          <h2 style={{ margin: 0, fontSize: 15, fontWeight: 700, flex: 1 }}>Incidents</h2>
          <select value={filter} onChange={e => setFilter(e.target.value)} className="filter-select">
            <option value="">All</option>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="closed">Closed</option>
          </select>
          <a
            href={mitreUrl}
            download="nexussoc-navigator.json"
            style={{ fontSize: 11, padding: '3px 8px', background: '#0f172a', color: '#60a5fa', border: '1px solid #1e40af', borderRadius: 4, textDecoration: 'none', whiteSpace: 'nowrap' }}
          >
            ↓ ATT&CK
          </a>
          <button onClick={load} style={{ fontSize: 12, padding: '2px 8px', background: '#1e293b', color: '#94a3b8', border: '1px solid #334155', borderRadius: 4, cursor: 'pointer' }}>↺</button>
        </div>

        {error && <div style={{ color: '#f87171', fontSize: 12, padding: '6px 8px', background: '#450a0a', borderRadius: 4 }}>{error}</div>}

        {loading ? (
          <div style={{ color: '#64748b', fontSize: 13, padding: 12 }}>Loading…</div>
        ) : incidents.length === 0 ? (
          <div style={{ color: '#64748b', fontSize: 13, padding: 12 }}>No incidents found.</div>
        ) : (
          <div style={{ overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 6 }}>
            {incidents.map(inc => (
              <button
                key={inc.incident_id}
                onClick={() => setSelected(inc)}
                style={{
                  textAlign: 'left',
                  background: selected?.incident_id === inc.incident_id ? '#1e3a5f' : '#0f172a',
                  border: `1px solid ${selected?.incident_id === inc.incident_id ? '#3b82f6' : '#1e293b'}`,
                  borderRadius: 6, padding: '10px 12px', cursor: 'pointer', color: '#e2e8f0',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginBottom: 4 }}>
                  <SeverityDot severity={inc.severity} />
                  <span style={{ fontWeight: 600, fontSize: 12, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {inc.incident_id}
                  </span>
                  <span style={{ fontSize: 10, color: '#94a3b8', background: '#1e293b', padding: '1px 5px', borderRadius: 3 }}>
                    {inc.case_count}c
                  </span>
                </div>
                <div style={{ fontSize: 11, color: '#94a3b8', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginBottom: 6 }}>
                  {inc.title}
                </div>
                {inc.kill_chain_phases.length > 0 && (
                  <div style={{ height: 3, borderRadius: 2, background: '#1e293b', overflow: 'hidden' }}>
                    <div style={{
                      height: '100%', borderRadius: 2, background: '#3b82f6',
                      width: `${Math.round((inc.kill_chain_phases.length / KILL_CHAIN_PHASES.length) * 100)}%`,
                    }} />
                  </div>
                )}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Detail pane */}
      <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', gap: 14 }}>
        {!selected ? (
          <div style={{ color: '#475569', fontSize: 14, paddingTop: 48, textAlign: 'center' }}>
            Select an incident to view kill chain timeline
          </div>
        ) : (
          <>
            {/* Header */}
            <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: 8, padding: '14px 18px' }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                    <SeverityDot severity={selected.severity} />
                    <span style={{ fontWeight: 700, fontSize: 15 }}>{selected.incident_id}</span>
                    <span style={{ fontSize: 11, color: '#94a3b8', background: '#1e293b', padding: '2px 6px', borderRadius: 3 }}>
                      {selected.severity.toUpperCase()}
                    </span>
                    <span style={{
                      fontSize: 11, padding: '2px 6px', borderRadius: 3,
                      background: selected.status === 'open' ? '#0f2e1a' : selected.status === 'investigating' ? '#172554' : '#1c1917',
                      color:      selected.status === 'open' ? '#4ade80' : selected.status === 'investigating' ? '#60a5fa' : '#78716c',
                      border: `1px solid ${selected.status === 'open' ? '#166534' : selected.status === 'investigating' ? '#1e40af' : '#292524'}`,
                    }}>
                      {selected.status}
                    </span>
                  </div>

                  <div style={{ fontSize: 13, color: '#cbd5e1', marginBottom: 10 }}>{selected.title}</div>

                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 14, fontSize: 11, color: '#64748b', marginBottom: 8 }}>
                    <span>{selected.case_count} case{selected.case_count !== 1 ? 's' : ''}</span>
                    {selected.source_ips.length > 0   && <span>IPs: <span style={{ color: '#94a3b8' }}>{selected.source_ips.join(', ')}</span></span>}
                    {selected.hostnames.length > 0    && <span>Hosts: <span style={{ color: '#94a3b8' }}>{selected.hostnames.join(', ')}</span></span>}
                    {(selected.users ?? []).length > 0 && <span>Users: <span style={{ color: '#94a3b8' }}>{selected.users.join(', ')}</span></span>}
                    {selected.attack_types.length > 0 && <span>Types: <span style={{ color: '#94a3b8' }}>{selected.attack_types.join(', ')}</span></span>}
                  </div>

                  {(selected.mitre_techniques ?? []).length > 0 && (
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                      {(selected.mitre_techniques ?? []).map(t => (
                        <span key={t} className="mitre-chip" style={{ fontSize: 11 }}>{t}</span>
                      ))}
                    </div>
                  )}
                </div>

                <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
                  {(['open', 'investigating', 'closed'] as const).map(s => (
                    <button
                      key={s}
                      disabled={selected.status === s || updating}
                      onClick={() => handleStatusChange(selected.incident_id, s)}
                      style={{
                        fontSize: 11, padding: '4px 10px', borderRadius: 4,
                        cursor: selected.status === s ? 'default' : 'pointer',
                        background: selected.status === s ? '#1e293b' : '#0f172a',
                        color: selected.status === s ? '#64748b' : '#94a3b8',
                        border: '1px solid #334155', opacity: updating ? 0.5 : 1,
                      }}
                    >
                      {s}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Kill chain swimlane */}
            <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: 8, padding: '16px 18px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
                <span style={{ fontSize: 11, fontWeight: 600, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                  Kill Chain Progress
                </span>
                <span style={{ fontSize: 11, color: '#3b82f6', fontFamily: 'var(--mono)' }}>
                  {progressPct}% — {selected.kill_chain_phases.length}/{KILL_CHAIN_PHASES.length} phases
                </span>
              </div>
              <div style={{ height: 4, borderRadius: 2, background: '#1e293b', marginBottom: 16, overflow: 'hidden' }}>
                <div style={{ height: '100%', borderRadius: 2, background: '#3b82f6', width: `${progressPct}%`, transition: 'width 0.4s ease' }} />
              </div>
              <div style={{ display: 'flex', alignItems: 'center', overflowX: 'auto', paddingBottom: 4 }}>
                {KILL_CHAIN_PHASES.map((phase, i) => {
                  const active = selected.kill_chain_phases.map(p => p.toLowerCase()).includes(phase.id)
                  return (
                    <div key={phase.id} style={{ display: 'flex', alignItems: 'center' }}>
                      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6, minWidth: 64 }}>
                        <PhaseCell active={active} icon={phase.icon} />
                        <span style={{ fontSize: 10, color: active ? '#93c5fd' : '#475569', fontWeight: active ? 600 : 400, whiteSpace: 'nowrap' }}>
                          {phase.label}
                        </span>
                      </div>
                      {i < KILL_CHAIN_PHASES.length - 1 && (
                        <div style={{ width: 20, height: 2, background: active ? '#3b82f6' : '#1e293b', flexShrink: 0, marginBottom: 20, transition: 'background 0.2s' }} />
                      )}
                    </div>
                  )
                })}
              </div>
              {selected.kill_chain_phases.length === 0 && (
                <div style={{ marginTop: 8, fontSize: 11, color: '#475569' }}>No kill chain phases recorded yet.</div>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  )
}
