import { useCallback, useEffect, useState } from 'react'
import { api } from '../lib/api'
import type { Playbook, PlaybookAction, PlaybookExecution } from '../types'

const ACTION_COLOR: Record<string, string> = {
  log:     'var(--text-3)',
  discord: '#5865f2',
  webhook: 'var(--amber)',
}

const ACTION_ICON: Record<string, string> = {
  log:     '◈',
  discord: '◉',
  webhook: '⇢',
}

function ActionBadge({ type }: { type: string }) {
  return (
    <span style={{
      fontFamily: 'var(--mono)',
      fontSize: 10,
      padding: '2px 7px',
      borderRadius: 3,
      background: 'var(--surface-2)',
      color: ACTION_COLOR[type] ?? 'var(--text-2)',
      border: `1px solid ${ACTION_COLOR[type] ?? 'var(--border)'}`,
      letterSpacing: '0.04em',
    }}>
      {ACTION_ICON[type] ?? '?'} {type}
    </span>
  )
}

function AttackChips({ types }: { types: string[] | null }) {
  if (!types?.length) return <span style={{ color: 'var(--text-3)', fontSize: 11 }}>any</span>
  return (
    <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
      {types.map(t => (
        <span key={t} className="mitre-chip" style={{ fontSize: 10 }}>
          {t.replace(/_/g, ' ')}
        </span>
      ))}
    </div>
  )
}

function ConfBar({ value }: { value: number }) {
  const pct = Math.round(value * 100)
  const color = pct >= 85 ? 'var(--red)' : pct >= 70 ? 'var(--amber)' : 'var(--green)'
  return (
    <div className="conf-bar">
      <div className="track">
        <div className="fill" style={{ width: `${pct}%`, background: color }} />
      </div>
      <span className="label" style={{ color }}>{pct}%</span>
    </div>
  )
}

function ActionDetail({ action }: { action: PlaybookAction }) {
  return (
    <div style={{
      padding: '10px 14px',
      borderRadius: 6,
      background: 'var(--surface-2)',
      border: '1px solid var(--border)',
      display: 'flex',
      flexDirection: 'column',
      gap: 6,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <ActionBadge type={action.type} />
        {action.url && (
          <span style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--text-3)' }}>
            {action.method ?? 'POST'} {action.url}
          </span>
        )}
      </div>
      {action.message && (
        <div style={{ fontSize: 12, color: 'var(--text-2)', fontStyle: 'italic', lineHeight: 1.5 }}>
          "{action.message.slice(0, 180)}{action.message.length > 180 ? '…' : ''}"
        </div>
      )}
      {action.payload && (
        <pre style={{
          margin: 0, fontSize: 10, color: 'var(--text-3)',
          fontFamily: 'var(--mono)', lineHeight: 1.6,
          overflow: 'hidden', maxHeight: 80,
        }}>
          {JSON.stringify(action.payload, null, 2).slice(0, 300)}
        </pre>
      )}
    </div>
  )
}

function PlaybookDetail({
  playbook,
  executions,
  onBack,
  onDelete,
}: {
  playbook: Playbook
  executions: PlaybookExecution[]
  onBack: () => void
  onDelete: (id: number) => void
}) {
  const related = executions.filter(e => e.playbook_name === playbook.name).slice(0, 6)

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Header */}
      <div className="section-header">
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <button className="btn btn-ghost" style={{ padding: '4px 10px', fontSize: 12 }} onClick={onBack}>
              ← Back
            </button>
            <div className="section-title" style={{ margin: 0 }}>
              {playbook.name}
            </div>
            <span className={`badge ${playbook.enabled ? 'tp' : 'fp'}`} style={{ fontSize: 10 }}>
              {playbook.enabled ? '● enabled' : '○ disabled'}
            </span>
          </div>
          {playbook.description && (
            <div className="section-sub" style={{ marginTop: 6 }}>
              {playbook.description}
            </div>
          )}
        </div>
        <button
          className="btn btn-danger"
          style={{ padding: '6px 14px', fontSize: 12 }}
          onClick={() => onDelete(playbook.id)}
        >
          Delete
        </button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        {/* Trigger conditions */}
        <div className="card">
          <div style={{ fontWeight: 600, fontSize: 12, color: 'var(--text-2)', marginBottom: 14, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
            Trigger Conditions
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 12, color: 'var(--text-3)' }}>Decision</span>
              <span className={`badge ${playbook.trigger_decision === 'True Positive' ? 'tp' : 'fp'}`}>
                {playbook.trigger_decision === 'True Positive' ? '⚡ True Positive' : '✓ False Positive'}
              </span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 12, color: 'var(--text-3)' }}>Min Confidence</span>
              <div style={{ width: 140 }}>
                <ConfBar value={playbook.trigger_min_confidence} />
              </div>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 8 }}>
              <span style={{ fontSize: 12, color: 'var(--text-3)', paddingTop: 2 }}>Attack Types</span>
              <AttackChips types={playbook.trigger_attack_types} />
            </div>
          </div>
        </div>

        {/* Stats */}
        <div className="card">
          <div style={{ fontWeight: 600, fontSize: 12, color: 'var(--text-2)', marginBottom: 14, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
            Stats
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ fontSize: 12, color: 'var(--text-3)' }}>Total Executions</span>
              <span style={{ fontFamily: 'var(--mono)', fontSize: 14, fontWeight: 700, color: playbook.execution_count > 0 ? 'var(--green)' : 'var(--text-3)' }}>
                {playbook.execution_count}
              </span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ fontSize: 12, color: 'var(--text-3)' }}>Actions</span>
              <span style={{ fontFamily: 'var(--mono)', fontSize: 14 }}>{playbook.actions.length}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ fontSize: 12, color: 'var(--text-3)' }}>Created</span>
              <span style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--text-3)' }}>
                {new Date(playbook.created_at).toLocaleDateString()}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Actions */}
      <div className="card">
        <div style={{ fontWeight: 600, fontSize: 12, color: 'var(--text-2)', marginBottom: 14, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
          Actions ({playbook.actions.length})
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {playbook.actions.map((action, i) => (
            <div key={i} style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
              <span style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--text-3)', paddingTop: 13, minWidth: 18 }}>
                {i + 1}.
              </span>
              <div style={{ flex: 1 }}>
                <ActionDetail action={action} />
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Recent executions */}
      {related.length > 0 && (
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <div style={{ padding: '14px 16px', fontWeight: 600, fontSize: 12, color: 'var(--text-2)', textTransform: 'uppercase', letterSpacing: '0.08em', borderBottom: '1px solid var(--border)' }}>
            Recent Executions ({related.length})
          </div>
          <table className="data-table">
            <thead>
              <tr>
                <th>Case ID</th>
                <th>Time</th>
                <th>Actions</th>
                <th>Outcomes</th>
              </tr>
            </thead>
            <tbody>
              {related.map(ex => {
                const outcomes = Array.isArray(ex.actions_taken) ? ex.actions_taken : []
                const ok      = outcomes.filter(a => a.status === 'ok' || a.status === 'dry_run').length
                const err     = outcomes.filter(a => a.status === 'error').length
                return (
                  <tr key={ex.id}>
                    <td style={{ fontFamily: 'var(--mono)', fontSize: 12 }}>{ex.case_id}</td>
                    <td style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>
                      {new Date(ex.executed_at).toLocaleString()}
                    </td>
                    <td style={{ fontFamily: 'var(--mono)', fontSize: 12 }}>{outcomes.length}</td>
                    <td>
                      <div style={{ display: 'flex', gap: 6 }}>
                        {ok > 0 && (
                          <span style={{ fontSize: 11, color: 'var(--green)', fontFamily: 'var(--mono)' }}>✓ {ok}</span>
                        )}
                        {err > 0 && (
                          <span style={{ fontSize: 11, color: 'var(--red)', fontFamily: 'var(--mono)' }}>✗ {err}</span>
                        )}
                        {outcomes.some(a => a.status === 'dry_run') && (
                          <span style={{ fontSize: 11, color: 'var(--amber)', fontFamily: 'var(--mono)' }}>dry-run</span>
                        )}
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

export function PlaybooksPanel() {
  const [playbooks,   setPlaybooks]   = useState<Playbook[]>([])
  const [executions,  setExecutions]  = useState<PlaybookExecution[]>([])
  const [selected,    setSelected]    = useState<Playbook | null>(null)
  const [loading,     setLoading]     = useState(true)
  const [error,       setError]       = useState<string | null>(null)
  const [filterState, setFilterState] = useState<'all' | 'enabled' | 'disabled'>('all')

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    Promise.all([api.getPlaybooks(), api.getPlaybookExecutions(50)])
      .then(([pb, ex]) => {
        setPlaybooks(pb.playbooks)
        setExecutions(ex.executions)
      })
      .catch(e => setError(e.message ?? 'Failed to load playbooks'))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => { load() }, [load])

  const remove = async (id: number) => {
    await api.deletePlaybook(id).catch(e => setError(e.message ?? 'Failed to delete playbook'))
    setPlaybooks(p => p.filter(x => x.id !== id))
    setSelected(null)
  }

  const visible = playbooks.filter(pb => {
    if (filterState === 'enabled')  return pb.enabled
    if (filterState === 'disabled') return !pb.enabled
    return true
  })

  const totalExecs = playbooks.reduce((a, p) => a + p.execution_count, 0)

  if (selected) {
    return (
      <PlaybookDetail
        playbook={selected}
        executions={executions}
        onBack={() => setSelected(null)}
        onDelete={remove}
      />
    )
  }

  return (
    <div>
      <div className="section-header">
        <div>
          <div className="section-title">Playbooks</div>
          <div className="section-sub">
            {playbooks.length} playbooks · {totalExecs} total executions ·{' '}
            {playbooks.filter(p => p.enabled).length} enabled
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <select
            className="filter-select"
            value={filterState}
            onChange={e => setFilterState(e.target.value as typeof filterState)}
          >
            <option value="all">All</option>
            <option value="enabled">Enabled</option>
            <option value="disabled">Disabled</option>
          </select>
          <button className="btn btn-ghost" onClick={load}>↺ Refresh</button>
        </div>
      </div>

      {error && (
        <div className="empty-state" style={{ color: 'var(--red)' }}>⚠ {error}</div>
      )}

      {loading ? (
        <div className="empty-state"><span className="log-info">Loading playbooks…</span></div>
      ) : visible.length === 0 ? (
        <div className="empty-state">
          <span className="icon">⚙</span>
          <span>No playbooks — run seed_playbooks.py to load defaults</span>
        </div>
      ) : (
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>#</th>
                <th>Name</th>
                <th>Decision</th>
                <th>Min Conf</th>
                <th>Attack Types</th>
                <th>Actions</th>
                <th>Executions</th>
                <th>Status</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {visible.map(pb => (
                <tr
                  key={pb.id}
                  style={{ cursor: 'pointer' }}
                  onClick={() => setSelected(pb)}
                >
                  <td style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--text-3)' }}>
                    {pb.id}
                  </td>
                  <td style={{ fontWeight: 600, maxWidth: 200 }}>
                    {pb.name}
                  </td>
                  <td>
                    <span className={`badge ${pb.trigger_decision === 'True Positive' ? 'tp' : 'fp'}`}>
                      {pb.trigger_decision === 'True Positive' ? '⚡ TP' : '✓ FP'}
                    </span>
                  </td>
                  <td style={{ minWidth: 110 }}>
                    <ConfBar value={pb.trigger_min_confidence} />
                  </td>
                  <td style={{ maxWidth: 180 }}>
                    <AttackChips types={pb.trigger_attack_types} />
                  </td>
                  <td>
                    <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                      {pb.actions.map((a, i) => (
                        <ActionBadge key={i} type={a.type} />
                      ))}
                    </div>
                  </td>
                  <td style={{ fontFamily: 'var(--mono)', fontSize: 13, color: pb.execution_count > 0 ? 'var(--green)' : 'var(--text-3)', fontWeight: pb.execution_count > 0 ? 600 : 400 }}>
                    {pb.execution_count}×
                  </td>
                  <td>
                    <span style={{
                      fontSize: 11,
                      fontFamily: 'var(--mono)',
                      color: pb.enabled ? 'var(--green)' : 'var(--text-3)',
                    }}>
                      {pb.enabled ? '● on' : '○ off'}
                    </span>
                  </td>
                  <td onClick={e => e.stopPropagation()}>
                    <div style={{ display: 'flex', gap: 4 }}>
                      <button
                        className="btn btn-ghost"
                        style={{ padding: '4px 10px', fontSize: 11 }}
                        onClick={() => setSelected(pb)}
                      >
                        View
                      </button>
                      <button
                        className="btn btn-danger"
                        style={{ padding: '4px 10px', fontSize: 11 }}
                        onClick={() => remove(pb.id)}
                      >
                        Del
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
