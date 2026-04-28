import { Fragment, useCallback, useEffect, useState } from 'react'
import { api } from '../lib/api'

interface DlqJob {
  job_id:     string
  alert:      Record<string, unknown>
  attempts:   number
  last_error: string
  failed_at:  string
}

export function DlqPanel() {
  const [jobs,     setJobs]     = useState<DlqJob[]>([])
  const [total,    setTotal]    = useState(0)
  const [loading,  setLoading]  = useState(true)
  const [error,    setError]    = useState<string | null>(null)
  const [busy,     setBusy]     = useState(false)
  const [expanded, setExpanded] = useState<string | null>(null)

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    api.getDlq(50)
      .then(r => { setJobs(r.jobs); setTotal(r.total) })
      .catch(e => setError(e.message ?? 'Failed to load DLQ'))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => { load() }, [load])

  const requeueAll = async () => {
    if (!confirm(`Requeue ${total} dead jobs back to the main queue?`)) return
    setBusy(true)
    try {
      const r = await api.requeueAllDlq()
      alert(`Requeued ${r.requeued} jobs (${r.failed} failed to parse)`)
      load()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Requeue failed')
    } finally {
      setBusy(false)
    }
  }

  const clearAll = async () => {
    if (!confirm(`Drop ${total} dead jobs permanently? This cannot be undone.`)) return
    setBusy(true)
    try {
      const r = await api.clearDlq()
      alert(`Cleared ${r.cleared} jobs from DLQ`)
      load()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Clear failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div>
      <div className="section-header">
        <div>
          <div className="section-title">Dead Letter Queue</div>
          <div className="section-sub">
            {total} job{total === 1 ? '' : 's'} failed all 3 retry attempts
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn btn-ghost" onClick={load} disabled={loading || busy}>
            {loading ? '⟳' : '↺'} Refresh
          </button>
          <button
            className="btn btn-ghost"
            onClick={requeueAll}
            disabled={busy || total === 0}
            style={{ color: 'var(--cyan)', borderColor: 'rgba(0,229,255,.2)' }}
          >
            ↻ Requeue All
          </button>
          <button
            className="btn btn-ghost"
            onClick={clearAll}
            disabled={busy || total === 0}
            style={{ color: 'var(--red)', borderColor: 'rgba(255,61,87,.2)' }}
          >
            ✕ Clear All
          </button>
        </div>
      </div>

      {error && <div className="empty-state" style={{ color: 'var(--red)' }}>⚠ {error}</div>}

      {loading && jobs.length === 0 ? (
        <div className="empty-state"><span className="log-info">Loading…</span></div>
      ) : jobs.length === 0 ? (
        <div className="empty-state">
          <span className="icon">✓</span>
          <span>DLQ is empty — no failed jobs</span>
        </div>
      ) : (
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Job ID</th>
                <th>Case</th>
                <th>Attempts</th>
                <th>Last Error</th>
                <th>Failed At</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {jobs.map(j => {
                const caseId = (j.alert?.sourceRef as string) ?? '?'
                const isOpen = expanded === j.job_id
                return (
                  <Fragment key={j.job_id}>
                    <tr style={{ cursor: 'pointer' }}
                        onClick={() => setExpanded(isOpen ? null : j.job_id)}>
                      <td style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--text-3)' }}>
                        {j.job_id.slice(0, 8)}…
                      </td>
                      <td style={{ fontFamily: 'var(--mono)', fontSize: 12 }}>{caseId}</td>
                      <td>
                        <span className="badge" style={{ background: 'var(--red-dim)', color: 'var(--red)' }}>
                          {j.attempts}/3
                        </span>
                      </td>
                      <td style={{ maxWidth: 360, color: 'var(--red)', fontSize: 11, fontFamily: 'var(--mono)' }}>
                        {j.last_error?.slice(0, 90)}{(j.last_error?.length ?? 0) > 90 ? '…' : ''}
                      </td>
                      <td style={{ color: 'var(--text-3)', fontFamily: 'var(--mono)', fontSize: 11 }}>
                        {new Date(j.failed_at).toLocaleString()}
                      </td>
                      <td style={{ color: 'var(--text-3)' }}>{isOpen ? '▾' : '▸'}</td>
                    </tr>
                    {isOpen && (
                      <tr>
                        <td colSpan={6} style={{ background: 'var(--bg-elevated)', padding: 16 }}>
                          <pre style={{
                            margin: 0, fontFamily: 'var(--mono)', fontSize: 11,
                            color: 'var(--text-2)', whiteSpace: 'pre-wrap', wordBreak: 'break-word',
                          }}>
                            {JSON.stringify(j.alert, null, 2)}
                          </pre>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
