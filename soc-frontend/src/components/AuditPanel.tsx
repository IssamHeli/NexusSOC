import { useCallback, useEffect, useState } from 'react'
import { api } from '../lib/api'
import type { AuditLog } from '../types'

const LIMITS = [50, 100, 250]

function statusColor(code: number) {
  if (code < 300) return 'var(--green)'
  if (code < 500) return 'var(--amber)'
  return 'var(--red)'
}

function methodColor(method: string) {
  switch (method) {
    case 'GET':    return 'var(--text-3)'
    case 'POST':   return 'var(--cyan)'
    case 'DELETE': return 'var(--red)'
    case 'PATCH':  return 'var(--amber)'
    default:       return 'var(--text-2)'
  }
}

export function AuditPanel() {
  const [logs,    setLogs]    = useState<AuditLog[]>([])
  const [total,   setTotal]   = useState(0)
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState<string | null>(null)
  const [limit,   setLimit]   = useState(100)
  const [offset,  setOffset]  = useState(0)

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    api.getAuditLogs(limit, offset)
      .then(r => { setLogs(r.logs); setTotal(r.total) })
      .catch(e => setError(e.message ?? 'Failed to load audit logs'))
      .finally(() => setLoading(false))
  }, [limit, offset])

  useEffect(() => { load() }, [load])

  const pages   = Math.ceil(total / limit)
  const page    = Math.floor(offset / limit)
  const hasPrev = offset > 0
  const hasNext = offset + limit < total

  return (
    <div>
      <div className="section-header">
        <div>
          <div className="section-title">Audit Log</div>
          <div className="section-sub">
            {total} events · admin only · real-time request history
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <select
            value={limit}
            onChange={e => { setLimit(Number(e.target.value)); setOffset(0) }}
            style={{
              background: 'var(--surface-2)',
              border: '1px solid var(--border)',
              color: 'var(--text-1)',
              borderRadius: 6,
              padding: '4px 8px',
              fontSize: 12,
              fontFamily: 'var(--mono)',
            }}
          >
            {LIMITS.map(l => <option key={l} value={l}>{l} / page</option>)}
          </select>
          <button className="btn btn-ghost" onClick={load} disabled={loading}>↺ Refresh</button>
        </div>
      </div>

      {error && (
        <div className="empty-state" style={{ color: 'var(--red)', marginBottom: 8 }}>
          ⚠ {error}
          {(error.includes('403') || error.toLowerCase().includes('forbidden')) && (
            <span style={{ marginLeft: 8, fontSize: 12, color: 'var(--text-3)' }}>— admin role required</span>
          )}
        </div>
      )}

      {loading ? (
        <div className="empty-state"><span className="log-info">Loading audit logs…</span></div>
      ) : logs.length === 0 ? (
        <div className="empty-state">
          <span className="icon">◎</span>
          <span>No audit events yet</span>
        </div>
      ) : (
        <>
          <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Method</th>
                  <th>Path</th>
                  <th>Status</th>
                  <th>User</th>
                  <th>IP</th>
                  <th>Duration</th>
                </tr>
              </thead>
              <tbody>
                {logs.map(log => (
                  <tr key={log.id}>
                    <td style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td>
                      <span style={{ fontFamily: 'var(--mono)', fontSize: 11, fontWeight: 700, color: methodColor(log.method) }}>
                        {log.method}
                      </span>
                    </td>
                    <td style={{ fontFamily: 'var(--mono)', fontSize: 12, color: 'var(--text-2)', maxWidth: 320 }}>
                      {log.path}
                    </td>
                    <td>
                      <span style={{ fontFamily: 'var(--mono)', fontSize: 12, fontWeight: 600, color: statusColor(log.status) }}>
                        {log.status}
                      </span>
                    </td>
                    <td style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--text-2)' }}>
                      {log.username ?? <span style={{ color: 'var(--text-3)' }}>—</span>}
                    </td>
                    <td style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--text-3)' }}>
                      {log.ip}
                    </td>
                    <td style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>
                      {log.duration_ms}ms
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {pages > 1 && (
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginTop: 12, justifyContent: 'flex-end' }}>
              <button
                className="btn btn-ghost"
                style={{ padding: '4px 12px', fontSize: 12 }}
                disabled={!hasPrev}
                onClick={() => setOffset(o => Math.max(0, o - limit))}
              >
                ← Prev
              </button>
              <span style={{ fontSize: 12, color: 'var(--text-3)', fontFamily: 'var(--mono)' }}>
                {page + 1} / {pages}
              </span>
              <button
                className="btn btn-ghost"
                style={{ padding: '4px 12px', fontSize: 12 }}
                disabled={!hasNext}
                onClick={() => setOffset(o => o + limit)}
              >
                Next →
              </button>
            </div>
          )}
        </>
      )}
    </div>
  )
}
