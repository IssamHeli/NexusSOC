import { useCallback, useEffect, useState } from 'react'
import { api } from '../lib/api'
import type { PluginStatus } from '../types'

const CATEGORY_ICON: Record<string, string> = {
  notification: '🔔',
  enrichment:   '🔍',
  export:       '📤',
}

const CATEGORY_ORDER = ['notification', 'enrichment', 'export']

export function PluginsPanel() {
  const [plugins, setPlugins] = useState<PluginStatus[]>([])
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState<string | null>(null)

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    api.getPlugins()
      .then(d => setPlugins(d.plugins))
      .catch(e => setError(e.message ?? 'Failed to load plugins'))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => { load() }, [load])

  const byCategory = CATEGORY_ORDER.map(cat => ({
    cat,
    items: plugins.filter(p => p.category === cat),
  }))

  const loaded = plugins.filter(p => p.loaded).length

  return (
    <div>
      <div className="section-header">
        <div>
          <div className="section-title">Plugin Registry</div>
          <div className="section-sub">{loaded}/{plugins.length} plugins active</div>
        </div>
        <button className="btn btn-ghost" onClick={load} disabled={loading}>
          {loading ? '⟳' : '↺'} Refresh
        </button>
      </div>

      {error && <div className="empty-state" style={{ color: 'var(--red)' }}>⚠ {error}</div>}

      {loading && plugins.length === 0 ? (
        <div className="empty-state"><span className="log-info">Loading…</span></div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          {byCategory.map(({ cat, items }) => (
            <div key={cat} className="card">
              <p className="card-title" style={{ marginBottom: 12 }}>
                {CATEGORY_ICON[cat] ?? '⚙'} {cat.charAt(0).toUpperCase() + cat.slice(1)} Plugins
              </p>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: 10 }}>
                {items.map(p => (
                  <div key={p.name} style={{
                    padding: '12px 16px', borderRadius: 8,
                    border: `1px solid ${p.loaded ? 'rgba(0,230,118,.2)' : 'rgba(255,255,255,.06)'}`,
                    background: p.loaded ? 'rgba(0,230,118,.05)' : 'var(--bg-elevated)',
                    display: 'flex', flexDirection: 'column', gap: 4,
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{
                        width: 8, height: 8, borderRadius: '50%', flexShrink: 0,
                        background: p.loaded ? 'var(--green)' : 'var(--text-3)',
                        boxShadow: p.loaded ? '0 0 6px var(--green)' : 'none',
                      }} />
                      <span style={{ fontFamily: 'var(--mono)', fontSize: 13, color: 'var(--text-1)' }}>
                        {p.name}
                      </span>
                      <span style={{
                        marginLeft: 'auto', fontSize: 10, fontFamily: 'var(--mono)',
                        padding: '1px 6px', borderRadius: 3,
                        background: p.loaded ? 'rgba(0,230,118,.15)' : 'rgba(255,255,255,.06)',
                        color: p.loaded ? 'var(--green)' : 'var(--text-3)',
                      }}>
                        {p.loaded ? 'ACTIVE' : 'INACTIVE'}
                      </span>
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--text-3)', fontFamily: 'var(--mono)', paddingLeft: 16 }}>
                      {p.reason === 'ok' ? 'running normally' : p.reason}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
