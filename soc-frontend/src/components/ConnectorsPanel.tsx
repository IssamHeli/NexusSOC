import { useCallback, useEffect, useState } from 'react'
import { api } from '../lib/api'

const CONNECTOR_META: Record<string, { icon: string; label: string; desc: string }> = {
  wazuh:   { icon: '🛡', label: 'Wazuh',        desc: 'HIDS/SIEM — rule-based host intrusion detection' },
  elastic: { icon: '🔎', label: 'Elastic SIEM', desc: 'Elastic Security alert hits from Kibana' },
  splunk:  { icon: '📊', label: 'Splunk',        desc: 'Saved-search webhook alerts + DLP events' },
  qradar:  { icon: '📡', label: 'IBM QRadar',    desc: 'Offense payloads with magnitude + categories' },
  generic: { icon: '⚡', label: 'Generic',       desc: 'Passthrough for pre-normalized custom payloads' },
}

export function ConnectorsPanel() {
  const [connectors, setConnectors] = useState<string[]>([])
  const [depth,      setDepth]      = useState<number | null>(null)
  const [redisOk,    setRedisOk]    = useState<boolean | null>(null)
  const [loading,    setLoading]    = useState(true)
  const [error,      setError]      = useState<string | null>(null)

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    Promise.all([api.getConnectors(), api.getQueueDepth()])
      .then(([c, q]) => {
        setConnectors(c.connectors)
        setDepth(q.depth)
        setRedisOk(q.redis)
      })
      .catch(e => setError(e.message ?? 'Failed to load'))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => { load() }, [load])

  return (
    <div>
      <div className="section-header">
        <div>
          <div className="section-title">SIEM Connectors</div>
          <div className="section-sub">{connectors.length} connectors registered · POST /ingest/{'{connector}'}</div>
        </div>
        <button className="btn btn-ghost" onClick={load} disabled={loading}>
          {loading ? '⟳' : '↺'} Refresh
        </button>
      </div>

      {error && <div className="empty-state" style={{ color: 'var(--red)' }}>⚠ {error}</div>}

      <div className="card" style={{ marginBottom: 16, padding: '12px 16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 20, flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{
              width: 8, height: 8, borderRadius: '50%',
              background: redisOk ? 'var(--green)' : 'var(--red)',
              boxShadow: redisOk ? '0 0 6px var(--green)' : '0 0 6px var(--red)',
            }} />
            <span style={{ fontFamily: 'var(--mono)', fontSize: 12, color: 'var(--text-2)' }}>Redis queue</span>
            <span style={{ fontFamily: 'var(--mono)', fontSize: 12, color: redisOk ? 'var(--green)' : 'var(--red)' }}>
              {redisOk ? 'ONLINE' : 'OFFLINE'}
            </span>
          </div>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 12, color: 'var(--text-2)' }}>
            Queue depth:{' '}
            <span style={{ color: (depth ?? 0) > 0 ? 'var(--amber)' : 'var(--text-1)' }}>
              {depth ?? '—'}
            </span>
          </div>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--text-3)', marginLeft: 'auto' }}>
            endpoint: <span style={{ color: 'var(--cyan)' }}>POST /ingest/{'{connector}'}</span>
          </div>
        </div>
      </div>

      {loading && connectors.length === 0 ? (
        <div className="empty-state"><span className="log-info">Loading…</span></div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: 12 }}>
          {connectors.map(name => {
            const meta = CONNECTOR_META[name] ?? { icon: '⚙', label: name, desc: 'Custom connector' }
            return (
              <div key={name} className="card" style={{
                border: '1px solid rgba(0,229,255,.15)',
                background: 'linear-gradient(135deg, var(--bg-surface), rgba(0,229,255,.04))',
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                  <span style={{ fontSize: 22 }}>{meta.icon}</span>
                  <div>
                    <div style={{ fontWeight: 600, fontSize: 14, color: 'var(--text-1)' }}>{meta.label}</div>
                    <div style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--cyan)' }}>
                      /ingest/{name}
                    </div>
                  </div>
                  <span style={{
                    marginLeft: 'auto', fontSize: 10, padding: '2px 7px', borderRadius: 4,
                    background: 'rgba(0,230,118,.12)', color: 'var(--green)',
                    fontFamily: 'var(--mono)', border: '1px solid rgba(0,230,118,.2)',
                  }}>
                    READY
                  </span>
                </div>
                <p style={{ fontSize: 12, color: 'var(--text-2)', lineHeight: 1.5 }}>{meta.desc}</p>
              </div>
            )
          })}
        </div>
      )}

      <div className="card" style={{ marginTop: 20 }}>
        <p className="card-title" style={{ marginBottom: 10 }}>How to ingest</p>
        <pre style={{
          fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--text-2)',
          background: 'var(--bg-elevated)', padding: 14, borderRadius: 6,
          overflowX: 'auto', lineHeight: 1.7,
        }}>{`# Wazuh
curl -X POST http://localhost:8001/ingest/wazuh \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"rule":{"level":10,"description":"SSH brute force"},"agent":{"name":"host-01"}}'

# Splunk saved-search webhook
curl -X POST http://localhost:8001/ingest/splunk \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"search_name":"DLP Alert","result":{"src":"10.0.0.1","severity":"high"}}'`}
        </pre>
      </div>
    </div>
  )
}
