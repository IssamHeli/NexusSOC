import { useEffect, useState } from 'react'
import { api } from '../lib/api'
import type { HealthStatus } from '../types'

export function StatusBar() {
  const [health,     setHealth]     = useState<HealthStatus | null>(null)
  const [queueDepth, setQueueDepth] = useState<number | null>(null)
  const [redisOk,    setRedisOk]    = useState<boolean | null>(null)

  useEffect(() => {
    const pollHealth = () =>
      api.health().then(setHealth).catch(() => setHealth(null))

    const pollQueue = () =>
      api.getQueueDepth()
        .then(d => { setQueueDepth(d.depth); setRedisOk(d.redis) })
        .catch(() => { setQueueDepth(null); setRedisOk(false) })

    pollHealth()
    pollQueue()
    const hi = setInterval(pollHealth, 15000)
    const qi = setInterval(pollQueue, 8000)
    return () => { clearInterval(hi); clearInterval(qi) }
  }, [])

  const ok = health?.status === 'healthy'

  return (
    <header className="status-bar">
      <span className="brand">◈ NexusSoc AI</span>
      <span className="divider">|</span>

      <span className={`status-pill ${health ? (ok ? 'ok' : 'err') : 'warn'}`}>
        <span className="dot" />
        {health ? (ok ? 'Online' : 'Degraded') : 'Connecting…'}
      </span>

      {health && (
        <>
          <span className={`status-pill ${health.database === 'connected' ? 'ok' : 'err'}`}>
            <span className="dot" />
            DB
          </span>
          <span className="divider">|</span>
          <span className="status-pill">Skills: {health.skills_learned}</span>
          <span className="status-pill">Mem: {health.memories_indexed}</span>
        </>
      )}

      {redisOk !== null && (
        <>
          <span className="divider">|</span>
          <span className={`status-pill ${redisOk ? 'ok' : 'err'}`}>
            <span className="dot" />
            Redis{queueDepth !== null && queueDepth > 0 ? ` Q:${queueDepth}` : ''}
          </span>
        </>
      )}

      {health?.playbook_mode && (
        <>
          <span className="divider">|</span>
          <span className="status-pill" style={{
            color: health.playbook_mode === 'live' ? 'var(--red)' : 'var(--amber)',
          }}>
            PB: {health.playbook_mode === 'live' ? '⚡ live' : '🔒 dry'}
          </span>
        </>
      )}

      <span className="spacer" />
      {health && <span className="model-badge">{health.ollama_model}</span>}
    </header>
  )
}
