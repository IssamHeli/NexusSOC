import { useRef, useState } from 'react'
import { api } from '../lib/api'
import { eliteAlerts } from '../data/alerts'

interface LogEntry {
  time: string
  cls:  string
  text: string
}

interface Score {
  caseId:            string
  decision:          string
  confidence:        number
  memCtx:            number
  skillsApplied:     number
  playbooksExecuted: number
  incidentId:        string | null
  incidentAction:    string | null
  enriched:          boolean
  ok:                boolean
}

// Set to true to show kill chain phases accumulating in real time in the terminal log
const SHOW_KILL_CHAIN_LIVE = true

function now() { return new Date().toLocaleTimeString('en', { hour12: false }) }

export function SimulationRunner() {
  const [running, setRunning] = useState(false)
  const [log,     setLog]     = useState<LogEntry[]>([])
  const [scores,  setScores]  = useState<Score[]>([])
  const [done,    setDone]    = useState(false)
  const termRef = useRef<HTMLDivElement>(null)

  const appendLog = (cls: string, text: string) => {
    setLog(l => [...l, { time: now(), cls, text }])
    setTimeout(() => termRef.current?.scrollTo({ top: 9999, behavior: 'smooth' }), 50)
  }

  const runSim = async () => {
    setRunning(true); setLog([]); setScores([]); setDone(false)
    appendLog('log-info', `▶ Starting elite simulation — ${eliteAlerts.length} cases`)
    appendLog('log-dim',  '  Stack: enrichment · correlation · playbooks · skill-learning')
    appendLog('log-dim',  '─'.repeat(64))

    const results: Score[] = []

    for (const alert of eliteAlerts) {
      const a = alert as Record<string, unknown>
      const hasEnrichment = a.ip_abuse_score != null || a.vt_malicious != null

      appendLog('log-dim',  '')
      appendLog('log-info', `[${a.sourceRef}] ${String(a.title).slice(0, 65)}`)
      appendLog('log-dim',  `  sev=${a.severity}  phase=${a.kill_chain_phase}  mitre=${(a.mitre_techniques as string[] ?? []).join(', ')}`)

      if (hasEnrichment) {
        const parts: string[] = []
        if (a.ip_abuse_score != null)
          parts.push(`ip_abuse=${a.ip_abuse_score}%${a.ip_is_tor ? ' [TOR]' : ''}  reports=${a.ip_total_reports}`)
        if (a.vt_malicious != null)
          parts.push(`vt=${a.vt_malicious}/${a.vt_total} engines  names=${(a.vt_names as string[] ?? []).slice(0, 2).join(',')}`)
        appendLog('log-dim', `  intel: ${parts.join('  |  ')}`)
      }

      try {
        const res = await api.analyzeCase({ ...a, timestamp: new Date().toISOString() })
        const { decision, confidence, explanation, recommended_action } = res.result
        const isTP = decision === 'True Positive'
        const pct  = (confidence * 100).toFixed(1)
        const pb   = res.playbooks_executed ?? 0

        appendLog(
          isTP ? 'log-tp' : 'log-fp',
          `  ${isTP ? '⚡' : '✓'} ${decision} — ${pct}%  [mem:${res.memory_context} skills:${res.skills_applied} pb:${pb}]`
        )
        appendLog('log-dim',  `  ${explanation.slice(0, 120)}…`)
        appendLog('log-warn', `  → ${recommended_action}`)

        if (res.incident) {
          const inc = res.incident
          const tag = inc.action === 'created' ? 'NEW' : `+${inc.case_count}`
          if (SHOW_KILL_CHAIN_LIVE) {
            const phases = inc.kill_chain_phases?.join(' → ') || '—'
            appendLog('log-info', `  ◈ ${inc.incident_id} [${tag}] ${inc.severity.toUpperCase()} | ${phases}`)
          } else {
            appendLog('log-info', `  ◈ ${inc.incident_id} [${tag}] ${inc.severity.toUpperCase()}`)
          }
        }

        results.push({
          caseId:            String(a.sourceRef),
          decision, confidence,
          memCtx:            res.memory_context,
          skillsApplied:     res.skills_applied,
          playbooksExecuted: pb,
          incidentId:        res.incident?.incident_id ?? null,
          incidentAction:    res.incident?.action     ?? null,
          enriched:          hasEnrichment,
          ok:                true,
        })
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e)
        appendLog('log-warn', `  ✗ Error: ${msg.slice(0, 100)}`)
        results.push({
          caseId: String(a.sourceRef), decision: 'ERROR', confidence: 0,
          memCtx: 0, skillsApplied: 0, playbooksExecuted: 0,
          incidentId: null, incidentAction: null, enriched: hasEnrichment, ok: false,
        })
      }

      await new Promise(r => setTimeout(r, 800))
    }

    appendLog('log-dim',  '')
    appendLog('log-dim',  '─'.repeat(64))
    const ok        = results.filter(r => r.ok)
    const incidents = [...new Set(ok.map(r => r.incidentId).filter(Boolean))]
    const totalPb   = ok.reduce((s, r) => s + r.playbooksExecuted, 0)
    appendLog('log-info', `✨ Done — ${ok.length}/${results.length} analyzed | ${incidents.length} incident(s) | ${totalPb} playbook(s) fired`)

    setScores(results)
    setDone(true)
    setRunning(false)
  }

  const ok        = scores.filter(s => s.ok)
  const tp        = ok.filter(s => s.decision === 'True Positive').length
  const fp        = ok.filter(s => s.decision === 'False Positive').length
  const errs      = scores.filter(s => !s.ok).length
  const avgConf   = ok.reduce((a, s) => a + s.confidence, 0) / (ok.length || 1)
  const totalPb   = ok.reduce((a, s) => a + s.playbooksExecuted, 0)
  const incidents = [...new Set(ok.map(s => s.incidentId).filter(Boolean))]

  return (
    <div>
      <div className="section-header">
        <div>
          <div className="section-title">Elite Simulation</div>
          <div className="section-sub">
            APT-29 campaign · ransomware · 3 FPs · enrichment · correlation · playbooks — {eliteAlerts.length} cases
          </div>
        </div>
        <button className="btn btn-primary" onClick={runSim} disabled={running}>
          {running ? '⟳ Running…' : '▶ Run Simulation'}
        </button>
      </div>

      {log.length > 0 && (
        <div className="terminal" ref={termRef}>
          {log.map((l, i) => (
            <div key={i} className="log-line">
              <span className="log-time">{l.time}</span>
              <span className={l.cls}>{l.text}</span>
            </div>
          ))}
        </div>
      )}

      {done && scores.length > 0 && (
        <div className="scoreboard">
          <div className="scoreboard-title">◈ Scoreboard</div>
          <table className="data-table" style={{ marginBottom: 14 }}>
            <thead>
              <tr>
                <th>Case</th>
                <th>Decision</th>
                <th>Confidence</th>
                <th>Mem</th>
                <th>Skills</th>
                <th>PB</th>
                <th>Incident</th>
                <th>Intel</th>
              </tr>
            </thead>
            <tbody>
              {scores.map(s => (
                <tr key={s.caseId}>
                  <td style={{ fontFamily: 'var(--mono)', fontSize: 11 }}>{s.caseId}</td>
                  <td>
                    {s.ok
                      ? <span className={`badge ${s.decision === 'True Positive' ? 'tp' : 'fp'}`}>
                          {s.decision === 'True Positive' ? '⚡ TP' : '✓ FP'}
                        </span>
                      : <span className="badge" style={{ color: 'var(--text-3)' }}>ERR</span>
                    }
                  </td>
                  <td>
                    {s.ok && (
                      <div className="conf-bar">
                        <div className="track">
                          <div className="fill" style={{
                            width: `${s.confidence * 100}%`,
                            background: s.decision === 'True Positive' ? 'var(--red)' : 'var(--green)',
                          }} />
                        </div>
                        <span className="label">{(s.confidence * 100).toFixed(0)}%</span>
                      </div>
                    )}
                  </td>
                  <td style={{ fontFamily: 'var(--mono)', fontSize: 11, color: s.memCtx > 0 ? 'var(--cyan)' : 'var(--text-3)' }}>
                    {s.memCtx}
                  </td>
                  <td style={{ fontFamily: 'var(--mono)', fontSize: 11, color: s.skillsApplied > 0 ? 'var(--green)' : 'var(--text-3)' }}>
                    {s.skillsApplied}
                  </td>
                  <td style={{ fontFamily: 'var(--mono)', fontSize: 11, color: s.playbooksExecuted > 0 ? 'var(--amber)' : 'var(--text-3)' }}>
                    {s.playbooksExecuted}
                  </td>
                  <td style={{ fontFamily: 'var(--mono)', fontSize: 10, color: s.incidentId ? 'var(--cyan)' : 'var(--text-3)' }}>
                    {s.incidentId
                      ? <>{s.incidentId} <span style={{ color: 'var(--text-3)', fontSize: 9 }}>{s.incidentAction === 'created' ? 'new' : '+1'}</span></>
                      : '—'
                    }
                  </td>
                  <td style={{ fontSize: 12, color: s.enriched ? 'var(--green)' : 'var(--text-3)', textAlign: 'center' }}>
                    {s.enriched ? '✓' : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          <div className="score-row"><span className="label">True Positives</span>   <span className="value" style={{ color: 'var(--red)' }}>{tp}</span></div>
          <div className="score-row"><span className="label">False Positives</span>  <span className="value" style={{ color: 'var(--green)' }}>{fp}</span></div>
          <div className="score-row"><span className="label">Errors</span>           <span className="value" style={{ color: 'var(--amber)' }}>{errs}</span></div>
          <div className="score-row"><span className="label">Avg Confidence</span>   <span className="value">{(avgConf * 100).toFixed(1)}%</span></div>
          <div className="score-row"><span className="label">Incidents Tracked</span><span className="value" style={{ color: 'var(--cyan)' }}>{incidents.length}</span></div>
          <div className="score-row"><span className="label">Playbooks Fired</span>  <span className="value" style={{ color: 'var(--amber)' }}>{totalPb}</span></div>
        </div>
      )}

      {log.length === 0 && (
        <div className="empty-state">
          <span className="icon">◎</span>
          <span>
            Run {eliteAlerts.length} elite SOC alerts through the full stack —
            APT-29 campaign chain, ransomware, 3 authorized FPs,
            with threat enrichment, incident correlation, and playbook execution
          </span>
        </div>
      )}
    </div>
  )
}
