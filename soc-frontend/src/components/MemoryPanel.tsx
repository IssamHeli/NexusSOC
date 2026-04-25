import { useCallback, useEffect, useState } from 'react'
import { api } from '../lib/api'
import type { Memory } from '../types'

type FeedbackState = { verdict: 'correct' | 'incorrect'; pending: boolean }

const STORAGE_KEY = 'nexussoc:feedback'

function loadPersistedFeedback(): Record<string, 'correct' | 'incorrect'> {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) ?? '{}')
  } catch {
    return {}
  }
}

function persistFeedback(caseId: string, verdict: 'correct' | 'incorrect') {
  try {
    const stored = loadPersistedFeedback()
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ ...stored, [caseId]: verdict }))
  } catch { /* localStorage unavailable */ }
}

function confColor(c: number) {
  return c >= 0.8 ? 'var(--green)' : c >= 0.5 ? 'var(--amber)' : 'var(--red)'
}

function ConfBar({ value, tpColor }: { value: number; tpColor?: boolean }) {
  const pct = Math.round(value * 100)
  const bg = tpColor ? 'var(--red)' : confColor(value)
  return (
    <div className="conf-bar">
      <div className="track">
        <div className="fill" style={{ width: `${pct}%`, background: bg }} />
      </div>
      <span className="label" style={{ color: tpColor ? undefined : confColor(value) }}>{pct}%</span>
    </div>
  )
}

function MemoryDetail({
  memory,
  feedback,
  onBack,
  onFeedback,
}: {
  memory: Memory
  feedback: FeedbackState | undefined
  onBack: () => void
  onFeedback: (caseId: string, correct: boolean) => void
}) {
  const isTP = memory.ai_decision === 'True Positive'

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Header */}
      <div className="section-header">
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <button className="btn btn-ghost" style={{ padding: '4px 10px', fontSize: 12 }} onClick={onBack}>
              ← Back
            </button>
            <div className="section-title" style={{ margin: 0 }}>Case {memory.case_id}</div>
            <span className={`badge ${isTP ? 'tp' : 'fp'}`} style={{ fontSize: 10 }}>
              {isTP ? '⚡ TP' : '✓ FP'}
            </span>
          </div>
          <div className="section-sub" style={{ marginTop: 6 }}>
            {new Date(memory.timestamp).toLocaleString()} · embedding {memory.has_embedding ? '● indexed' : '○ missing'}
          </div>
        </div>
      </div>

      {/* Stats grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div className="card">
          <div style={{ fontWeight: 600, fontSize: 12, color: 'var(--text-2)', marginBottom: 14, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
            Confidence
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 12, color: 'var(--text-3)' }}>Score</span>
              <div style={{ width: 160 }}>
                <ConfBar value={memory.confidence ?? 0} tpColor={isTP} />
              </div>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ fontSize: 12, color: 'var(--text-3)' }}>Decision</span>
              <span className={`badge ${isTP ? 'tp' : 'fp'}`}>{isTP ? 'True Positive' : 'False Positive'}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ fontSize: 12, color: 'var(--text-3)' }}>Vector</span>
              <span style={{ fontFamily: 'var(--mono)', fontSize: 12, color: memory.has_embedding ? 'var(--green)' : 'var(--text-3)' }}>
                {memory.has_embedding ? '● Indexed' : '○ No embedding'}
              </span>
            </div>
          </div>
        </div>

        <div className="card">
          <div style={{ fontWeight: 600, fontSize: 12, color: 'var(--text-2)', marginBottom: 14, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
            Analyst Feedback
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div style={{ fontSize: 12, color: 'var(--text-3)' }}>
              Rate this decision to improve future case matching
            </div>
            <div>
              {feedback && !feedback.pending ? (
                <span style={{
                  fontFamily: 'var(--mono)', fontSize: 13,
                  color: feedback.verdict === 'correct' ? 'var(--green)' : 'var(--red)',
                }}>
                  {feedback.verdict === 'correct' ? '✓ Marked correct' : '✗ Marked wrong'}
                </span>
              ) : feedback?.pending ? (
                <span style={{ color: 'var(--text-3)', fontSize: 12 }}>Sending…</span>
              ) : (
                <div style={{ display: 'flex', gap: 8 }}>
                  <button className="feedback-btn correct" style={{ padding: '6px 16px', fontSize: 13 }} title="Agent was correct" onClick={() => onFeedback(memory.case_id, true)}>✓ Correct</button>
                  <button className="feedback-btn incorrect" style={{ padding: '6px 16px', fontSize: 13 }} title="Agent was wrong" onClick={() => onFeedback(memory.case_id, false)}>✗ Wrong</button>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Analysis Summary */}
      <div className="card">
        <div style={{ fontWeight: 600, fontSize: 12, color: 'var(--text-2)', marginBottom: 14, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
          Analysis Summary
        </div>
        <p style={{ fontSize: 13, color: 'var(--text-2)', lineHeight: 1.7, margin: 0 }}>
          {memory.analysis_summary || '—'}
        </p>
      </div>

      {/* Recommended Action */}
      {memory.recommended_action && (
        <div className="card">
          <div style={{ fontWeight: 600, fontSize: 12, color: 'var(--text-2)', marginBottom: 14, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
            Recommended Action
          </div>
          <p style={{ fontSize: 13, color: 'var(--text-2)', lineHeight: 1.7, margin: 0 }}>
            {memory.recommended_action}
          </p>
        </div>
      )}
    </div>
  )
}

export function MemoryPanel() {
  const [memories,  setMemories]  = useState<Memory[]>([])
  const [loading,   setLoading]   = useState(true)
  const [error,     setError]     = useState<string | null>(null)
  const [selected,  setSelected]  = useState<Memory | null>(null)
  const [feedback,  setFeedback]  = useState<Record<string, FeedbackState>>(() => {
    const persisted = loadPersistedFeedback()
    return Object.fromEntries(
      Object.entries(persisted).map(([id, verdict]) => [id, { verdict, pending: false }])
    )
  })

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    api.getMemory(30)
      .then(r => setMemories(r.memories))
      .catch(e => setError(e.message ?? 'Failed to load memory'))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => { load() }, [load])

  const sendFeedback = async (caseId: string, correct: boolean) => {
    if (feedback[caseId] && !feedback[caseId].pending) return
    const verdict = correct ? 'correct' : 'incorrect'
    setFeedback(f => ({ ...f, [caseId]: { verdict, pending: true } }))
    try {
      await api.sendFeedback(caseId, correct)
      persistFeedback(caseId, verdict)
      setFeedback(f => ({ ...f, [caseId]: { verdict, pending: false } }))
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Failed to send feedback'
      setError(msg)
      setFeedback(f => { const next = { ...f }; delete next[caseId]; return next })
    }
  }

  if (selected) {
    return (
      <MemoryDetail
        memory={selected}
        feedback={feedback[selected.case_id]}
        onBack={() => setSelected(null)}
        onFeedback={sendFeedback}
      />
    )
  }

  if (loading) return <div className="empty-state"><span className="log-info">Loading memory…</span></div>

  return (
    <div>
      <div className="section-header">
        <div>
          <div className="section-title">Case Memory</div>
          <div className="section-sub">
            {memories.length} cases indexed · analyst feedback improves future case matching
          </div>
        </div>
        <button className="btn btn-ghost" onClick={load} disabled={loading}>↺ Refresh</button>
      </div>

      {error && (
        <div className="empty-state" style={{ color: 'var(--red)', marginBottom: 8 }}>⚠ {error}</div>
      )}

      {memories.length === 0 ? (
        <div className="empty-state">
          <span className="icon">◎</span>
          <span>No memories yet — run the simulation</span>
        </div>
      ) : (
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Case ID</th>
                <th>Decision</th>
                <th>Confidence</th>
                <th>Summary</th>
                <th>Action</th>
                <th>Vector</th>
                <th>Feedback</th>
                <th>Time</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {memories.map((m, i) => {
                const fb = feedback[m.case_id]
                const isTP = m.ai_decision === 'True Positive'
                return (
                  <tr key={`${m.case_id}-${i}`} style={{ cursor: 'pointer' }} onClick={() => setSelected(m)}>
                    <td style={{ fontFamily: 'var(--mono)', fontSize: 12 }}>{m.case_id}</td>
                    <td>
                      <span className={`badge ${isTP ? 'tp' : 'fp'}`}>
                        {isTP ? '⚡ TP' : '✓ FP'}
                      </span>
                    </td>
                    <td>
                      <div className="conf-bar">
                        <div className="track">
                          <div className="fill" style={{
                            width: `${(m.confidence ?? 0) * 100}%`,
                            background: isTP ? 'var(--red)' : 'var(--green)',
                          }} />
                        </div>
                        <span className="label">{((m.confidence ?? 0) * 100).toFixed(0)}%</span>
                      </div>
                    </td>
                    <td style={{ maxWidth: 280, color: 'var(--text-2)', fontSize: 12 }}>
                      {(m.analysis_summary ?? '').slice(0, 90)}
                      {(m.analysis_summary ?? '').length > 90 ? '…' : ''}
                    </td>
                    <td style={{ maxWidth: 180, color: 'var(--text-2)', fontSize: 11 }}>
                      {(m.recommended_action ?? '').slice(0, 60)}
                      {(m.recommended_action ?? '').length > 60 ? '…' : ''}
                    </td>
                    <td style={{ fontFamily: 'var(--mono)', fontSize: 11, color: m.has_embedding ? 'var(--green)' : 'var(--text-3)' }}>
                      {m.has_embedding ? '● vec' : '○'}
                    </td>
                    <td onClick={e => e.stopPropagation()}>
                      {fb && !fb.pending ? (
                        <span style={{
                          fontFamily: 'var(--mono)',
                          fontSize: 11,
                          color: fb.verdict === 'correct' ? 'var(--green)' : 'var(--red)',
                        }}>
                          {fb.verdict === 'correct' ? '✓ correct' : '✗ wrong'}
                        </span>
                      ) : fb?.pending ? (
                        <span style={{ color: 'var(--text-3)', fontSize: 11 }}>…</span>
                      ) : (
                        <div className="feedback-btns">
                          <button
                            className="feedback-btn correct"
                            title="Agent was correct"
                            onClick={() => sendFeedback(m.case_id, true)}
                          >
                            ✓
                          </button>
                          <button
                            className="feedback-btn incorrect"
                            title="Agent was wrong"
                            onClick={() => sendFeedback(m.case_id, false)}
                          >
                            ✗
                          </button>
                        </div>
                      )}
                    </td>
                    <td style={{ color: 'var(--text-3)', fontFamily: 'var(--mono)', fontSize: 11, whiteSpace: 'nowrap' }}>
                      {new Date(m.timestamp).toLocaleString()}
                    </td>
                    <td onClick={e => e.stopPropagation()}>
                      <button className="btn btn-ghost" style={{ padding: '4px 10px', fontSize: 11 }} onClick={() => setSelected(m)}>View</button>
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
