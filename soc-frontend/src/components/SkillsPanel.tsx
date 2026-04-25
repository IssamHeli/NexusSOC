import { useCallback, useEffect, useState } from 'react'
import { api } from '../lib/api'
import type { Skill } from '../types'

type FeedbackState = { verdict: 'correct' | 'incorrect'; pending: boolean }

const STORAGE_KEY = 'nexussoc:skill-feedback'

function loadPersistedFeedback(): Record<string, 'correct' | 'incorrect'> {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY) ?? '{}') } catch { return {} }
}

function persistFeedback(id: number, verdict: 'correct' | 'incorrect') {
  try {
    const stored = loadPersistedFeedback()
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ ...stored, [id]: verdict }))
  } catch { /* localStorage unavailable */ }
}

function confColor(c: number) {
  return c >= 0.8 ? 'var(--green)' : c >= 0.5 ? 'var(--amber)' : 'var(--red)'
}

function ConfBar({ value }: { value: number }) {
  const pct = Math.round(value * 100)
  return (
    <div className="conf-bar">
      <div className="track">
        <div className="fill" style={{ width: `${pct}%`, background: confColor(value) }} />
      </div>
      <span className="label" style={{ color: confColor(value) }}>{pct}%</span>
    </div>
  )
}

function SkillDetail({
  skill,
  feedback,
  onBack,
  onDelete,
  onFeedback,
}: {
  skill: Skill
  feedback: FeedbackState | undefined
  onBack: () => void
  onDelete: (id: number) => void
  onFeedback: (id: number, correct: boolean) => void
}) {
  const successRate = skill.usage_count > 0
    ? Math.round((skill.success_count / skill.usage_count) * 100)
    : null

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Header */}
      <div className="section-header">
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <button className="btn btn-ghost" style={{ padding: '4px 10px', fontSize: 12 }} onClick={onBack}>
              ← Back
            </button>
            <div className="section-title" style={{ margin: 0 }}>{skill.skill_name}</div>
            <span className={`badge ${skill.decision === 'True Positive' ? 'tp' : 'fp'}`} style={{ fontSize: 10 }}>
              {skill.decision === 'True Positive' ? '⚡ TP' : '✓ FP'}
            </span>
          </div>
          <div className="section-sub" style={{ marginTop: 6 }}>
            ID #{skill.id} · created {new Date(skill.created_at).toLocaleDateString()} · updated {new Date(skill.updated_at).toLocaleDateString()}
          </div>
        </div>
        <button className="btn btn-danger" style={{ padding: '6px 14px', fontSize: 12 }} onClick={() => onDelete(skill.id)}>
          Delete
        </button>
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
              <div style={{ width: 160 }}><ConfBar value={skill.confidence_score} /></div>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ fontSize: 12, color: 'var(--text-3)' }}>Times Used</span>
              <span style={{ fontFamily: 'var(--mono)', fontSize: 14, fontWeight: 700 }}>{skill.usage_count}×</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ fontSize: 12, color: 'var(--text-3)' }}>Success Rate</span>
              <span style={{ fontFamily: 'var(--mono)', fontSize: 14, color: successRate !== null ? confColor(successRate / 100) : 'var(--text-3)' }}>
                {successRate !== null ? `${successRate}%` : '—'}
                <span style={{ color: 'var(--text-3)', marginLeft: 6, fontSize: 11 }}>({skill.success_count}/{skill.usage_count})</span>
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
              Rate this pattern to update its confidence via EMA (α=0.15)
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
                  <button className="feedback-btn correct" style={{ padding: '6px 16px', fontSize: 13 }} title="Pattern is correct" onClick={() => onFeedback(skill.id, true)}>✓ Correct</button>
                  <button className="feedback-btn incorrect" style={{ padding: '6px 16px', fontSize: 13 }} title="Pattern is wrong" onClick={() => onFeedback(skill.id, false)}>✗ Wrong</button>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Pattern */}
      <div className="card">
        <div style={{ fontWeight: 600, fontSize: 12, color: 'var(--text-2)', marginBottom: 14, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
          Detection Pattern
        </div>
        <p style={{ fontSize: 13, color: 'var(--text-2)', lineHeight: 1.7, margin: 0 }}>{skill.pattern}</p>
      </div>

      {/* MITRE */}
      {(skill.mitre_techniques ?? []).length > 0 && (
        <div className="card">
          <div style={{ fontWeight: 600, fontSize: 12, color: 'var(--text-2)', marginBottom: 14, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
            MITRE ATT&CK Techniques
          </div>
          <div className="mitre-chips">
            {(skill.mitre_techniques ?? []).map(t => (
              <span key={t} className="mitre-chip" style={{ fontSize: 12, padding: '4px 10px' }}>{t}</span>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

export function SkillsPanel() {
  const [skills,         setSkills]         = useState<Skill[]>([])
  const [loading,        setLoading]        = useState(true)
  const [error,          setError]          = useState<string | null>(null)
  const [minConf,        setMinConf]        = useState(0)
  const [filterDecision, setFilterDecision] = useState<string>('all')
  const [selected,       setSelected]       = useState<Skill | null>(null)
  const [feedback,       setFeedback]       = useState<Record<number, FeedbackState>>(() => {
    const persisted = loadPersistedFeedback()
    return Object.fromEntries(
      Object.entries(persisted).map(([id, verdict]) => [Number(id), { verdict, pending: false }])
    )
  })

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    api.getSkills(minConf)
      .then(r => setSkills(r.skills))
      .catch(e => setError(e.message ?? 'Failed to load skills'))
      .finally(() => setLoading(false))
  }, [minConf])

  useEffect(() => { load() }, [load])

  const remove = async (id: number) => {
    await api.deleteSkill(id).catch(e => setError(e.message ?? 'Failed to delete skill'))
    setSkills(s => s.filter(x => x.id !== id))
    setSelected(null)
  }

  const sendFeedback = async (id: number, correct: boolean) => {
    if (feedback[id] && !feedback[id].pending) return
    const verdict = correct ? 'correct' : 'incorrect'
    setFeedback(f => ({ ...f, [id]: { verdict, pending: true } }))
    try {
      const res = await api.skillFeedback(id, correct)
      persistFeedback(id, verdict)
      setFeedback(f => ({ ...f, [id]: { verdict, pending: false } }))
      setSkills(s => s.map(sk => sk.id === id ? { ...sk, confidence_score: res.confidence_after } : sk))
      if (selected?.id === id) setSelected(prev => prev ? { ...prev, confidence_score: res.confidence_after } : prev)
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Failed to send feedback'
      setError(msg)
      setFeedback(f => { const next = { ...f }; delete next[id]; return next })
    }
  }

  const visible = skills.filter(s => filterDecision === 'all' || s.decision === filterDecision)
  const avgConf    = skills.length > 0 ? skills.reduce((a, s) => a + s.confidence_score, 0) / skills.length : 0
  const totalUsage = skills.reduce((a, s) => a + s.usage_count, 0)

  if (selected) {
    return (
      <SkillDetail
        skill={selected}
        feedback={feedback[selected.id]}
        onBack={() => setSelected(null)}
        onDelete={remove}
        onFeedback={sendFeedback}
      />
    )
  }

  return (
    <div>
      <div className="section-header">
        <div>
          <div className="section-title">Learned Skills</div>
          <div className="section-sub">
            {skills.length} patterns · avg confidence {(avgConf * 100).toFixed(0)}% · {totalUsage} total uses
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <select className="filter-select" value={filterDecision} onChange={e => setFilterDecision(e.target.value)}>
            <option value="all">All decisions</option>
            <option value="True Positive">True Positive</option>
            <option value="False Positive">False Positive</option>
          </select>
          <select className="filter-select" value={minConf} onChange={e => setMinConf(Number(e.target.value))}>
            <option value={0}>All confidence</option>
            <option value={0.5}>≥ 50%</option>
            <option value={0.7}>≥ 70%</option>
            <option value={0.85}>≥ 85%</option>
          </select>
          <button className="btn btn-ghost" onClick={load}>↺ Refresh</button>
        </div>
      </div>

      {error && (
        <div className="empty-state" style={{ color: 'var(--red)' }}>⚠ {error}</div>
      )}

      {loading ? (
        <div className="empty-state"><span className="log-info">Loading skills…</span></div>
      ) : visible.length === 0 ? (
        <div className="empty-state">
          <span className="icon">◎</span>
          <span>No skills match filter — run simulation to build knowledge</span>
        </div>
      ) : (
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>#</th>
                <th>Skill Name</th>
                <th>Pattern</th>
                <th>Decision</th>
                <th>Confidence</th>
                <th>Success Rate</th>
                <th>Used</th>
                <th>MITRE</th>
                <th>Feedback</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {visible.map(s => {
                const successRate = s.usage_count > 0 ? Math.round((s.success_count / s.usage_count) * 100) : null
                const fb = feedback[s.id]
                return (
                  <tr key={s.id} style={{ cursor: 'pointer' }} onClick={() => setSelected(s)}>
                    <td style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--text-3)' }}>{s.id}</td>
                    <td style={{ fontWeight: 600, maxWidth: 160 }}>{s.skill_name}</td>
                    <td style={{ color: 'var(--text-2)', fontSize: 12, maxWidth: 260 }}>
                      {s.pattern.slice(0, 120)}{s.pattern.length > 120 ? '…' : ''}
                    </td>
                    <td>
                      <span className={`badge ${s.decision === 'True Positive' ? 'tp' : 'fp'}`}>
                        {s.decision === 'True Positive' ? '⚡ TP' : '✓ FP'}
                      </span>
                    </td>
                    <td>
                      <div className="conf-bar">
                        <div className="track">
                          <div className="fill" style={{ width: `${s.confidence_score * 100}%`, background: confColor(s.confidence_score) }} />
                        </div>
                        <span className="label" style={{ color: confColor(s.confidence_score) }}>
                          {(s.confidence_score * 100).toFixed(0)}%
                        </span>
                      </div>
                    </td>
                    <td style={{ fontFamily: 'var(--mono)', fontSize: 12, color: successRate !== null ? confColor(successRate / 100) : 'var(--text-3)' }}>
                      {successRate !== null ? `${successRate}%` : '—'}
                      <span style={{ color: 'var(--text-3)', marginLeft: 4, fontSize: 10 }}>
                        {s.success_count}/{s.usage_count}
                      </span>
                    </td>
                    <td style={{ fontFamily: 'var(--mono)', fontSize: 12, color: s.usage_count > 0 ? 'var(--text-2)' : 'var(--text-3)' }}>
                      {s.usage_count}×
                    </td>
                    <td>
                      <div className="mitre-chips">
                        {(s.mitre_techniques ?? []).slice(0, 2).map(t => (
                          <span key={t} className="mitre-chip">{t}</span>
                        ))}
                        {(s.mitre_techniques ?? []).length > 2 && (
                          <span className="mitre-chip">+{(s.mitre_techniques ?? []).length - 2}</span>
                        )}
                      </div>
                    </td>
                    <td onClick={e => e.stopPropagation()}>
                      {fb && !fb.pending ? (
                        <span style={{ fontFamily: 'var(--mono)', fontSize: 11, color: fb.verdict === 'correct' ? 'var(--green)' : 'var(--red)' }}>
                          {fb.verdict === 'correct' ? '✓ good' : '✗ wrong'}
                        </span>
                      ) : fb?.pending ? (
                        <span style={{ color: 'var(--text-3)', fontSize: 11 }}>…</span>
                      ) : (
                        <div className="feedback-btns">
                          <button className="feedback-btn correct" title="Pattern is correct" onClick={() => sendFeedback(s.id, true)}>✓</button>
                          <button className="feedback-btn incorrect" title="Pattern is wrong" onClick={() => sendFeedback(s.id, false)}>✗</button>
                        </div>
                      )}
                    </td>
                    <td onClick={e => e.stopPropagation()}>
                      <div style={{ display: 'flex', gap: 4 }}>
                        <button className="btn btn-ghost" style={{ padding: '4px 10px', fontSize: 11 }} onClick={() => setSelected(s)}>View</button>
                        <button className="btn btn-danger" style={{ padding: '4px 10px', fontSize: 11 }} onClick={() => remove(s.id)}>Del</button>
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
