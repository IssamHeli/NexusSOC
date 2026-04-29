import { useRef, useState } from 'react'
import { api } from '../lib/api'

export interface BatchIngestResultItem {
  index:     number
  success:   boolean
  job_id?:    string
  case_id?:   string
  connector?: string
  error?:     string
}

interface BatchIngestResponse {
  results:   BatchIngestResultItem[]
  total:     number
  succeeded: number
  failed:    number
}

const CONNECTOR_OPTIONS = [
  { value: '',        label: 'Auto-detect' },
  { value: 'wazuh',  label: 'Wazuh' },
  { value: 'elastic', label: 'Elastic SIEM' },
  { value: 'splunk', label: 'Splunk' },
  { value: 'qradar', label: 'IBM QRadar' },
  { value: 'generic', label: 'Generic' },
]

function ResultCard({ item }: { item: BatchIngestResultItem }) {
  return (
    <div style={{
      borderLeft: `3px solid ${item.success ? 'var(--green, #00e676)' : 'var(--red, #ff5252)'}`,
      padding: '10px 14px',
      background: 'var(--bg-elevated, #1e1e2e)',
      borderRadius: '0 6px 6px 0',
      marginBottom: 8,
    }}>
      {item.success ? (
        <>
          <div style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--cyan, #80deea)' }}>
            job: {item.job_id}
          </div>
          <div style={{ fontFamily: 'monospace', fontSize: 11, marginTop: 2 }}>
            case: {item.case_id}
          </div>
          <div style={{ fontSize: 11, marginTop: 4 }}>
            <span style={{
              background: 'rgba(0,230,118,.12)',
              color: 'var(--green, #00e676)',
              padding: '2px 8px',
              borderRadius: 4,
              fontFamily: 'monospace',
            }}>
              {item.connector} · queued
            </span>
          </div>
        </>
      ) : (
        <>
          <div style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--text-2, #888)' }}>
            Alert #{item.index + 1}
          </div>
          <div style={{ fontSize: 12, color: 'var(--red, #ff5252)', marginTop: 4 }}>
            {item.error}
          </div>
        </>
      )}
    </div>
  )
}

export function AnalyzeForm() {
  const [inputMode,    setInputMode]    = useState<'paste' | 'file'>('paste')
  const [jsonText,     setJsonText]     = useState('')
  const [fileName,     setFileName]     = useState<string | null>(null)
  const [fileCount,    setFileCount]    = useState<number | null>(null)
  const [connectorHint, setConnectorHint] = useState('')
  const [results,      setResults]      = useState<BatchIngestResultItem[] | null>(null)
  const [submitting,   setSubmitting]   = useState(false)
  const [topError,     setTopError]     = useState<string | null>(null)
  const [parseError,   setParseError]   = useState<string | null>(null)
  const [summary,      setSummary]      = useState<{ total: number; succeeded: number; failed: number } | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setParseError(null)
    setResults(null)
    setSummary(null)
    const file = e.target.files?.[0]
    if (!file) return
    setFileName(file.name)
    const reader = new FileReader()
    reader.onload = (ev) => {
      try {
        const parsed = JSON.parse(ev.target?.result as string)
        const arr: unknown[] = Array.isArray(parsed) ? parsed : (parsed.alerts ?? null)
        if (!Array.isArray(arr)) throw new Error('Expected array of alerts in JSON file')
        setFileCount(arr.length)
      } catch (err: unknown) {
        setParseError(err instanceof Error ? err.message : 'Invalid JSON file')
        setFileCount(null)
      }
    }
    reader.readAsText(file)
  }

  const handleSubmit = async () => {
    setTopError(null)
    setParseError(null)
    setResults(null)
    setSummary(null)

    let alerts: Record<string, unknown>[]

    if (inputMode === 'paste') {
      if (!jsonText.trim()) { setTopError('No JSON provided'); return }
      try {
        const parsed = JSON.parse(jsonText)
        alerts = Array.isArray(parsed) ? parsed : [parsed]
      } catch (err: unknown) {
        setParseError(err instanceof Error ? err.message : 'Invalid JSON')
        return
      }
    } else {
      const file = fileRef.current?.files?.[0]
      if (!file) { setTopError('No file selected'); return }
      try {
        const text = await file.text()
        const parsed = JSON.parse(text)
        alerts = Array.isArray(parsed) ? parsed : ((parsed as Record<string, unknown>).alerts as unknown[]) ?? null
        if (!Array.isArray(alerts)) throw new Error('Expected array of alerts in JSON file')
      } catch (err: unknown) {
        setTopError(err instanceof Error ? err.message : 'Could not parse file')
        return
      }
    }

    if (alerts.length === 0) { setTopError('No alerts to submit'); return }

    setSubmitting(true)
    try {
      const res = await api.ingestBatch({
        connector_name: connectorHint || undefined,
        alerts,
      }) as BatchIngestResponse
      setResults(res.results)
      setSummary({ total: res.total, succeeded: res.succeeded, failed: res.failed })
    } catch (err: unknown) {
      setTopError(err instanceof Error ? err.message : 'Submission failed')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div style={{ padding: '0 24px 24px' }}>
      <div style={{ marginBottom: 24 }}>
        <h2 style={{ margin: 0, fontSize: '1.25rem' }}>Analyze</h2>
        <p style={{ margin: '4px 0 0', color: 'var(--text-muted, #888)', fontSize: 13 }}>
          Submit raw SIEM alerts for AI analysis — single alert or batch via JSON file
        </p>
      </div>

      <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        <button
          onClick={() => { setInputMode('paste'); setResults(null); setSummary(null); setParseError(null) }}
          style={{
            padding: '6px 16px',
            borderRadius: 6,
            border: '1px solid',
            borderColor: inputMode === 'paste' ? 'var(--accent, #7c6af7)' : 'var(--border, #333)',
            background: inputMode === 'paste' ? 'rgba(124,106,247,.15)' : 'transparent',
            color: inputMode === 'paste' ? 'var(--accent, #7c6af7)' : 'var(--text-muted, #888)',
            cursor: 'pointer',
            fontSize: 13,
          }}
        >
          Paste JSON
        </button>
        <button
          onClick={() => { setInputMode('file'); setResults(null); setSummary(null); setParseError(null) }}
          style={{
            padding: '6px 16px',
            borderRadius: 6,
            border: '1px solid',
            borderColor: inputMode === 'file' ? 'var(--accent, #7c6af7)' : 'var(--border, #333)',
            background: inputMode === 'file' ? 'rgba(124,106,247,.15)' : 'transparent',
            color: inputMode === 'file' ? 'var(--accent, #7c6af7)' : 'var(--text-muted, #888)',
            cursor: 'pointer',
            fontSize: 13,
          }}
        >
          Upload .json
        </button>
      </div>

      <div style={{ marginBottom: 16, display: 'flex', alignItems: 'center', gap: 12 }}>
        <label style={{ fontSize: 13, color: 'var(--text-muted, #888)' }}>Connector:</label>
        <select
          value={connectorHint}
          onChange={e => setConnectorHint(e.target.value)}
          style={{
            background: 'var(--bg-elevated, #1e1e2e)',
            border: '1px solid var(--border, #333)',
            borderRadius: 6,
            color: 'var(--text, #e0e0e0)',
            padding: '6px 10px',
            fontSize: 13,
          }}
        >
          {CONNECTOR_OPTIONS.map(o => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </select>
      </div>

      {inputMode === 'paste' && (
        <div style={{ marginBottom: 16 }}>
          <textarea
            value={jsonText}
            onChange={e => { setJsonText(e.target.value); setParseError(null) }}
            placeholder={'[\n  {"rule":{"level":10,"description":"SSH brute force"},"agent":{"name":"host-01"}},\n  {"rule":{"level":5,"description":"Login success"},"agent":{"name":"host-02"}}\n]'}
            style={{
              width: '100%',
              minHeight: 200,
              fontFamily: 'monospace',
              fontSize: 12,
              background: 'var(--bg-elevated, #1e1e2e)',
              border: `1px solid ${parseError ? 'var(--red, #ff5252)' : 'var(--border, #333)'}`,
              borderRadius: 6,
              color: 'var(--text, #e0e0e0)',
              padding: 10,
              resize: 'vertical',
              boxSizing: 'border-box',
            }}
          />
          {parseError && (
            <div style={{ color: 'var(--red, #ff5252)', fontSize: 12, marginTop: 4 }}>
              ⚠ {parseError}
            </div>
          )}
        </div>
      )}

      {inputMode === 'file' && (
        <div style={{ marginBottom: 16 }}>
          <input
            ref={fileRef}
            type="file"
            accept=".json"
            onChange={handleFileChange}
            style={{ fontSize: 13 }}
          />
          {fileName && (
            <div style={{ fontSize: 12, color: 'var(--text-muted, #888)', marginTop: 6 }}>
              {fileName}
              {fileCount !== null && ` — ${fileCount} alert${fileCount !== 1 ? 's' : ''} detected`}
            </div>
          )}
          {parseError && (
            <div style={{ color: 'var(--red, #ff5252)', fontSize: 12, marginTop: 4 }}>
              ⚠ {parseError}
            </div>
          )}
        </div>
      )}

      <button
        onClick={handleSubmit}
        disabled={submitting}
        style={{
          padding: '8px 20px',
          borderRadius: 6,
          border: 'none',
          background: 'var(--accent, #7c6af7)',
          color: '#fff',
          fontSize: 13,
          cursor: submitting ? 'not-allowed' : 'pointer',
          opacity: submitting ? 0.6 : 1,
        }}
      >
        {submitting ? 'Submitting…' : 'Submit for Analysis'}
      </button>

      {topError && (
        <div style={{
          marginTop: 16,
          padding: '10px 14px',
          borderRadius: 6,
          background: 'rgba(255,82,82,.1)',
          border: '1px solid rgba(255,82,82,.3)',
          color: 'var(--red, #ff5252)',
          fontSize: 13,
        }}>
          ⚠ {topError}
        </div>
      )}

      {summary && (
        <div style={{
          marginTop: 20,
          padding: '10px 14px',
          borderRadius: 6,
          background: 'var(--bg-elevated, #1e1e2e)',
          border: '1px solid var(--border, #333)',
          fontSize: 13,
          display: 'flex',
          gap: 16,
        }}>
          <span>
            <span style={{ color: 'var(--green, #00e676)' }}>{summary.succeeded}</span> succeeded
          </span>
          <span>
            <span style={{ color: summary.failed > 0 ? 'var(--red, #ff5252)' : 'var(--text-muted, #888)' }}>{summary.failed}</span> failed
          </span>
          <span style={{ color: 'var(--text-muted, #888)' }}>
            total: {summary.total}
          </span>
        </div>
      )}

      {results && (
        <div style={{ marginTop: 16 }}>
          {results.map(item => (
            <ResultCard key={item.index} item={item} />
          ))}
        </div>
      )}
    </div>
  )
}
