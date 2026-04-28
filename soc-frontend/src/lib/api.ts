import type { HealthStatus, AnalyzeResponse, Skill, Memory, Incident, Playbook, PlaybookExecution, AuditLog, User, PluginStatus } from '../types'

const BASE = import.meta.env.VITE_API_URL ?? 'http://localhost:8001'

const KEY_ACCESS  = 'nexussoc:access_token'
const KEY_REFRESH = 'nexussoc:refresh_token'
const KEY_USER    = 'nexussoc:user'

let _onUnauthorized: (() => void) | null = null

/** Register a callback that fires when the session expires (all 401s exhausted). */
export function setUnauthorizedHandler(fn: () => void) {
  _onUnauthorized = fn
}

async function _tryRefresh(): Promise<string | null> {
  const refreshToken = localStorage.getItem(KEY_REFRESH)
  if (!refreshToken) return null
  try {
    const res = await fetch(`${BASE}/auth/refresh`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ refresh_token: refreshToken }),
    })
    if (!res.ok) return null
    const data = await res.json() as {
      access_token: string; refresh_token: string; username: string; role: string
    }
    localStorage.setItem(KEY_ACCESS,  data.access_token)
    localStorage.setItem(KEY_REFRESH, data.refresh_token)
    localStorage.setItem(KEY_USER,    JSON.stringify({ username: data.username, role: data.role }))
    return data.access_token
  } catch {
    return null
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const token = localStorage.getItem(KEY_ACCESS)
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (token) headers['Authorization'] = `Bearer ${token}`

  let res = await fetch(`${BASE}${path}`, { headers, ...init })

  // On 401 try a token refresh once, then retry the original request
  if (res.status === 401) {
    const newToken = await _tryRefresh()
    if (newToken) {
      res = await fetch(`${BASE}${path}`, {
        headers: { ...headers, Authorization: `Bearer ${newToken}` },
        ...init,
      })
    }
  }

  // Still 401 after refresh attempt — session is dead
  if (res.status === 401) {
    localStorage.removeItem(KEY_ACCESS)
    localStorage.removeItem(KEY_REFRESH)
    localStorage.removeItem(KEY_USER)
    _onUnauthorized?.()
    throw new Error('Session expired — please log in again')
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error((err as { detail?: string }).detail ?? `HTTP ${res.status}`)
  }
  return res.json()
}

export const api = {
  health: () => request<HealthStatus>('/health'),

  analyzeCase: (alert: Record<string, unknown>) =>
    request<AnalyzeResponse>('/analyze-case', {
      method: 'POST',
      body: JSON.stringify(alert),
    }),

  getSkills: (minConfidence = 0) =>
    request<{ total: number; skills: Skill[] }>(`/skills?min_confidence=${minConfidence}`),

  deleteSkill: (id: number) =>
    request<{ deleted: number }>(`/skills/${id}`, { method: 'DELETE' }),

  skillFeedback: (id: number, correct: boolean, note?: string) =>
    request<{ skill_id: number; confidence_before: number; confidence_after: number }>(
      `/skills/${id}/feedback`,
      { method: 'POST', body: JSON.stringify({ correct, analyst_note: note }) }
    ),

  getMemory: (limit = 20) =>
    request<{ total: number; memories: Memory[] }>(`/memory?limit=${limit}`),

  sendFeedback: (caseId: string, correct: boolean, note?: string) =>
    request(`/feedback/${caseId}`, {
      method: 'POST',
      body: JSON.stringify({ correct, analyst_note: note }),
    }),

  getIncidents: (status?: string, limit = 50) =>
    request<{ total: number; incidents: Incident[] }>(
      `/incidents${status ? `?status=${status}&limit=${limit}` : `?limit=${limit}`}`
    ),

  getIncident: (incidentId: string) =>
    request<Incident>(`/incidents/${incidentId}`),

  updateIncidentStatus: (incidentId: string, status: string) =>
    request<{ incident_id: string; status: string }>(
      `/incidents/${incidentId}/status?status=${encodeURIComponent(status)}`,
      { method: 'PATCH' }
    ),

  getPlaybooks: () =>
    request<{ total: number; playbooks: Playbook[] }>('/playbooks'),

  createPlaybook: (data: {
    name: string
    description?: string
    trigger_decision: string
    trigger_min_confidence: number
    trigger_attack_types?: string[]
    actions: object[]
    enabled: boolean
  }) =>
    request<{ created: Playbook }>('/playbooks', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  deletePlaybook: (id: number) =>
    request<{ deleted: number }>(`/playbooks/${id}`, { method: 'DELETE' }),

  getPlaybookExecutions: (limit = 30) =>
    request<{ total: number; executions: PlaybookExecution[] }>(`/playbooks/executions?limit=${limit}`),

  getQueueDepth: () =>
    request<{ depth: number; redis: boolean; queue?: string }>('/queue/depth'),

  getMitreExportUrl: () => `${BASE}/mitre/export`,

  getAuditLogs: (limit = 100, offset = 0) =>
    request<{ total: number; logs: AuditLog[] }>(`/admin/audit-logs?limit=${limit}&offset=${offset}`),

  getUsers: () =>
    request<{ total: number; users: User[] }>('/admin/users'),

  createUser: (data: { username: string; password: string; role: string }) =>
    request<{ created: { id: number; username: string; role: string } }>('/admin/users', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  updateUserRole: (username: string, role: string) =>
    request<{ username: string; role: string }>(`/admin/users/${username}/role`, {
      method: 'PATCH',
      body: JSON.stringify({ role }),
    }),

  resetUserPassword: (username: string, password: string) =>
    request<{ username: string; message: string }>(`/admin/users/${username}/password`, {
      method: 'PATCH',
      body: JSON.stringify({ password }),
    }),

  deleteUser: (username: string) =>
    request<{ username: string; message: string }>(`/admin/users/${username}`, {
      method: 'DELETE',
    }),

  getPlugins: () =>
    request<{ plugins: PluginStatus[] }>('/plugins'),

  getConnectors: () =>
    request<{ connectors: string[] }>('/connectors'),

  getDlq: (limit = 50) =>
    request<{
      total: number
      limit: number
      jobs: Array<{
        job_id:     string
        alert:      Record<string, unknown>
        attempts:   number
        last_error: string
        failed_at:  string
      }>
    }>(`/queue/dlq?limit=${limit}`),

  clearDlq: () =>
    request<{ cleared: number }>('/queue/dlq/clear', { method: 'POST' }),

  requeueAllDlq: () =>
    request<{ requeued: number; failed: number }>('/queue/dlq/requeue-all', { method: 'POST' }),

  /** Trigger a STIX 2.1 download for a single case via authenticated fetch + Blob. */
  exportCaseStix: async (caseId: string): Promise<void> => {
    const token = localStorage.getItem(KEY_ACCESS)
    const headers: Record<string, string> = {}
    if (token) headers['Authorization'] = `Bearer ${token}`
    const res = await fetch(`${BASE}/export/case/${encodeURIComponent(caseId)}/stix2`, { headers })
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }))
      throw new Error((err as { detail?: string }).detail ?? `HTTP ${res.status}`)
    }
    const blob = await res.blob()
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href     = url
    a.download = `nexussoc-${caseId}-stix2.json`
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
  },
}
