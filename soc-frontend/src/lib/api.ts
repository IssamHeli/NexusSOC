import type { HealthStatus, AnalyzeResponse, Skill, Memory, Incident, Playbook, PlaybookExecution } from '../types'

const BASE = import.meta.env.VITE_API_URL ?? 'http://localhost:8001'

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...init,
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail ?? `HTTP ${res.status}`)
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
}
