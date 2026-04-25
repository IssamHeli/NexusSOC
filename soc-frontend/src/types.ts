export interface HealthStatus {
  status: string
  database: string
  ollama_model: string
  embed_model: string
  skills_learned: number
  memories_indexed: number
  playbook_mode: string
}

export interface AnalysisResult {
  decision: 'True Positive' | 'False Positive'
  confidence: number
  explanation: string
  recommended_action: string
}

export interface IncidentSummary {
  incident_id:       string
  action:            'created' | 'updated'
  case_count:        number
  kill_chain_phases: string[]
  severity:          string
}

export interface AnalyzeResponse {
  status:             string
  case_id:            string
  memory_context:     number
  skills_applied:     number
  playbooks_executed: number
  incident:           IncidentSummary | null
  result:             AnalysisResult
}

export interface Incident {
  incident_id:       string
  title:             string
  status:            'open' | 'investigating' | 'closed'
  severity:          'low' | 'medium' | 'high' | 'critical'
  case_count:        number
  kill_chain_phases: string[]
  attack_types:      string[]
  source_ips:        string[]
  hostnames:         string[]
  users:             string[]
  mitre_techniques:  string[]
  created_at:        string
  updated_at:        string
}

export interface Skill {
  id: number
  skill_name: string
  pattern: string
  decision: string
  confidence_score: number
  usage_count: number
  success_count: number
  mitre_techniques: string[] | null
  created_at: string
  updated_at: string
}

export interface Memory {
  case_id: string
  ai_decision: string
  confidence: number
  analysis_summary: string
  recommended_action: string
  timestamp: string
  has_embedding: boolean
}

export interface PlaybookAction {
  type: 'log' | 'discord' | 'webhook'
  message?: string
  url?: string
  method?: string
  payload?: Record<string, unknown>
}

export interface Playbook {
  id: number
  name: string
  description: string | null
  trigger_decision: string
  trigger_min_confidence: number
  trigger_attack_types: string[] | null
  actions: PlaybookAction[]
  enabled: boolean
  execution_count: number
  created_at: string
}

export interface ActionOutcome {
  type: string
  status: string
  detail: string
}

export interface PlaybookExecution {
  id: number
  executed_at: string
  case_id: string
  playbook_name: string
  actions_taken: ActionOutcome[]
}

export type TabId = 'dashboard' | 'skills' | 'memory' | 'simulation' | 'incidents' | 'playbooks'
