import { useState } from 'react'
import { StatusBar } from './components/StatusBar'
import { Dashboard } from './components/Dashboard'
import { SkillsPanel } from './components/SkillsPanel'
import { MemoryPanel } from './components/MemoryPanel'
import { SimulationRunner } from './components/SimulationRunner'
import { KillChainTimeline } from './components/KillChainTimeline'
import { PlaybooksPanel } from './components/PlaybooksPanel'
import type { TabId } from './types'

const TABS: { id: TabId; label: string }[] = [
  { id: 'dashboard',  label: '◈ Dashboard' },
  { id: 'simulation', label: '▶ Simulation' },
  { id: 'incidents',  label: '⬡ Incidents' },
  { id: 'playbooks',  label: '⚙ Playbooks' },
  { id: 'skills',     label: '◎ Skills' },
  { id: 'memory',     label: '⊞ Memory' },
]

export default function App() {
  const [tab, setTab] = useState<TabId>('dashboard')

  return (
    <div className="layout">
      <StatusBar />
      <nav className="nav-tabs">
        {TABS.map(t => (
          <button
            key={t.id}
            className={`nav-tab ${tab === t.id ? 'active' : ''}`}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </nav>
      <main className="main-content">
        {tab === 'dashboard'  && <Dashboard />}
        {tab === 'simulation' && <SimulationRunner />}
        {tab === 'incidents'  && <KillChainTimeline />}
        {tab === 'playbooks'  && <PlaybooksPanel />}
        {tab === 'skills'     && <SkillsPanel />}
        {tab === 'memory'     && <MemoryPanel />}
      </main>
    </div>
  )
}
