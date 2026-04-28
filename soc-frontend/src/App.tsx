import { useState, useEffect } from 'react'
import { StatusBar } from './components/StatusBar'
import { Dashboard } from './components/Dashboard'
import { SkillsPanel } from './components/SkillsPanel'
import { MemoryPanel } from './components/MemoryPanel'
import { SimulationRunner } from './components/SimulationRunner'
import { KillChainTimeline } from './components/KillChainTimeline'
import { PlaybooksPanel } from './components/PlaybooksPanel'
import { AuditPanel } from './components/AuditPanel'
import { UsersPanel } from './components/UsersPanel'
import { PluginsPanel } from './components/PluginsPanel'
import { DlqPanel } from './components/DlqPanel'
import { ConnectorsPanel } from './components/ConnectorsPanel'
import { LoginPage } from './components/LoginPage'
import { AuthProvider, useAuth, AUTH_ENABLED } from './contexts/AuthContext'
import { setUnauthorizedHandler } from './lib/api'
import type { TabId } from './types'

const TABS: { id: TabId; label: string }[] = [
  { id: 'dashboard',  label: '◈ Dashboard' },
  { id: 'simulation', label: '▶ Simulation' },
  { id: 'incidents',  label: '⬡ Incidents' },
  { id: 'playbooks',  label: '⚙ Playbooks' },
  { id: 'skills',     label: '◎ Skills' },
  { id: 'memory',     label: '⊞ Memory' },
  { id: 'plugins',    label: '⬡ Plugins' },
  { id: 'connectors', label: '⇄ Connectors' },
  { id: 'dlq',        label: '☒ DLQ' },
  { id: 'audit',      label: '⊛ Audit' },
  { id: 'users',      label: '◉ Users' },
]

function useTheme() {
  const [theme, setTheme] = useState<'dark' | 'light'>(
    () => (localStorage.getItem('nexussoc:theme') as 'dark' | 'light') ?? 'dark'
  )
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme === 'light' ? 'light' : '')
    localStorage.setItem('nexussoc:theme', theme)
  }, [theme])
  const toggle = () => setTheme(t => t === 'dark' ? 'light' : 'dark')
  return { theme, toggle }
}

function AppShell() {
  const [tab, setTab] = useState<TabId>('dashboard')
  const { user, isLoading, logout } = useAuth()
  const { theme, toggle: toggleTheme } = useTheme()

  // Wire 401 handler — any expired API call forces logout
  useEffect(() => {
    setUnauthorizedHandler(logout)
  }, [logout])

  if (isLoading) {
    return (
      <div className="login-page">
        <div className="login-card">
          <p style={{ color: 'var(--text-muted)' }}>Loading…</p>
        </div>
      </div>
    )
  }

  if (AUTH_ENABLED && !user) {
    return <LoginPage />
  }

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
        <button
          className="nav-tab"
          onClick={toggleTheme}
          title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
          style={{ marginLeft: 'auto', opacity: 0.7 }}
        >
          {theme === 'dark' ? '☀' : '🌙'}
        </button>
        {AUTH_ENABLED && user && (
          <button
            className="nav-tab nav-tab-logout"
            onClick={logout}
            title={`${user.username} · ${user.role}`}
          >
            ⏻ {user.username}
          </button>
        )}
      </nav>
      <main className="main-content">
        {tab === 'dashboard'  && <Dashboard />}
        {tab === 'simulation' && <SimulationRunner />}
        {tab === 'incidents'  && <KillChainTimeline />}
        {tab === 'playbooks'  && <PlaybooksPanel />}
        {tab === 'skills'     && <SkillsPanel />}
        {tab === 'memory'     && <MemoryPanel />}
        {tab === 'plugins'     && <PluginsPanel />}
        {tab === 'connectors'  && <ConnectorsPanel />}
        {tab === 'dlq'         && <DlqPanel />}
        {tab === 'audit'       && <AuditPanel />}
        {tab === 'users'       && <UsersPanel />}
      </main>
    </div>
  )
}

export default function App() {
  return (
    <AuthProvider>
      <AppShell />
    </AuthProvider>
  )
}
