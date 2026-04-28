import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { api } from '../lib/api'
import type { User } from '../types'

const ROLES = ['viewer', 'analyst', 'admin'] as const
type Role = typeof ROLES[number]

function roleBadgeClass(role: string) {
  if (role === 'admin')   return 'badge tp'
  if (role === 'analyst') return 'badge'
  return 'badge fp'
}

function RoleBadge({ role }: { role: string }) {
  return <span className={roleBadgeClass(role)} style={{ fontSize: 11 }}>{role}</span>
}

export function UsersPanel() {
  const [users,   setUsers]   = useState<User[]>([])
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState<string | null>(null)

  // create form
  const [showForm,    setShowForm]    = useState(false)
  const [newUsername, setNewUsername] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [newRole,     setNewRole]     = useState<Role>('analyst')
  const [creating,    setCreating]    = useState(false)
  const [formError,   setFormError]   = useState<string | null>(null)

  // inline edit state
  const [editingRole,     setEditingRole]     = useState<string | null>(null)
  const [editingPassword, setEditingPassword] = useState<string | null>(null)
  const [pendingRole,     setPendingRole]     = useState<Role>('analyst')
  const [pendingPassword, setPendingPassword] = useState('')
  const [saving,          setSaving]          = useState(false)

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    api.getUsers()
      .then(r => setUsers(r.users))
      .catch(e => setError(e.message ?? 'Failed to load users'))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => { load() }, [load])

  async function handleCreate(e: FormEvent) {
    e.preventDefault()
    setFormError(null)
    setCreating(true)
    try {
      await api.createUser({ username: newUsername, password: newPassword, role: newRole })
      setNewUsername(''); setNewPassword(''); setNewRole('analyst')
      setShowForm(false)
      load()
    } catch (err) {
      setFormError(err instanceof Error ? err.message : 'Failed to create user')
    } finally {
      setCreating(false)
    }
  }

  async function handleRoleSave(username: string) {
    setSaving(true)
    try {
      await api.updateUserRole(username, pendingRole)
      setEditingRole(null)
      load()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update role')
    } finally {
      setSaving(false)
    }
  }

  async function handlePasswordSave(username: string) {
    setSaving(true)
    try {
      await api.resetUserPassword(username, pendingPassword)
      setEditingPassword(null)
      setPendingPassword('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to reset password')
    } finally {
      setSaving(false)
    }
  }

  async function handleDelete(username: string) {
    if (!confirm(`Deactivate user "${username}"?`)) return
    try {
      await api.deleteUser(username)
      load()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to deactivate user')
    }
  }

  const inputStyle = {
    background: 'var(--surface-2)',
    border: '1px solid var(--border)',
    color: 'var(--text-1)',
    borderRadius: 6,
    padding: '5px 10px',
    fontSize: 12,
    fontFamily: 'var(--mono)',
    width: '100%',
  }

  const selectStyle = { ...inputStyle, width: 'auto', cursor: 'pointer' }

  return (
    <div>
      <div className="section-header">
        <div>
          <div className="section-title">User Management</div>
          <div className="section-sub">{users.length} accounts · admin only</div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn btn-ghost" onClick={load} disabled={loading}>↺ Refresh</button>
          <button
            className="btn"
            style={{ background: 'var(--cyan)', color: '#000', fontWeight: 700, padding: '6px 16px' }}
            onClick={() => { setShowForm(s => !s); setFormError(null) }}
          >
            {showForm ? '✕ Cancel' : '+ New User'}
          </button>
        </div>
      </div>

      {showForm && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div style={{ fontWeight: 600, fontSize: 12, color: 'var(--text-2)', marginBottom: 14, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
            Create User
          </div>
          <form onSubmit={handleCreate} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr auto auto', gap: 10, alignItems: 'end' }}>
            <div>
              <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Username</label>
              <input
                style={inputStyle}
                value={newUsername}
                onChange={e => setNewUsername(e.target.value)}
                placeholder="username"
                required
                minLength={2}
                pattern="[a-zA-Z0-9_\-]+"
                disabled={creating}
              />
            </div>
            <div>
              <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Password</label>
              <input
                style={inputStyle}
                type="password"
                value={newPassword}
                onChange={e => setNewPassword(e.target.value)}
                placeholder="min 8 characters"
                required
                minLength={8}
                disabled={creating}
              />
            </div>
            <div>
              <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Role</label>
              <select style={selectStyle} value={newRole} onChange={e => setNewRole(e.target.value as Role)} disabled={creating}>
                {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
              </select>
            </div>
            <button type="submit" className="btn" disabled={creating}
              style={{ background: 'var(--green)', color: '#000', fontWeight: 700, padding: '6px 18px', whiteSpace: 'nowrap' }}>
              {creating ? '…' : 'Create'}
            </button>
          </form>
          {formError && <p style={{ color: 'var(--red)', fontSize: 12, marginTop: 10, marginBottom: 0 }}>⚠ {formError}</p>}
        </div>
      )}

      {error && (
        <div className="empty-state" style={{ color: 'var(--red)', marginBottom: 8 }}>⚠ {error}</div>
      )}

      {loading ? (
        <div className="empty-state"><span className="log-info">Loading users…</span></div>
      ) : (
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Username</th>
                <th>Role</th>
                <th>Status</th>
                <th>Created</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map(u => (
                <tr key={u.id}>
                  <td style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--text-3)' }}>{u.id}</td>
                  <td style={{ fontFamily: 'var(--mono)', fontSize: 13, fontWeight: 600 }}>{u.username}</td>
                  <td>
                    {editingRole === u.username ? (
                      <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                        <select
                          style={{ ...selectStyle, padding: '3px 6px' }}
                          value={pendingRole}
                          onChange={e => setPendingRole(e.target.value as Role)}
                          disabled={saving}
                        >
                          {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
                        </select>
                        <button className="btn btn-ghost" style={{ padding: '3px 8px', fontSize: 11 }} disabled={saving} onClick={() => handleRoleSave(u.username)}>✓</button>
                        <button className="btn btn-ghost" style={{ padding: '3px 8px', fontSize: 11 }} onClick={() => setEditingRole(null)}>✕</button>
                      </div>
                    ) : (
                      <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                        <RoleBadge role={u.role} />
                        <button className="btn btn-ghost" style={{ padding: '2px 7px', fontSize: 10 }}
                          onClick={() => { setEditingRole(u.username); setPendingRole(u.role as Role); setEditingPassword(null) }}>
                          ✎
                        </button>
                      </div>
                    )}
                  </td>
                  <td>
                    <span style={{ fontFamily: 'var(--mono)', fontSize: 11, color: u.is_active ? 'var(--green)' : 'var(--text-3)' }}>
                      {u.is_active ? '● active' : '○ inactive'}
                    </span>
                  </td>
                  <td style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>
                    {new Date(u.created_at).toLocaleDateString()}
                  </td>
                  <td>
                    <div style={{ display: 'flex', gap: 6 }}>
                      {editingPassword === u.username ? (
                        <>
                          <input
                            type="password"
                            placeholder="new password"
                            style={{ ...inputStyle, width: 140 }}
                            value={pendingPassword}
                            onChange={e => setPendingPassword(e.target.value)}
                            disabled={saving}
                          />
                          <button className="btn btn-ghost" style={{ padding: '3px 8px', fontSize: 11 }}
                            disabled={saving || pendingPassword.length < 8}
                            onClick={() => handlePasswordSave(u.username)}>✓</button>
                          <button className="btn btn-ghost" style={{ padding: '3px 8px', fontSize: 11 }}
                            onClick={() => { setEditingPassword(null); setPendingPassword('') }}>✕</button>
                        </>
                      ) : (
                        <button className="btn btn-ghost" style={{ padding: '3px 10px', fontSize: 11 }}
                          onClick={() => { setEditingPassword(u.username); setPendingPassword(''); setEditingRole(null) }}>
                          ⚿ Password
                        </button>
                      )}
                      {u.is_active && (
                        <button
                          className="btn btn-ghost"
                          style={{ padding: '3px 10px', fontSize: 11, color: 'var(--red)' }}
                          onClick={() => handleDelete(u.username)}
                        >
                          ✕ Deactivate
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
