import React, { useState, useEffect } from 'react';
import {
  Users, UserCheck, UserX, Shield, ShieldAlert, FolderPlus,
  RefreshCw, CheckCircle2, AlertCircle, Lock, Folder, Tag, Plus
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useRouter } from '../context/RouterContext';
import { apiRequest } from '../services/api';
import AccessDeniedPage from './AccessDeniedPage';

export default function UserManagementView() {
  const { user } = useAuth();
  const { navigate } = useRouter();

  // Users state
  const [users, setUsers] = useState([]);
  const [loadingUsers, setLoadingUsers] = useState(true);
  const [userActionLoading, setUserActionLoading] = useState(false);
  const [userError, setUserError] = useState(null);
  const [userSuccess, setUserSuccess] = useState(null);

  // Categories state
  const [categories, setCategories] = useState([]);
  const [newCatName, setNewCatName] = useState('');
  const [newCatDesc, setNewCatDesc] = useState('');
  const [creatingCat, setCreatingCat] = useState(false);
  const [catError, setCatError] = useState(null);
  const [catSuccess, setCatSuccess] = useState(null);

  useEffect(() => {
    if (user?.system_role === 'administrator') {
      loadUsers();
      loadCategories();
    }
  }, [user]);

  async function loadUsers() {
    setLoadingUsers(true);
    setUserError(null);
    try {
      const res = await apiRequest('/admin/users');
      setUsers(res.users || []);
    } catch (err) {
      console.error('Failed to load users:', err);
      setUserError(err.message || 'Failed to retrieve user accounts');
    } finally {
      setLoadingUsers(false);
    }
  }

  async function handleToggleStatus(targetUser) {
    const nextStatus = !targetUser.is_active;
    const actionLabel = nextStatus ? 'activate' : 'suspend';

    if (!window.confirm(`Are you sure you want to ${actionLabel} access for ${targetUser.email}?`)) {
      return;
    }

    setUserActionLoading(true);
    setUserError(null);
    setUserSuccess(null);

    try {
      const res = await apiRequest(`/admin/users/${targetUser.id}/status`, {
        method: 'PATCH',
        body: { is_active: nextStatus }
      });
      setUserSuccess(res.message || `Account for ${targetUser.email} updated to ${nextStatus ? 'Active' : 'Suspended'}`);
      await loadUsers();
    } catch (err) {
      setUserError(err.message || `Failed to ${actionLabel} user account`);
    } finally {
      setUserActionLoading(false);
    }
  }

  async function handleRoleChange(targetUser, newRole) {
    if (targetUser.system_role === newRole) return;

    if (!window.confirm(`Change system role for ${targetUser.email} from "${targetUser.system_role}" to "${newRole}"?`)) {
      return;
    }

    setUserActionLoading(true);
    setUserError(null);
    setUserSuccess(null);

    try {
      const res = await apiRequest(`/admin/users/${targetUser.id}/status`, {
        method: 'PATCH',
        body: { system_role: newRole }
      });
      setUserSuccess(res.message || `Updated ${targetUser.email} role to ${newRole}`);
      await loadUsers();
    } catch (err) {
      setUserError(err.message || 'Failed to update system role');
    } finally {
      setUserActionLoading(false);
    }
  }

  async function loadCategories() {
    try {
      const res = await apiRequest('/categories');
      setCategories(res.categories || []);
    } catch (err) {
      console.warn('Failed to load categories:', err);
    }
  }

  async function handleCreateCategory(e) {
    e.preventDefault();
    if (!newCatName.trim()) {
      setCatError('Category name cannot be empty.');
      return;
    }

    setCreatingCat(true);
    setCatError(null);
    setCatSuccess(null);

    try {
      const res = await apiRequest('/categories', {
        method: 'POST',
        body: {
          name: newCatName.trim(),
          description: newCatDesc.trim()
        }
      });
      setCatSuccess(res.message || `Created category "${newCatName.trim()}"`);
      setNewCatName('');
      setNewCatDesc('');
      await loadCategories();
    } catch (err) {
      setCatError(err.message || 'Failed to create category');
    } finally {
      setCreatingCat(false);
    }
  }

  // Non-admin guard
  if (user?.system_role !== 'administrator') {
    return (
      <AccessDeniedPage
        message="User governance and security role administration is restricted to authorized Security Administrators."
        requiredRole="Administrator (administrator)"
      />
    );
  }

  return (
    <div style={{ maxWidth: '1360px', margin: '0 auto', padding: '24px 20px', width: '100%' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '4px' }}>
            <h1 style={{ fontSize: '1.6rem', color: 'var(--navy-dark)' }}>User Management & Governance</h1>
            <span className="badge badge-rose">ADMIN ACCESS</span>
          </div>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            Enterprise identity directory, role assignment, account status, and category administration
          </p>
        </div>

        <button
          className="btn btn-secondary"
          onClick={loadUsers}
          disabled={loadingUsers}
        >
          <RefreshCw size={14} className={loadingUsers ? 'animate-spin' : ''} /> Refresh Directory
        </button>
      </div>

      {userError && (
        <div className="alert alert-danger" style={{ marginBottom: '16px' }}>
          <AlertCircle size={18} style={{ flexShrink: 0, marginTop: '2px' }} />
          <div>{userError}</div>
        </div>
      )}

      {userSuccess && (
        <div className="alert alert-success" style={{ marginBottom: '16px' }}>
          <CheckCircle2 size={18} style={{ flexShrink: 0, marginTop: '2px' }} />
          <div>{userSuccess}</div>
        </div>
      )}

      {/* Users Directory Table */}
      <div className="card" style={{ marginBottom: '28px', padding: 0, overflow: 'hidden' }}>
        <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ fontWeight: 700, fontSize: '0.95rem', color: 'var(--navy-dark)', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Users size={18} color="var(--blue-primary)" />
            <span>Enterprise Identities ({users.length})</span>
          </div>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Strict role boundaries: Administrators cannot deactivate their own active account.
          </span>
        </div>

        <div className="table-container" style={{ border: 'none', borderRadius: 0, boxShadow: 'none' }}>
          <table>
            <thead>
              <tr>
                <th>Identity</th>
                <th>System Role</th>
                <th>Account Status</th>
                <th>Joined Date</th>
                <th style={{ textAlign: 'right' }}>Security Actions</th>
              </tr>
            </thead>
            <tbody>
              {loadingUsers ? (
                <tr>
                  <td colSpan={5} style={{ textAlign: 'center', padding: '36px' }}>
                    <RefreshCw size={20} className="animate-spin" style={{ margin: '0 auto 8px', opacity: 0.6 }} />
                    <div>Loading enterprise user directory...</div>
                  </td>
                </tr>
              ) : (
                users.map((u) => {
                  const isCurrentAdmin = u.id === user?.id;

                  return (
                    <tr key={u.id}>
                      {/* Name & Email */}
                      <td>
                        <div style={{ fontWeight: 600, color: 'var(--navy-dark)', fontSize: '0.875rem' }}>
                          {u.full_name}
                          {isCurrentAdmin && (
                            <span style={{ marginLeft: '6px', fontSize: '0.7rem', color: 'var(--blue-text)' }}>
                              (You)
                            </span>
                          )}
                        </div>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                          {u.email}
                        </div>
                      </td>

                      {/* System Role Selector */}
                      <td>
                        <select
                          className="form-select"
                          style={{ width: 'auto', padding: '4px 8px', fontSize: '0.78rem' }}
                          value={u.system_role}
                          onChange={(e) => handleRoleChange(u, e.target.value)}
                          disabled={userActionLoading || isCurrentAdmin}
                        >
                          <option value="administrator">administrator (Security Admin)</option>
                          <option value="document_owner">document_owner (Owner & Uploads)</option>
                          <option value="viewer">viewer (Strict Read-Only)</option>
                        </select>
                      </td>

                      {/* Account Status Badge */}
                      <td>
                        {u.is_active ? (
                          <span className="badge badge-emerald">
                            <CheckCircle2 size={11} /> ACTIVE
                          </span>
                        ) : (
                          <span className="badge badge-rose">
                            <UserX size={11} /> SUSPENDED
                          </span>
                        )}
                      </td>

                      {/* Joined Date */}
                      <td style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                        {new Date(u.created_at).toLocaleDateString()}
                      </td>

                      {/* Toggle Status Action */}
                      <td style={{ textAlign: 'right' }}>
                        <button
                          id={`btn-toggle-user-${u.id}`}
                          className={u.is_active ? 'btn btn-danger' : 'btn btn-success'}
                          style={{ padding: '4px 10px', fontSize: '0.75rem' }}
                          onClick={() => handleToggleStatus(u)}
                          disabled={userActionLoading || isCurrentAdmin}
                          title={isCurrentAdmin ? 'Administrators cannot deactivate their own account' : ''}
                        >
                          {u.is_active ? (
                            <>
                              <UserX size={12} /> Suspend Account
                            </>
                          ) : (
                            <>
                              <UserCheck size={12} /> Activate Account
                            </>
                          )}
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Enterprise Categories Management Section */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '20px', alignItems: 'start' }}>
        {/* Categories List */}
        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <h2 style={{ fontSize: '1.05rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Folder size={18} color="var(--blue-primary)" />
              <span>Enterprise Classification Categories</span>
            </h2>
            <span className="badge badge-gray">{categories.length} Total</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {categories.map((cat) => (
              <div
                key={cat.id}
                style={{
                  padding: '12px 14px',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-md)',
                  background: 'var(--bg-subtle)'
                }}
              >
                <div style={{ fontWeight: 600, color: 'var(--navy-dark)', fontSize: '0.875rem' }}>
                  {cat.name}
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                  {cat.description || 'No description recorded.'}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Create Category Form */}
        <div className="card">
          <h2 style={{ fontSize: '1.05rem', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <FolderPlus size={18} color="var(--blue-primary)" />
            <span>Create New Document Category</span>
          </h2>

          <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '16px' }}>
            Define custom enterprise classification categories for organizing documents and enforcing retention rules.
          </p>

          {catError && (
            <div className="alert alert-danger" style={{ marginBottom: '14px' }}>
              <AlertCircle size={16} />
              <div>{catError}</div>
            </div>
          )}

          {catSuccess && (
            <div className="alert alert-success" style={{ marginBottom: '14px' }}>
              <CheckCircle2 size={16} />
              <div>{catSuccess}</div>
            </div>
          )}

          <form onSubmit={handleCreateCategory}>
            <div className="form-group">
              <label className="form-label">Category Name *</label>
              <input
                id="create-category-name"
                className="form-input"
                type="text"
                required
                placeholder="e.g. Legal & Compliance"
                value={newCatName}
                onChange={(e) => setNewCatName(e.target.value)}
              />
            </div>

            <div className="form-group">
              <label className="form-label">Description</label>
              <textarea
                id="create-category-desc"
                className="form-textarea"
                rows={3}
                placeholder="Category scope and access guidelines..."
                value={newCatDesc}
                onChange={(e) => setNewCatDesc(e.target.value)}
              />
            </div>

            <button
              id="btn-create-category-submit"
              type="submit"
              className="btn btn-primary"
              disabled={creatingCat || !newCatName.trim()}
              style={{ width: '100%', marginTop: '8px', padding: '10px' }}
            >
              {creatingCat ? 'Creating Category...' : 'Create Classification Category'}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
