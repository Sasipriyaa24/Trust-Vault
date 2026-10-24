import React, { useState, useEffect } from 'react';
import { X, Users, UserPlus, Trash2, Key, AlertCircle, CheckCircle2, Shield } from 'lucide-react';
import { apiRequest } from '../services/api';

export default function PermissionModal({ isOpen, onClose, document }) {
  const [permissions, setPermissions] = useState([]);
  const [targetEmail, setTargetEmail] = useState('');
  const [permissionLevel, setPermissionLevel] = useState('read');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);

  useEffect(() => {
    if (isOpen && document) {
      loadPermissions();
      setTargetEmail('');
      setPermissionLevel('read');
      setError(null);
      setSuccess(null);
    }
  }, [isOpen, document]);

  async function loadPermissions() {
    if (!document) return;
    try {
      const res = await apiRequest(`/documents/${document.id}/permissions`);
      setPermissions(res.permissions || []);
    } catch (err) {
      console.warn('Failed to load permissions:', err);
    }
  }

  const handleGrant = async (e) => {
    e.preventDefault();
    if (!targetEmail.trim()) {
      setError('Target user email is required.');
      return;
    }

    setLoading(true);
    setError(null);
    setSuccess(null);

    try {
      const res = await apiRequest(`/documents/${document.id}/permissions`, {
        method: 'POST',
        body: {
          user_email: targetEmail.trim(),
          permission_level: permissionLevel
        }
      });
      setSuccess(res.message);
      setTargetEmail('');
      await loadPermissions();
    } catch (err) {
      setError(err.message || 'Failed to grant permission.');
    } finally {
      setLoading(false);
    }
  };

  const handleRevoke = async (userId, userEmail) => {
    setError(null);
    setSuccess(null);
    try {
      const res = await apiRequest(`/documents/${document.id}/permissions/${userId}`, {
        method: 'DELETE'
      });
      setSuccess(`Access immediately revoked for ${userEmail}.`);
      await loadPermissions();
    } catch (err) {
      setError(err.message || 'Failed to revoke access.');
    }
  };

  if (!isOpen || !document) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{ padding: '8px', background: 'rgba(99, 102, 241, 0.15)', borderRadius: '8px', color: 'var(--indigo-primary)' }}>
              <Users size={20} />
            </div>
            <div>
              <h2 style={{ fontSize: '1.25rem', color: 'var(--text-primary)' }}>Manage Document Access</h2>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                {document.title}
              </div>
            </div>
          </div>
          <button onClick={onClose} style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
            <X size={20} />
          </button>
        </div>

        {error && (
          <div style={{ padding: '10px 14px', background: 'rgba(244, 63, 94, 0.15)', border: '1px solid rgba(244, 63, 94, 0.4)', borderRadius: 'var(--radius-md)', color: '#FDA4AF', fontSize: '0.825rem', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <AlertCircle size={16} />
            <span>{error}</span>
          </div>
        )}

        {success && (
          <div style={{ padding: '10px 14px', background: 'rgba(16, 185, 129, 0.15)', border: '1px solid rgba(16, 185, 129, 0.4)', borderRadius: 'var(--radius-md)', color: '#6EE7B7', fontSize: '0.825rem', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <CheckCircle2 size={16} />
            <span>{success}</span>
          </div>
        )}

        {/* Existing Active Permissions List */}
        <div style={{ marginBottom: '24px' }}>
          <div style={{ fontSize: '0.825rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '8px', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
            Active Named Collaborators ({permissions.length})
          </div>

          {permissions.length === 0 ? (
            <div style={{ padding: '16px', background: 'rgba(11, 17, 32, 0.6)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-md)', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.825rem' }}>
              🔒 No external collaborators. This document is private to you.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {permissions.map((perm) => (
                <div
                  key={perm.id}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '10px 14px',
                    background: 'rgba(11, 17, 32, 0.6)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-md)'
                  }}
                >
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '0.85rem' }}>
                        {perm.user_name || 'Enterprise User'}
                      </span>
                      <span className={`badge ${perm.permission_level === 'edit' ? 'badge-cyan' : 'badge-indigo'}`} style={{ fontSize: '0.65rem' }}>
                        {perm.permission_level.toUpperCase()}
                      </span>
                    </div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      {perm.user_email} • Granted {new Date(perm.created_at).toLocaleDateString()}
                    </div>
                  </div>

                  <button
                    id={`btn-revoke-${perm.user_id}`}
                    className="btn btn-danger"
                    style={{ padding: '6px 10px', fontSize: '0.75rem' }}
                    onClick={() => handleRevoke(perm.user_id, perm.user_email)}
                    title="Revoke access immediately"
                  >
                    <Trash2 size={13} /> Revoke
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Grant New Permission Form */}
        <form onSubmit={handleGrant} style={{ paddingTop: '16px', borderTop: '1px solid var(--border-subtle)' }}>
          <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <UserPlus size={16} color="var(--cyan-light)" /> Grant Named Access
          </div>

          {/* Quick Demo Recipient Fill */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '12px', flexWrap: 'wrap' }}>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Quick Select:</span>
            <button
              type="button"
              className="demo-pill"
              onClick={() => setTargetEmail('alice@trustvault.internal')}
            >
              alice@trustvault.internal
            </button>
            <button
              type="button"
              className="demo-pill"
              onClick={() => setTargetEmail('viewer@trustvault.internal')}
            >
              viewer@trustvault.internal
            </button>
          </div>

          <div className="form-group">
            <label className="form-label" htmlFor="grant-email-input">User Email Address</label>
            <input
              id="grant-email-input"
              className="form-input"
              type="email"
              placeholder="e.g. viewer@trustvault.internal"
              value={targetEmail}
              onChange={(e) => setTargetEmail(e.target.value)}
              required
            />
          </div>

          <div className="form-group">
            <label className="form-label" htmlFor="grant-level-select">Permission Level</label>
            <select
              id="grant-level-select"
              className="form-select"
              value={permissionLevel}
              onChange={(e) => setPermissionLevel(e.target.value)}
            >
              <option value="read">Read Only (Can search, view metadata & download)</option>
              <option value="edit">Edit Permission (Can view, download & update metadata)</option>
            </select>
          </div>

          <div style={{ padding: '8px 12px', background: 'rgba(245, 158, 11, 0.08)', border: '1px solid rgba(245, 158, 11, 0.25)', borderRadius: 'var(--radius-md)', fontSize: '0.75rem', color: '#FCD34D', marginBottom: '18px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Shield size={14} />
            <span>Zero-Trust: Permissions are checked on live DB records on every request. Revocation takes effect instantly.</span>
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
            <button type="button" className="btn btn-secondary" onClick={onClose}>
              Close
            </button>
            <button id="btn-submit-grant" type="submit" className="btn btn-primary" disabled={loading}>
              {loading ? 'Granting...' : 'Grant Access'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
