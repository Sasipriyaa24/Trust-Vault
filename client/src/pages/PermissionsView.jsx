import React, { useState, useEffect } from 'react';
import {
  Users, UserPlus, Trash2, Key, ArrowLeft, Shield,
  CheckCircle2, AlertCircle, Lock, ShieldCheck, Mail, Edit3, Eye
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useRouter } from '../context/RouterContext';
import { apiRequest } from '../services/api';
import AccessDeniedPage from './AccessDeniedPage';

export default function PermissionsView({ documentId }) {
  const { user } = useAuth();
  const { navigate } = useRouter();

  const [documentTitle, setDocumentTitle] = useState('');
  const [permissions, setPermissions] = useState([]);
  const [targetEmail, setTargetEmail] = useState('');
  const [permissionLevel, setPermissionLevel] = useState('read');

  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);
  const [isAccessDenied, setIsAccessDenied] = useState(false);
  const [docMetadata, setDocMetadata] = useState(null);

  const demoQuickUsers = [
    { email: 'alice@trustvault.internal', name: 'Alice Cooper', role: 'Collaborator' },
    { email: 'viewer@trustvault.internal', name: 'External Auditor', role: 'Viewer' },
    { email: 'admin@trustvault.internal', name: 'Security Administrator', role: 'Admin' }
  ];

  useEffect(() => {
    if (documentId) {
      loadPermissionsData();
    }
  }, [documentId, user]);

  async function loadPermissionsData() {
    setLoading(true);
    setError(null);
    setIsAccessDenied(false);

    try {
      // First load document details to verify ownership and title
      const docRes = await apiRequest(`/documents/${documentId}`).catch((err) => {
        if (err.status === 403) setIsAccessDenied(true);
        throw err;
      });
      setDocMetadata(docRes.document);
      setDocumentTitle(docRes.document.title);

      // Next load permissions
      const res = await apiRequest(`/documents/${documentId}/permissions`);
      setPermissions(res.permissions || []);
    } catch (err) {
      if (err.status === 403 || err.code === 'ACCESS_DENIED') {
        setIsAccessDenied(true);
      } else {
        setError(err.message || 'Failed to load document permissions');
      }
    } finally {
      setLoading(false);
    }
  }

  async function handleGrant(e) {
    e.preventDefault();
    if (!targetEmail.trim()) {
      setError('Target user email is required.');
      return;
    }

    setActionLoading(true);
    setError(null);
    setSuccess(null);

    try {
      const res = await apiRequest(`/documents/${documentId}/permissions`, {
        method: 'POST',
        body: {
          user_email: targetEmail.trim(),
          permission_level: permissionLevel
        }
      });
      setSuccess(res.message || `Granted ${permissionLevel} access to ${targetEmail.trim()}`);
      setTargetEmail('');
      await loadPermissionsData();
    } catch (err) {
      setError(err.message || 'Failed to grant permission');
    } finally {
      setActionLoading(false);
    }
  }

  async function handleRevoke(targetUserId, targetEmail) {
    if (!window.confirm(`Revoke all access for ${targetEmail}? This takes effect immediately.`)) {
      return;
    }

    setActionLoading(true);
    setError(null);
    setSuccess(null);

    try {
      const res = await apiRequest(`/documents/${documentId}/permissions/${targetUserId}`, {
        method: 'DELETE'
      });
      setSuccess(res.message || `Revoked access for ${targetEmail}`);
      await loadPermissionsData();
    } catch (err) {
      setError(err.message || 'Failed to revoke permission');
    } finally {
      setActionLoading(false);
    }
  }

  if (loading) {
    return (
      <div style={{ maxWidth: '960px', margin: '40px auto', padding: '0 20px', textAlign: 'center' }}>
        <div style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
          Verifying authorization and loading access control lists...
        </div>
      </div>
    );
  }

  if (isAccessDenied) {
    return (
      <AccessDeniedPage
        message="Only the document owner (or a compliance administrator in inspection mode) may view or modify document permissions. You are not the owner of this document."
        requiredRole="Document Owner"
      />
    );
  }

  const isOwner = docMetadata?.owner_id === user?.id || docMetadata?.user_access_level === 'owner';

  return (
    <div style={{ maxWidth: '1000px', margin: '0 auto', padding: '24px 20px', width: '100%' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <button
            className="btn btn-secondary"
            onClick={() => navigate(`/documents/${documentId}`)}
            style={{ padding: '6px 10px' }}
            title="Back to Document Details"
          >
            <ArrowLeft size={16} />
          </button>
          <div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Documents / Access Control
            </div>
            <h1 style={{ fontSize: '1.45rem', color: 'var(--navy-dark)' }}>
              Sharing & Permissions
            </h1>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span className="badge badge-emerald">
            <Key size={12} /> OWNER PERMISSION CONTROLS
          </span>
        </div>
      </div>

      {/* Target Document Info Card */}
      <div className="card" style={{ marginBottom: '20px', background: 'var(--bg-subtle)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              Target Confidential Resource
            </div>
            <div style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--navy-dark)' }}>
              {documentTitle || 'Document'}
            </div>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '2px' }}>
              UUID: <code>{documentId}</code> • Owned by <strong>{docMetadata?.owner_name}</strong>
            </div>
          </div>

          <button
            className="btn btn-secondary"
            onClick={() => navigate(`/documents/${documentId}`)}
            style={{ fontSize: '0.8rem' }}
          >
            View Full Metadata Card
          </button>
        </div>
      </div>

      {/* Alerts */}
      {error && (
        <div className="alert alert-danger" style={{ marginBottom: '16px' }}>
          <AlertCircle size={18} style={{ flexShrink: 0, marginTop: '2px' }} />
          <div>{error}</div>
        </div>
      )}

      {success && (
        <div className="alert alert-success" style={{ marginBottom: '16px' }}>
          <CheckCircle2 size={18} style={{ flexShrink: 0, marginTop: '2px' }} />
          <div>{success}</div>
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: '20px', alignItems: 'start' }}>
        {/* Left: Active Grants List */}
        <div className="card" style={{ gridColumn: 'span 1' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <h2 style={{ fontSize: '1.05rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Users size={18} color="var(--blue-primary)" />
              <span>Active Delegated Grants</span>
            </h2>
            <span className="badge badge-gray">{permissions.length} Granted</span>
          </div>

          {permissions.length === 0 ? (
            <div style={{ padding: '32px 16px', textAlign: 'center', color: 'var(--text-muted)', background: 'var(--bg-subtle)', borderRadius: 'var(--radius-md)' }}>
              <Lock size={24} style={{ margin: '0 auto 8px', opacity: 0.6 }} />
              <div style={{ fontWeight: 600, fontSize: '0.875rem' }}>No External Grants</div>
              <div style={{ fontSize: '0.75rem', marginTop: '4px' }}>
                Only you (the document owner) can access this document.
              </div>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {permissions.map((grant) => (
                <div
                  key={grant.id || grant.user_id}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '12px 14px',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-md)',
                    background: 'var(--bg-surface)'
                  }}
                >
                  <div style={{ minWidth: 0, flex: 1, marginRight: '12px' }}>
                    <div style={{ fontWeight: 600, color: 'var(--navy-dark)', fontSize: '0.85rem' }}>
                      {grant.full_name || 'Named User'}
                    </div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                      {grant.email}
                    </div>
                    <div style={{ marginTop: '4px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                      {grant.permission_level === 'edit' ? (
                        <span className="badge badge-blue">
                          <Edit3 size={11} /> CAN EDIT
                        </span>
                      ) : (
                        <span className="badge badge-gray">
                          <Eye size={11} /> READ ONLY
                        </span>
                      )}
                      <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                        Granted {new Date(grant.created_at).toLocaleDateString()}
                      </span>
                    </div>
                  </div>

                  {isOwner && (
                    <button
                      id={`btn-revoke-${grant.user_id}`}
                      className="btn btn-danger"
                      onClick={() => handleRevoke(grant.user_id, grant.email)}
                      disabled={actionLoading}
                      style={{ padding: '6px 10px', fontSize: '0.75rem' }}
                      title="Revoke access immediately"
                    >
                      <Trash2 size={14} /> Revoke
                    </button>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right: Grant Form */}
        <div className="card" style={{ gridColumn: 'span 1' }}>
          <h2 style={{ fontSize: '1.05rem', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <UserPlus size={18} color="var(--blue-primary)" />
            <span>Delegate Access to Named User</span>
          </h2>

          <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '16px' }}>
            Authorize a registered enterprise user to read or edit this document. Access takes effect instantly.
          </p>

          <form onSubmit={handleGrant}>
            <div className="form-group">
              <label className="form-label" htmlFor="grant-user-email">User Email Address *</label>
              <input
                id="grant-user-email"
                className="form-input"
                type="email"
                required
                placeholder="colleague@trustvault.internal"
                value={targetEmail}
                onChange={(e) => setTargetEmail(e.target.value)}
              />
            </div>

            {/* Quick Demo Pickers */}
            <div style={{ marginBottom: '14px' }}>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: '6px' }}>
                Quick Fill Demo Users:
              </div>
              <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                {demoQuickUsers.map((u) => (
                  <button
                    key={u.email}
                    type="button"
                    className="btn btn-secondary"
                    style={{ fontSize: '0.7rem', padding: '3px 8px' }}
                    onClick={() => setTargetEmail(u.email)}
                  >
                    {u.name} ({u.role})
                  </button>
                ))}
              </div>
            </div>

            <div className="form-group">
              <label className="form-label" htmlFor="grant-permission-level">Permission Level *</label>
              <select
                id="grant-permission-level"
                className="form-select"
                value={permissionLevel}
                onChange={(e) => setPermissionLevel(e.target.value)}
              >
                <option value="read">Read Only (Inspect metadata & download document)</option>
                <option value="edit">Can Edit (Modify metadata, title, categories & tags)</option>
              </select>
              <div className="form-hint" style={{ marginTop: '4px' }}>
                ⚠️ <strong>Security Rule:</strong> Edit permission does NOT allow deleting, re-sharing, or modifying permissions.
              </div>
            </div>

            <button
              id="btn-grant-permission-submit"
              type="submit"
              className="btn btn-primary"
              disabled={actionLoading || !targetEmail.trim() || !isOwner}
              style={{ width: '100%', marginTop: '8px', padding: '10px' }}
            >
              {actionLoading ? 'Granting Access...' : 'Grant Permission'}
            </button>
          </form>

          {/* Policy Information */}
          <div style={{ marginTop: '20px', padding: '12px', background: 'var(--bg-subtle)', borderRadius: 'var(--radius-md)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            <div style={{ fontWeight: 600, color: 'var(--navy-dark)', marginBottom: '4px' }}>
              Enterprise Permission Guardrails:
            </div>
            <ul style={{ paddingLeft: '16px', lineHeight: '1.5' }}>
              <li>Users cannot grant permissions on documents they do not own.</li>
              <li>Deactivated or suspended accounts are automatically rejected.</li>
              <li>Every grant and revocation is immutably logged with the actor's identity.</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}
