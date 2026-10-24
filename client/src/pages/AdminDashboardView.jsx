import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { apiRequest } from '../services/api';
import {
  ShieldAlert, ShieldCheck, CheckCircle2, AlertOctagon, RefreshCw,
  Search, Users, FolderPlus, Lock, Database, ArrowRight, Shield,
  Filter, Calendar, FileText, Eye, X, Copy, Check, RotateCcw
} from 'lucide-react';

export default function AdminDashboardView() {
  const { user } = useAuth();
  const [subTab, setSubTab] = useState('audit'); // 'audit', 'users', 'categories'

  // Audit state & Filters
  const [logs, setLogs] = useState([]);
  const [loadingLogs, setLoadingLogs] = useState(true);
  const [actionSearch, setActionSearch] = useState('');
  const [outcomeFilter, setOutcomeFilter] = useState('');
  const [actorFilter, setActorFilter] = useState('');
  const [documentFilter, setDocumentFilter] = useState('');
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');
  const [selectedLog, setSelectedLog] = useState(null);
  const [copiedId, setCopiedId] = useState(null);

  // Verification state
  const [verifying, setVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState(null);
  const [tampering, setTampering] = useState(false);

  // Users state
  const [users, setUsers] = useState([]);
  const [loadingUsers, setLoadingUsers] = useState(false);

  // Categories state
  const [categories, setCategories] = useState([]);
  const [newCatName, setNewCatName] = useState('');
  const [newCatDesc, setNewCatDesc] = useState('');
  const [creatingCat, setCreatingCat] = useState(false);

  useEffect(() => {
    if (user?.system_role === 'administrator') {
      loadAuditLogs();
      verifyChain();
    }
  }, [user]);

  async function loadAuditLogs() {
    setLoadingLogs(true);
    try {
      const params = new URLSearchParams();
      if (outcomeFilter) params.append('outcome', outcomeFilter);
      if (actionSearch) params.append('action', actionSearch);
      if (actorFilter) params.append('actor', actorFilter);
      if (documentFilter) params.append('document', documentFilter);
      if (dateFrom) params.append('dateFrom', dateFrom);
      if (dateTo) params.append('dateTo', dateTo);

      const res = await apiRequest(`/admin/audit-logs?${params.toString()}`);
      setLogs(res.logs || []);
    } catch (err) {
      console.error('Failed to load audit logs:', err);
    } finally {
      setLoadingLogs(false);
    }
  }

  function handleResetFilters() {
    setActionSearch('');
    setOutcomeFilter('');
    setActorFilter('');
    setDocumentFilter('');
    setDateFrom('');
    setDateTo('');
    setTimeout(() => {
      loadAuditLogsDirect();
    }, 50);
  }

  async function loadAuditLogsDirect() {
    setLoadingLogs(true);
    try {
      const res = await apiRequest('/admin/audit-logs');
      setLogs(res.logs || []);
    } catch (err) {
      console.error('Failed to load audit logs:', err);
    } finally {
      setLoadingLogs(false);
    }
  }

  function handleCopy(text, id) {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text);
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 2000);
    }
  }

  async function verifyChain() {
    setVerifying(true);
    try {
      const res = await apiRequest('/admin/audit-logs/verify');
      setVerificationResult(res);
    } catch (err) {
      setVerificationResult({
        isValid: false,
        message: err.message
      });
    } finally {
      setVerifying(false);
    }
  }

  async function handleSimulateTampering() {
    if (!window.confirm('Simulate database attack? This will modify an audit log entry in the database to test whether cryptographic HMAC verification catches fraud.')) {
      return;
    }
    setTampering(true);
    try {
      await apiRequest('/admin/audit-logs/simulate-tampering', {
        method: 'POST',
        body: { logId: 1 }
      });
      await loadAuditLogs();
      await verifyChain();
    } catch (err) {
      alert(`Simulation error: ${err.message}`);
    } finally {
      setTampering(false);
    }
  }

  async function loadUsers() {
    setLoadingUsers(true);
    try {
      const res = await apiRequest('/admin/users');
      setUsers(res.users || []);
    } catch (err) {
      console.error('Failed to load users:', err);
    } finally {
      setLoadingUsers(false);
    }
  }

  async function handleToggleUserStatus(userId, currentActive) {
    try {
      await apiRequest(`/admin/users/${userId}/status`, {
        method: 'PATCH',
        body: { is_active: !currentActive }
      });
      await loadUsers();
      await loadAuditLogs();
    } catch (err) {
      alert(`Failed to update user: ${err.message}`);
    }
  }

  async function loadCategories() {
    try {
      const res = await apiRequest('/categories');
      setCategories(res.categories || []);
    } catch (err) {
      console.error('Failed to load categories:', err);
    }
  }

  async function handleCreateCategory(e) {
    e.preventDefault();
    if (!newCatName.trim()) return;
    setCreatingCat(true);
    try {
      await apiRequest('/categories', {
        method: 'POST',
        body: { name: newCatName.trim(), description: newCatDesc.trim() }
      });
      setNewCatName('');
      setNewCatDesc('');
      await loadCategories();
      await loadAuditLogs();
    } catch (err) {
      alert(`Failed to create category: ${err.message}`);
    } finally {
      setCreatingCat(false);
    }
  }

  // Guard for non-admin
  if (user?.system_role !== 'administrator') {
    return (
      <div style={{ maxWidth: '800px', margin: '60px auto', padding: '32px 24px', textAlign: 'center' }}>
        <div className="glass-panel" style={{ padding: '40px 24px', border: '1px solid rgba(244, 63, 94, 0.3)' }}>
          <div style={{ width: '60px', height: '60px', borderRadius: '50%', background: 'rgba(244, 63, 94, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px', color: '#F43F5E' }}>
            <ShieldAlert size={32} />
          </div>
          <h2 style={{ fontSize: '1.4rem', color: '#FDA4AF', marginBottom: '8px' }}>
            Restricted Administrator Zone
          </h2>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem', maxWidth: '520px', margin: '0 auto 20px' }}>
            Your current persona ({user?.email || 'Guest'}, role: {user?.system_role || 'viewer'}) is not authorized to access security audit trails or admin controls.
          </p>
          <div style={{ display: 'inline-block', padding: '10px 16px', background: 'rgba(255, 255, 255, 0.04)', borderRadius: 'var(--radius-md)', fontSize: '0.825rem', color: 'var(--text-secondary)' }}>
            💡 Tip: Use the top <strong>Evaluation Persona Switcher</strong> ribbon to switch to <strong>👑 Administrator</strong>.
          </div>
        </div>
      </div>
    );
  }

  return (
    <div style={{ maxWidth: '1440px', margin: '0 auto', padding: '32px 24px', width: '100%' }}>
      {/* Admin Title */}
      <div style={{ marginBottom: '24px', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <h1 style={{ fontSize: '1.85rem', marginBottom: '6px', display: 'flex', alignItems: 'center', gap: '10px' }}>
            <ShieldAlert size={28} color="#FB7185" />
            <span>Admin Security & Audit Portal</span>
          </h1>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
            Append-only cryptographic ledger surveillance, distributed request correlation, and security governance.
          </p>
        </div>

        {/* Admin Isolation Reminder */}
        <div style={{ padding: '10px 16px', background: 'rgba(244, 63, 94, 0.08)', border: '1px solid rgba(244, 63, 94, 0.25)', borderRadius: 'var(--radius-md)', maxWidth: '460px', fontSize: '0.78rem', color: '#FDA4AF', display: 'flex', alignItems: 'center', gap: '10px' }}>
          <Lock size={18} style={{ flexShrink: 0 }} />
          <span>
            <strong>No Blanket Admin Bypass Enforced:</strong> Administrators cannot download or view private documents without explicit owner delegation.
          </span>
        </div>
      </div>

      {/* Cryptographic Hash Chain Verifier Banner */}
      <div
        className="glass-panel"
        style={{
          padding: '22px',
          marginBottom: '28px',
          border: verificationResult?.isValid
            ? '1px solid rgba(16, 185, 129, 0.4)'
            : '1px solid rgba(244, 63, 94, 0.5)',
          background: verificationResult?.isValid
            ? 'linear-gradient(135deg, rgba(16, 185, 129, 0.06), rgba(11, 17, 32, 0.8))'
            : 'linear-gradient(135deg, rgba(244, 63, 94, 0.12), rgba(11, 17, 32, 0.8))'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            <div
              style={{
                width: '44px',
                height: '44px',
                borderRadius: '12px',
                background: verificationResult?.isValid ? 'rgba(16, 185, 129, 0.15)' : 'rgba(244, 63, 94, 0.2)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: verificationResult?.isValid ? '#34D399' : '#F43F5E',
                boxShadow: verificationResult?.isValid ? '0 0 16px var(--emerald-glow)' : '0 0 16px var(--rose-glow)'
              }}
            >
              {verificationResult?.isValid ? <ShieldCheck size={26} /> : <AlertOctagon size={26} />}
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <h3 style={{ fontSize: '1.15rem', color: verificationResult?.isValid ? '#34D399' : '#FDA4AF' }}>
                  {verificationResult?.isValid ? 'Cryptographic Hash Chain: VERIFIED PRISTINE' : 'SECURITY ALERT: TAMPERING DETECTED'}
                </h3>
                <span className={`badge ${verificationResult?.isValid ? 'badge-emerald' : 'badge-rose'}`}>
                  {verificationResult?.isValid ? 'HMAC-SHA256 INTACT' : 'CHAIN COMPROMISED'}
                </span>
              </div>
              <div style={{ fontSize: '0.825rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
                {verificationResult?.message || 'Ready for cryptographic ledger verification.'}
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
            <button
              id="btn-verify-audit-chain"
              className="btn btn-success"
              onClick={verifyChain}
              disabled={verifying}
            >
              <RefreshCw size={14} className={verifying ? 'spinning' : ''} />
              {verifying ? 'Verifying Hashes...' : 'Re-verify Chain'}
            </button>

            {/* Test Tamper Hook */}
            <button
              id="btn-simulate-tampering"
              className="btn btn-danger"
              onClick={handleSimulateTampering}
              disabled={tampering}
              title="Test whether cryptographic hashing detects an unauthorized DB edit"
            >
              <AlertOctagon size={14} />
              {tampering ? 'Simulating...' : 'Test Tamper Detection'}
            </button>
          </div>
        </div>
      </div>

      {/* Admin Tabs */}
      <div style={{ display: 'flex', gap: '8px', borderBottom: '1px solid var(--border-subtle)', marginBottom: '24px' }}>
        <button
          id="admin-subtab-audit"
          className="btn"
          style={{
            borderBottom: subTab === 'audit' ? '2px solid var(--cyan-primary)' : '2px solid transparent',
            color: subTab === 'audit' ? 'var(--cyan-light)' : 'var(--text-muted)',
            borderRadius: '0',
            padding: '10px 18px'
          }}
          onClick={() => { setSubTab('audit'); loadAuditLogs(); }}
        >
          <Database size={16} /> Audit Trail ({logs.length})
        </button>
        <button
          id="admin-subtab-users"
          className="btn"
          style={{
            borderBottom: subTab === 'users' ? '2px solid var(--cyan-primary)' : '2px solid transparent',
            color: subTab === 'users' ? 'var(--cyan-light)' : 'var(--text-muted)',
            borderRadius: '0',
            padding: '10px 18px'
          }}
          onClick={() => { setSubTab('users'); loadUsers(); }}
        >
          <Users size={16} /> User Governance
        </button>
        <button
          id="admin-subtab-categories"
          className="btn"
          style={{
            borderBottom: subTab === 'categories' ? '2px solid var(--cyan-primary)' : '2px solid transparent',
            color: subTab === 'categories' ? 'var(--cyan-light)' : 'var(--text-muted)',
            borderRadius: '0',
            padding: '10px 18px'
          }}
          onClick={() => { setSubTab('categories'); loadCategories(); }}
        >
          <FolderPlus size={16} /> Categories
        </button>
      </div>

      {/* SUBTAB 1: AUDIT TRAIL EXPLORER */}
      {subTab === 'audit' && (
        <div>
          {/* Multi-Criteria Filter Bar */}
          <div className="glass-panel" style={{ padding: '18px 20px', marginBottom: '20px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
              <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Filter size={15} color="var(--cyan-light)" /> Activity Surveillance & Multi-Attribute Search
              </div>
              <button
                className="btn btn-secondary"
                style={{ padding: '4px 10px', fontSize: '0.75rem' }}
                onClick={handleResetFilters}
              >
                <RotateCcw size={12} /> Reset Filters
              </button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px' }}>
              {/* Actor Filter */}
              <div>
                <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>
                  Actor (Email or ID)
                </label>
                <input
                  id="filter-audit-actor"
                  className="form-input"
                  style={{ fontSize: '0.825rem', padding: '7px 10px' }}
                  placeholder="e.g. admin@, owner@, alice@..."
                  value={actorFilter}
                  onChange={(e) => setActorFilter(e.target.value)}
                />
              </div>

              {/* Action Filter */}
              <div>
                <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>
                  Action
                </label>
                <input
                  id="filter-audit-action"
                  className="form-input"
                  style={{ fontSize: '0.825rem', padding: '7px 10px' }}
                  placeholder="e.g. LOGIN, UPLOAD, DENIED..."
                  value={actionSearch}
                  onChange={(e) => setActionSearch(e.target.value)}
                />
              </div>

              {/* Outcome Filter */}
              <div>
                <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>
                  Outcome
                </label>
                <select
                  id="filter-audit-outcome"
                  className="form-select"
                  style={{ fontSize: '0.825rem', padding: '7px 10px' }}
                  value={outcomeFilter}
                  onChange={(e) => setOutcomeFilter(e.target.value)}
                >
                  <option value="">All Outcomes</option>
                  <option value="SUCCESS">SUCCESS (Allowed)</option>
                  <option value="DENIED">DENIED (Security Policy)</option>
                  <option value="ERROR">ERROR (System/Partial Failure)</option>
                </select>
              </div>

              {/* Document Target Filter */}
              <div>
                <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>
                  Target Document
                </label>
                <input
                  id="filter-audit-document"
                  className="form-input"
                  style={{ fontSize: '0.825rem', padding: '7px 10px' }}
                  placeholder="Doc title or UUID..."
                  value={documentFilter}
                  onChange={(e) => setDocumentFilter(e.target.value)}
                />
              </div>

              {/* Date From */}
              <div>
                <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>
                  Date From (UTC)
                </label>
                <input
                  id="filter-audit-date-from"
                  type="date"
                  className="form-input"
                  style={{ fontSize: '0.825rem', padding: '6px 10px' }}
                  value={dateFrom}
                  onChange={(e) => setDateFrom(e.target.value)}
                />
              </div>

              {/* Date To */}
              <div>
                <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>
                  Date To (UTC)
                </label>
                <input
                  id="filter-audit-date-to"
                  type="date"
                  className="form-input"
                  style={{ fontSize: '0.825rem', padding: '6px 10px' }}
                  value={dateTo}
                  onChange={(e) => setDateTo(e.target.value)}
                />
              </div>
            </div>

            <div style={{ marginTop: '14px', display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
              <button
                id="btn-apply-audit-filters"
                className="btn btn-primary"
                style={{ padding: '7px 16px', fontSize: '0.825rem' }}
                onClick={loadAuditLogs}
              >
                <Search size={14} /> Apply Filters
              </button>
            </div>
          </div>

          {/* Audit Logs Table */}
          <div className="glass-panel" style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.825rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-subtle)', background: 'rgba(255, 255, 255, 0.02)', color: 'var(--text-muted)', fontSize: '0.72rem', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  <th style={{ padding: '12px 14px' }}>ID / UTC Timestamp</th>
                  <th style={{ padding: '12px 14px' }}>Correlation ID</th>
                  <th style={{ padding: '12px 14px' }}>Actor</th>
                  <th style={{ padding: '12px 14px' }}>Action & Target</th>
                  <th style={{ padding: '12px 14px' }}>Outcome</th>
                  <th style={{ padding: '12px 14px' }}>Client IP</th>
                  <th style={{ padding: '12px 14px' }}>HMAC Fingerprint</th>
                  <th style={{ padding: '12px 14px' }}>Inspect</th>
                </tr>
              </thead>
              <tbody>
                {logs.length === 0 ? (
                  <tr>
                    <td colSpan={8} style={{ padding: '36px', textAlign: 'center', color: 'var(--text-muted)' }}>
                      No audit records found matching the specified surveillance criteria.
                    </td>
                  </tr>
                ) : (
                  logs.map((log) => {
                    const isDenied = log.status === 'DENIED';
                    const isError = log.status === 'ERROR';
                    const badgeClass = isDenied ? 'badge-rose' : isError ? 'badge-amber' : 'badge-emerald';

                    return (
                      <tr
                        key={log.id}
                        style={{
                          borderBottom: '1px solid var(--border-subtle)',
                          background: isDenied ? 'rgba(244, 63, 94, 0.04)' : isError ? 'rgba(245, 158, 11, 0.04)' : 'transparent',
                          transition: 'background 0.15s ease'
                        }}
                      >
                        {/* ID & Timestamp */}
                        <td style={{ padding: '12px 14px', whiteSpace: 'nowrap' }}>
                          <div style={{ fontWeight: 700, color: 'var(--text-primary)' }}>#{log.id}</div>
                          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }} title={new Date(log.timestamp).toISOString()}>
                            {new Date(log.timestamp).toUTCString().replace('GMT', 'UTC')}
                          </div>
                        </td>

                        {/* Correlation ID */}
                        <td style={{ padding: '12px 14px', whiteSpace: 'nowrap' }}>
                          {log.request_id ? (
                            <span
                              style={{
                                fontFamily: 'var(--font-mono)',
                                fontSize: '0.72rem',
                                color: 'var(--cyan-light)',
                                background: 'rgba(34, 211, 238, 0.08)',
                                padding: '2px 6px',
                                borderRadius: '4px',
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '4px',
                                cursor: 'pointer'
                              }}
                              onClick={() => handleCopy(log.request_id, `req-${log.id}`)}
                              title="Click to copy correlation request ID"
                            >
                              {log.request_id.length > 18 ? `${log.request_id.substring(0, 16)}...` : log.request_id}
                              {copiedId === `req-${log.id}` ? <Check size={11} color="#34D399" /> : <Copy size={11} />}
                            </span>
                          ) : (
                            <span style={{ color: 'var(--text-muted)', fontSize: '0.72rem' }}>—</span>
                          )}
                        </td>

                        {/* Actor */}
                        <td style={{ padding: '12px 14px' }}>
                          <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                            {log.user_email || 'ANONYMOUS'}
                          </div>
                          {log.user_id && (
                            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                              {log.user_id.substring(0, 10)}...
                            </div>
                          )}
                        </td>

                        {/* Action & Target */}
                        <td style={{ padding: '12px 14px' }}>
                          <div style={{ fontWeight: 600, color: isDenied ? '#FB7185' : isError ? '#FBBF24' : 'var(--text-primary)' }}>
                            {log.action}
                          </div>
                          {log.document_title && (
                            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                              Doc: {log.document_title}
                            </div>
                          )}
                          {log.details?.reason && (
                            <div style={{ fontSize: '0.7rem', color: '#FDA4AF', marginTop: '2px' }}>
                              ⚠️ {log.details.reason}
                            </div>
                          )}
                        </td>

                        {/* Outcome */}
                        <td style={{ padding: '12px 14px', whiteSpace: 'nowrap' }}>
                          <span className={`badge ${badgeClass}`}>
                            {log.status}
                          </span>
                        </td>

                        {/* Client IP */}
                        <td style={{ padding: '12px 14px', fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                          {log.ip_address}
                        </td>

                        {/* Cryptographic Hash */}
                        <td style={{ padding: '12px 14px', fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--text-muted)' }} title={log.current_hash}>
                          {log.current_hash ? `${log.current_hash.substring(0, 12)}...` : '—'}
                        </td>

                        {/* Inspect Action */}
                        <td style={{ padding: '12px 14px', whiteSpace: 'nowrap' }}>
                          <button
                            className="btn btn-secondary"
                            style={{ padding: '4px 8px', fontSize: '0.72rem' }}
                            onClick={() => setSelectedLog(log)}
                            title="Inspect full audit record & safe metadata"
                          >
                            <Eye size={12} /> View
                          </button>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          {/* Audit Record Inspection Modal */}
          {selectedLog && (
            <div
              style={{
                position: 'fixed',
                inset: 0,
                background: 'rgba(0, 0, 0, 0.75)',
                backdropFilter: 'blur(6px)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                zIndex: 1000,
                padding: '20px'
              }}
              onClick={() => setSelectedLog(null)}
            >
              <div
                className="glass-panel"
                style={{
                  width: '100%',
                  maxWidth: '720px',
                  maxHeight: '85vh',
                  overflowY: 'auto',
                  padding: '28px',
                  border: '1px solid var(--border-glow)'
                }}
                onClick={(e) => e.stopPropagation()}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '18px' }}>
                  <h3 style={{ fontSize: '1.2rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Shield size={20} color="var(--cyan-light)" />
                    <span>Audit Record Inspection #{selectedLog.id}</span>
                  </h3>
                  <button className="btn btn-secondary" style={{ padding: '4px 8px' }} onClick={() => setSelectedLog(null)}>
                    <X size={16} />
                  </button>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '14px', marginBottom: '18px' }}>
                  <div style={{ padding: '10px 14px', background: 'rgba(11, 17, 32, 0.6)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>UTC Timestamp</div>
                    <div style={{ fontSize: '0.85rem', fontWeight: 600 }}>{new Date(selectedLog.timestamp).toISOString()}</div>
                  </div>

                  <div style={{ padding: '10px 14px', background: 'rgba(11, 17, 32, 0.6)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Action & Outcome</div>
                    <div style={{ fontSize: '0.85rem', fontWeight: 600 }}>
                      {selectedLog.action} <span className={`badge ${selectedLog.status === 'DENIED' ? 'badge-rose' : 'badge-emerald'}`}>{selectedLog.status}</span>
                    </div>
                  </div>

                  <div style={{ padding: '10px 14px', background: 'rgba(11, 17, 32, 0.6)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Actor Identity</div>
                    <div style={{ fontSize: '0.85rem', fontWeight: 600 }}>{selectedLog.user_email || 'ANONYMOUS'}</div>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>UUID: {selectedLog.user_id || 'null'}</div>
                  </div>

                  <div style={{ padding: '10px 14px', background: 'rgba(11, 17, 32, 0.6)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Request / Correlation ID</div>
                    <div style={{ fontSize: '0.85rem', fontWeight: 600, fontFamily: 'var(--font-mono)', color: 'var(--cyan-light)' }}>
                      {selectedLog.request_id || 'NONE'}
                    </div>
                  </div>
                </div>

                {/* Cryptographic Linkage */}
                <div style={{ marginBottom: '18px', padding: '14px', background: 'rgba(11, 17, 32, 0.7)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
                  <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--cyan-light)', marginBottom: '8px' }}>
                    🔗 Cryptographic Hash Chain Pointers (HMAC-SHA256)
                  </div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: '4px' }}>
                    Previous Block Hash:
                  </div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', wordBreak: 'break-all', color: 'var(--text-secondary)', background: 'rgba(0,0,0,0.3)', padding: '6px 10px', borderRadius: '4px', marginBottom: '8px' }}>
                    {selectedLog.previous_hash}
                  </div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: '4px' }}>
                    Current Block Hash:
                  </div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', wordBreak: 'break-all', color: '#34D399', background: 'rgba(0,0,0,0.3)', padding: '6px 10px', borderRadius: '4px' }}>
                    {selectedLog.current_hash}
                  </div>
                </div>

                {/* Safe Sanitized Metadata */}
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                    <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
                      🛡️ Sanitized Event Metadata (Safe Details)
                    </div>
                    <span style={{ fontSize: '0.68rem', color: '#34D399' }}>
                      ✓ Zero Passwords, Tokens, or Raw Secrets
                    </span>
                  </div>
                  <pre
                    style={{
                      background: 'rgba(0, 0, 0, 0.5)',
                      padding: '12px',
                      borderRadius: 'var(--radius-sm)',
                      fontFamily: 'var(--font-mono)',
                      fontSize: '0.75rem',
                      color: 'var(--cyan-light)',
                      overflowX: 'auto',
                      border: '1px solid var(--border-subtle)'
                    }}
                  >
                    {JSON.stringify(selectedLog.details || {}, null, 2)}
                  </pre>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* SUBTAB 2: USER GOVERNANCE */}
      {subTab === 'users' && (
        <div className="glass-panel" style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-subtle)', background: 'rgba(255, 255, 255, 0.02)', color: 'var(--text-muted)', fontSize: '0.75rem', textTransform: 'uppercase' }}>
                <th style={{ padding: '12px 16px' }}>User</th>
                <th style={{ padding: '12px 16px' }}>Email</th>
                <th style={{ padding: '12px 16px' }}>System Role</th>
                <th style={{ padding: '12px 16px' }}>Account Status</th>
                <th style={{ padding: '12px 16px' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                  <td style={{ padding: '12px 16px', fontWeight: 600 }}>{u.full_name}</td>
                  <td style={{ padding: '12px 16px', color: 'var(--text-secondary)' }}>{u.email}</td>
                  <td style={{ padding: '12px 16px' }}>
                    <span className="badge badge-indigo">{u.system_role}</span>
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <span className={`badge ${u.is_active ? 'badge-emerald' : 'badge-rose'}`}>
                      {u.is_active ? 'ACTIVE' : 'SUSPENDED'}
                    </span>
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    {u.id !== user?.id && (
                      <button
                        className={`btn ${u.is_active ? 'btn-danger' : 'btn-success'}`}
                        style={{ padding: '4px 10px', fontSize: '0.75rem' }}
                        onClick={() => handleToggleUserStatus(u.id, u.is_active)}
                      >
                        {u.is_active ? 'Suspend Account' : 'Activate Account'}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* SUBTAB 3: CATEGORIES */}
      {subTab === 'categories' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '24px' }}>
          {/* Create category */}
          <div className="glass-panel" style={{ padding: '24px' }}>
            <h3 style={{ fontSize: '1.15rem', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <FolderPlus size={18} color="var(--cyan-light)" /> Add Enterprise Category
            </h3>
            <form onSubmit={handleCreateCategory}>
              <div className="form-group">
                <label className="form-label">Category Name *</label>
                <input
                  className="form-input"
                  type="text"
                  placeholder="e.g. Board of Directors Confidential"
                  value={newCatName}
                  onChange={(e) => setNewCatName(e.target.value)}
                  required
                />
              </div>
              <div className="form-group">
                <label className="form-label">Description</label>
                <textarea
                  className="form-textarea"
                  rows={2}
                  placeholder="Purpose of this document category..."
                  value={newCatDesc}
                  onChange={(e) => setNewCatDesc(e.target.value)}
                />
              </div>
              <button type="submit" className="btn btn-primary" disabled={creatingCat}>
                {creatingCat ? 'Creating...' : 'Create Category'}
              </button>
            </form>
          </div>

          {/* List categories */}
          <div className="glass-panel" style={{ padding: '24px' }}>
            <h3 style={{ fontSize: '1.15rem', marginBottom: '16px' }}>
              Existing Enterprise Categories ({categories.length})
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {categories.map((c) => (
                <div key={c.id} style={{ padding: '12px 14px', background: 'rgba(11, 17, 32, 0.5)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
                  <div style={{ fontWeight: 600, color: 'var(--cyan-light)' }}>{c.name}</div>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>{c.description}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
