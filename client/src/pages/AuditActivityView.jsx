import React, { useState, useEffect } from 'react';
import {
  ShieldAlert, ShieldCheck, CheckCircle2, AlertOctagon, RefreshCw,
  Search, Filter, Calendar, FileText, Eye, X, Copy, Check, Lock,
  AlertCircle, ArrowRight
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useRouter } from '../context/RouterContext';
import { apiRequest } from '../services/api';
import AccessDeniedPage from './AccessDeniedPage';

export default function AuditActivityView() {
  const { user } = useAuth();
  const { navigate } = useRouter();

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
      apiRequest('/admin/audit-logs')
        .then(res => setLogs(res.logs || []))
        .catch(() => {});
    }, 50);
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
    if (!window.confirm('Simulate database attack? This will modify an audit log entry in the database to test whether cryptographic HMAC-SHA256 verification catches unauthorized manipulation.')) {
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

  function handleCopy(text, id) {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text);
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 2000);
    }
  }

  // Guard: Fail closed for non-administrators
  if (user?.system_role !== 'administrator') {
    return (
      <AccessDeniedPage
        message="Audit trail ledger and cryptographic verification portals are restricted to Security Administrators. Your current role is not authorized."
        requiredRole="Administrator (administrator)"
      />
    );
  }

  return (
    <div style={{ maxWidth: '1440px', margin: '0 auto', padding: '24px 20px', width: '100%' }}>
      {/* Header */}
      <div style={{ marginBottom: '24px', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '4px' }}>
            <h1 style={{ fontSize: '1.6rem', color: 'var(--navy-dark)' }}>Audit Activity</h1>
            <span className="badge badge-rose">ADMINISTRATOR SURVEILLANCE</span>
          </div>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            Cryptographically sealed HMAC-SHA256 audit ledger with request correlation and anti-tamper proofs
          </p>
        </div>

        {/* Isolation reminder */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '8px 14px', background: 'var(--blue-subtle)', border: '1px solid var(--blue-border)', borderRadius: 'var(--radius-md)', fontSize: '0.78rem', color: 'var(--blue-text)' }}>
          <Lock size={15} />
          <span><strong>Zero-Trust Guard:</strong> Administrators cannot download private document files without explicit owner delegation.</span>
        </div>
      </div>

      {/* Cryptographic Hash Chain Verifier Banner */}
      <div
        className="card"
        style={{
          borderLeft: verificationResult?.isValid ? '4px solid var(--emerald-success)' : '4px solid var(--rose-danger)',
          marginBottom: '20px',
          background: verificationResult?.isValid ? 'var(--emerald-bg)' : 'var(--rose-bg)'
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            <div
              style={{
                width: '42px',
                height: '42px',
                borderRadius: '50%',
                background: 'var(--bg-surface)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: verificationResult?.isValid ? 'var(--emerald-success)' : 'var(--rose-danger)',
                border: '1px solid var(--border-subtle)'
              }}
            >
              {verificationResult?.isValid ? <ShieldCheck size={24} /> : <AlertOctagon size={24} />}
            </div>

            <div>
              <div style={{ fontWeight: 700, fontSize: '0.95rem', color: 'var(--navy-dark)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span>HMAC-SHA256 Cryptographic Hash Chain:</span>
                <span className={`badge ${verificationResult?.isValid ? 'badge-emerald' : 'badge-rose'}`}>
                  {verifying ? 'VERIFYING...' : verificationResult?.isValid ? 'INTEGRITY VERIFIED' : 'COMPROMISED / TAMPER DETECTED'}
                </span>
              </div>
              <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
                {verificationResult?.isValid
                  ? `All ${verificationResult.checkedCount || logs.length} audit records mathematically verified against cryptographic chain signatures.`
                  : `Chain verification failed! Log ID ${verificationResult?.compromisedAtId || 'unknown'} hash signature does not match.`}
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
            <button
              id="btn-verify-audit-chain"
              className="btn btn-secondary"
              onClick={verifyChain}
              disabled={verifying}
              style={{ fontSize: '0.78rem', padding: '6px 12px' }}
            >
              <RefreshCw size={13} className={verifying ? 'animate-spin' : ''} />
              Re-verify Chain
            </button>

            <button
              id="btn-simulate-tamper-attack"
              className="btn btn-danger"
              onClick={handleSimulateTampering}
              disabled={tampering}
              style={{ fontSize: '0.78rem', padding: '6px 12px' }}
              title="Test whether cryptographic verification catches direct database tampering"
            >
              <AlertOctagon size={13} />
              {tampering ? 'Tampering...' : 'Simulate Tamper Attack'}
            </button>
          </div>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="card" style={{ marginBottom: '20px', padding: '16px' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px', alignItems: 'center' }}>
          <div>
            <label className="form-label" style={{ fontSize: '0.75rem', marginBottom: '4px' }}>Action Name</label>
            <input
              id="audit-filter-action"
              className="form-input"
              type="text"
              placeholder="e.g. UPLOAD, DENIED, LOGIN"
              value={actionSearch}
              onChange={(e) => setActionSearch(e.target.value)}
            />
          </div>

          <div>
            <label className="form-label" style={{ fontSize: '0.75rem', marginBottom: '4px' }}>Outcome</label>
            <select
              id="audit-filter-outcome"
              className="form-select"
              value={outcomeFilter}
              onChange={(e) => setOutcomeFilter(e.target.value)}
            >
              <option value="">All Outcomes</option>
              <option value="SUCCESS">SUCCESS (Allowed)</option>
              <option value="DENIED">DENIED (Blocked / Unauthorized)</option>
              <option value="ERROR">ERROR (Failure)</option>
            </select>
          </div>

          <div>
            <label className="form-label" style={{ fontSize: '0.75rem', marginBottom: '4px' }}>Actor (Email or ID)</label>
            <input
              id="audit-filter-actor"
              className="form-input"
              type="text"
              placeholder="e.g. owner@trustvault.internal"
              value={actorFilter}
              onChange={(e) => setActorFilter(e.target.value)}
            />
          </div>

          <div>
            <label className="form-label" style={{ fontSize: '0.75rem', marginBottom: '4px' }}>Date From</label>
            <input
              id="audit-filter-date-from"
              type="date"
              className="form-input"
              value={dateFrom}
              onChange={(e) => setDateFrom(e.target.value)}
            />
          </div>

          <div>
            <label className="form-label" style={{ fontSize: '0.75rem', marginBottom: '4px' }}>Date To</label>
            <input
              id="audit-filter-date-to"
              type="date"
              className="form-input"
              value={dateTo}
              onChange={(e) => setDateTo(e.target.value)}
            />
          </div>
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '12px', paddingTop: '10px', borderTop: '1px solid var(--border-subtle)' }}>
          <button
            className="btn btn-secondary"
            onClick={handleResetFilters}
            style={{ fontSize: '0.78rem', padding: '6px 12px' }}
          >
            Reset Filters
          </button>
          <button
            id="btn-apply-audit-filters"
            className="btn btn-primary"
            onClick={loadAuditLogs}
            style={{ fontSize: '0.78rem', padding: '6px 14px' }}
          >
            Apply Filters
          </button>
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>Timestamp (UTC)</th>
              <th>Outcome</th>
              <th>Action</th>
              <th>Actor</th>
              <th>Target Document</th>
              <th>Correlation ID</th>
              <th style={{ textAlign: 'right' }}>Inspection</th>
            </tr>
          </thead>
          <tbody>
            {loadingLogs ? (
              <tr>
                <td colSpan={7} style={{ textAlign: 'center', padding: '36px' }}>
                  <RefreshCw size={20} className="animate-spin" style={{ margin: '0 auto 8px', opacity: 0.6 }} />
                  <div>Querying append-only cryptographic ledger...</div>
                </td>
              </tr>
            ) : logs.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ textAlign: 'center', padding: '36px', color: 'var(--text-muted)' }}>
                  No audit log entries found matching filters.
                </td>
              </tr>
            ) : (
              logs.map((log) => {
                const isDenied = log.status === 'DENIED';
                const isSuccess = log.status === 'SUCCESS';

                return (
                  <tr key={log.id} style={{ background: isDenied ? 'rgba(254, 242, 242, 0.4)' : undefined }}>
                    {/* Timestamp */}
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                      {new Date(log.created_at).toISOString().replace('T', ' ').substring(0, 19)}
                    </td>

                    {/* Outcome Badge */}
                    <td>
                      {isSuccess ? (
                        <span className="badge badge-emerald">
                          <CheckCircle2 size={11} /> SUCCESS
                        </span>
                      ) : isDenied ? (
                        <span className="badge badge-rose">
                          <ShieldAlert size={11} /> DENIED
                        </span>
                      ) : (
                        <span className="badge badge-amber">ERROR</span>
                      )}
                    </td>

                    {/* Action */}
                    <td>
                      <code style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--navy-dark)' }}>
                        {log.action}
                      </code>
                    </td>

                    {/* Actor */}
                    <td>
                      <div style={{ fontSize: '0.8rem', fontWeight: 500, color: 'var(--navy-dark)' }}>
                        {log.user_email || 'Anonymous / Guest'}
                      </div>
                      {log.user_id && (
                        <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                          {log.user_id.substring(0, 8)}...
                        </div>
                      )}
                    </td>

                    {/* Target Document */}
                    <td>
                      {log.document_title ? (
                        <div>
                          <div style={{ fontSize: '0.8rem', fontWeight: 500 }}>{log.document_title}</div>
                          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                            {log.document_id?.substring(0, 8)}...
                          </div>
                        </div>
                      ) : log.document_id ? (
                        <code style={{ fontSize: '0.72rem' }}>{log.document_id.substring(0, 12)}...</code>
                      ) : (
                        <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>—</span>
                      )}
                    </td>

                    {/* Correlation ID */}
                    <td>
                      {log.request_id ? (
                        <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                          <code style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>
                            {log.request_id.substring(0, 14)}...
                          </code>
                          <button
                            className="btn btn-secondary"
                            onClick={() => handleCopy(log.request_id, log.id)}
                            style={{ padding: '2px 4px', fontSize: '0.65rem' }}
                            title="Copy full correlation ID"
                          >
                            {copiedId === log.id ? <Check size={10} color="var(--emerald-success)" /> : <Copy size={10} />}
                          </button>
                        </div>
                      ) : (
                        <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>—</span>
                      )}
                    </td>

                    {/* Inspection Button */}
                    <td style={{ textAlign: 'right' }}>
                      <button
                        className="btn btn-secondary"
                        style={{ padding: '4px 8px', fontSize: '0.72rem' }}
                        onClick={() => setSelectedLog(log)}
                      >
                        <Eye size={12} /> Inspect
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Audit Detail Inspector Modal */}
      {selectedLog && (
        <div className="modal-overlay" onClick={() => setSelectedLog(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '720px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <div>
                <h3 style={{ fontSize: '1.15rem', color: 'var(--navy-dark)' }}>Audit Event Inspector</h3>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                  Record #{selectedLog.id} • {selectedLog.action}
                </div>
              </div>
              <button
                className="btn btn-secondary"
                style={{ padding: '4px 8px' }}
                onClick={() => setSelectedLog(null)}
              >
                <X size={16} />
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', fontSize: '0.825rem' }}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '10px', background: 'var(--bg-subtle)', padding: '12px', borderRadius: 'var(--radius-md)' }}>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Status / Outcome:</span>{' '}
                  <span className={`badge ${selectedLog.status === 'SUCCESS' ? 'badge-emerald' : 'badge-rose'}`}>
                    {selectedLog.status}
                  </span>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>UTC Timestamp:</span>{' '}
                  <span style={{ fontFamily: 'var(--font-mono)' }}>{selectedLog.created_at}</span>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Client IP:</span>{' '}
                  <span style={{ fontFamily: 'var(--font-mono)' }}>{selectedLog.ip_address || '127.0.0.1'}</span>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Request Correlation ID:</span>{' '}
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem' }}>{selectedLog.request_id || 'N/A'}</span>
                </div>
              </div>

              <div>
                <div style={{ fontWeight: 600, color: 'var(--navy-dark)', marginBottom: '4px' }}>Safe Sanitized Details (No Raw Secrets):</div>
                <pre
                  style={{
                    background: 'var(--bg-subtle)',
                    padding: '12px',
                    borderRadius: 'var(--radius-md)',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '0.75rem',
                    overflowX: 'auto',
                    border: '1px solid var(--border-subtle)',
                    maxHeight: '200px'
                  }}
                >
                  {JSON.stringify(selectedLog.details, null, 2)}
                </pre>
              </div>

              <div>
                <div style={{ fontWeight: 600, color: 'var(--navy-dark)', marginBottom: '4px' }}>Cryptographic Proofs:</div>
                <div style={{ background: 'var(--bg-subtle)', padding: '10px', borderRadius: 'var(--radius-md)', fontSize: '0.72rem', fontFamily: 'var(--font-mono)' }}>
                  <div><strong>Prev Hash:</strong> {selectedLog.prev_hash || 'GENESIS'}</div>
                  <div style={{ marginTop: '4px' }}><strong>Record Signature:</strong> {selectedLog.entry_hash || 'HMAC-SHA256'}</div>
                </div>
              </div>
            </div>

            <div style={{ marginTop: '20px', display: 'flex', justifyContent: 'flex-end' }}>
              <button className="btn btn-secondary" onClick={() => setSelectedLog(null)}>
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
