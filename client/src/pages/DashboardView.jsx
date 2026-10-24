import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { useRouter } from '../context/RouterContext';
import { apiRequest, downloadDocumentStream } from '../services/api';
import {
  FileText, Upload, Shield, Users, ArrowRight, Download,
  Eye, CheckCircle2, AlertCircle, RefreshCw, Folder, Lock
} from 'lucide-react';

export default function DashboardView({ onNavigate }) {
  const { user } = useAuth();
  const { navigate: routerNavigate } = useRouter();
  const navigate = onNavigate || routerNavigate;
  const [documents, setDocuments] = useState([]);
  const [categories, setCategories] = useState([]);
  const [loading, setLoading] = useState(true);
  const [downloadingId, setDownloadingId] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    loadDashboardData();
  }, [user]);

  async function loadDashboardData() {
    setLoading(true);
    setError(null);
    try {
      const [docsRes, catsRes] = await Promise.all([
        apiRequest('/documents'),
        apiRequest('/categories').catch(() => ({ categories: [] }))
      ]);
      setDocuments(docsRes.documents || []);
      setCategories(catsRes.categories || []);
    } catch (err) {
      console.error('Failed to load dashboard data:', err);
      setError(err.message || 'Failed to load security dashboard data');
    } finally {
      setLoading(false);
    }
  }

  async function handleDownload(doc) {
    setDownloadingId(doc.id);
    try {
      await downloadDocumentStream(doc.id, doc.original_filename);
    } catch (err) {
      alert(`Download failed: ${err.message}`);
    } finally {
      setDownloadingId(null);
    }
  }

  const ownedCount = documents.filter(d => d.owner_id === user?.id).length;
  const sharedCount = documents.filter(d => d.owner_id !== user?.id).length;
  const recentDocs = documents.slice(0, 5);

  const canUpload = ['document_owner', 'administrator'].includes(user?.system_role);
  const isAdmin = user?.system_role === 'administrator';

  return (
    <div style={{ maxWidth: '1280px', margin: '0 auto', padding: '24px 20px', width: '100%' }}>
      {/* Welcome & Security Perimeter Header */}
      <div style={{ marginBottom: '24px', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '4px' }}>
            <h1 style={{ fontSize: '1.65rem' }}>Security Dashboard</h1>
            <span className={`badge ${isAdmin ? 'badge-rose' : canUpload ? 'badge-blue' : 'badge-gray'}`}>
              {user?.system_role}
            </span>
          </div>
          <p style={{ fontSize: '0.875rem' }}>
            Authenticated as <strong>{user?.full_name}</strong> ({user?.email}) • Zero-Trust Perimeter Enforced
          </p>
        </div>

        {/* Security Controls Status Pill */}
        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', padding: '6px 12px', background: 'var(--emerald-bg)', border: '1px solid var(--emerald-border)', borderRadius: 'var(--radius-md)', fontSize: '0.75rem', color: 'var(--emerald-success)', fontWeight: 600 }}>
            <CheckCircle2 size={14} /> Zero-Trust Access Check Active
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', padding: '6px 12px', background: 'var(--blue-subtle)', border: '1px solid var(--blue-border)', borderRadius: 'var(--radius-md)', fontSize: '0.75rem', color: 'var(--blue-text)', fontWeight: 600 }}>
            <Lock size={14} /> No Admin Blanket Bypass
          </div>
        </div>
      </div>

      {error && (
        <div className="alert alert-danger">
          <AlertCircle size={16} />
          <div>{error}</div>
        </div>
      )}

      {/* Metrics Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px', marginBottom: '24px' }}>
        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-muted)' }}>ACCESSIBLE DOCUMENTS</span>
            <Folder size={18} color="var(--blue-primary)" />
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: 700, color: 'var(--navy-dark)' }}>
            {loading ? '...' : documents.length}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            Documents authorized for this persona
          </div>
        </div>

        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-muted)' }}>OWNED DOCUMENTS</span>
            <FileText size={18} color="var(--emerald-success)" />
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: 700, color: 'var(--navy-dark)' }}>
            {loading ? '...' : ownedCount}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            Created & owned by you
          </div>
        </div>

        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-muted)' }}>SHARED ACCESS</span>
            <Users size={18} color="var(--blue-primary)" />
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: 700, color: 'var(--navy-dark)' }}>
            {loading ? '...' : sharedCount}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            Delegated via named permission grants
          </div>
        </div>

        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-muted)' }}>SYSTEM ROLE PRIVILEGES</span>
            <Shield size={18} color="var(--navy-dark)" />
          </div>
          <div style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--navy-dark)', textTransform: 'capitalize' }}>
            {user?.system_role?.replace('_', ' ')}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
            {isAdmin ? 'Surveillance & Governance' : canUpload ? 'Author & Delegate' : 'Read-Only Collaborator'}
          </div>
        </div>
      </div>

      {/* Relevant Quick Actions Bar */}
      <div className="card" style={{ marginBottom: '28px', background: 'var(--bg-subtle)' }}>
        <div style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--navy-dark)', marginBottom: '12px' }}>
          Relevant Quick Actions
        </div>
        <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
          {canUpload && (
            <button
              id="dash-btn-upload"
              className="btn btn-primary"
              onClick={() => navigate('/documents/upload')}
            >
              <Upload size={15} /> Upload Document
            </button>
          )}

          <button
            id="dash-btn-browse-docs"
            className="btn btn-secondary"
            onClick={() => navigate('/documents')}
          >
            <Folder size={15} /> Browse All Documents
          </button>

          {isAdmin && (
            <>
              <button
                id="dash-btn-audit"
                className="btn btn-secondary"
                onClick={() => navigate('/audit')}
              >
                <Shield size={15} /> Audit Activity Ledger
              </button>
              <button
                id="dash-btn-users"
                className="btn btn-secondary"
                onClick={() => navigate('/users')}
              >
                <Users size={15} /> User Governance
              </button>
            </>
          )}

          <button
            className="btn btn-secondary"
            onClick={loadDashboardData}
            style={{ marginLeft: 'auto' }}
          >
            <RefreshCw size={14} className={loading ? 'spinning' : ''} /> Refresh Data
          </button>
        </div>
      </div>

      {/* Recent Activity / Documents Section */}
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <div>
            <h2 style={{ fontSize: '1.15rem' }}>Recent Documents</h2>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              Authorized documents discoverable by your account
            </p>
          </div>
          <button
            className="btn btn-secondary"
            style={{ fontSize: '0.8rem', padding: '6px 12px' }}
            onClick={() => navigate('/documents')}
          >
            View All ({documents.length}) <ArrowRight size={14} />
          </button>
        </div>

        {loading ? (
          <div style={{ padding: '36px', textAlign: 'center', color: 'var(--text-muted)' }}>
            <RefreshCw size={20} className="spinning" style={{ margin: '0 auto 8px' }} />
            <div>Loading security-cleared documents...</div>
          </div>
        ) : recentDocs.length === 0 ? (
          <div className="empty-state">
            <FileText size={36} className="empty-state-icon" />
            <div className="empty-state-title">No accessible documents</div>
            <div className="empty-state-desc">
              {canUpload
                ? 'Upload a confidential document to your private vault to get started.'
                : 'No documents have been shared with your account yet.'}
            </div>
            {canUpload && (
              <button className="btn btn-primary" onClick={() => navigate('/documents/upload')}>
                <Upload size={14} /> Upload First Document
              </button>
            )}
          </div>
        ) : (
          <div className="table-container" style={{ border: 'none', boxShadow: 'none' }}>
            <table>
              <thead>
                <tr>
                  <th>Document Title</th>
                  <th>Category</th>
                  <th>Owner</th>
                  <th>Size</th>
                  <th>Uploaded Date</th>
                  <th>Access Rights</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {recentDocs.map((doc) => {
                  const isOwner = doc.owner_id === user?.id;
                  return (
                    <tr key={doc.id}>
                      <td style={{ fontWeight: 600, color: 'var(--navy-dark)' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <FileText size={16} color="var(--blue-primary)" />
                          <span>{doc.title}</span>
                        </div>
                      </td>
                      <td>
                        <span className="badge badge-gray">
                          {doc.category_name || 'Uncategorized'}
                        </span>
                      </td>
                      <td>
                        <div style={{ fontSize: '0.8rem' }}>{doc.owner_name || doc.owner_email || 'Owner'}</div>
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>
                        {(doc.file_size_bytes / 1024).toFixed(1)} KB
                      </td>
                      <td style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                        {new Date(doc.created_at).toLocaleDateString()}
                      </td>
                      <td>
                        <span className={`badge ${isOwner ? 'badge-emerald' : 'badge-blue'}`}>
                          {isOwner ? 'Owner' : 'Delegated'}
                        </span>
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: '6px' }}>
                          <button
                            className="btn btn-secondary"
                            style={{ padding: '4px 8px', fontSize: '0.75rem' }}
                            onClick={() => navigate(`/documents/${doc.id}`)}
                            title="View Document Details"
                          >
                            <Eye size={12} /> Details
                          </button>

                          <button
                            className="btn btn-secondary"
                            style={{ padding: '4px 8px', fontSize: '0.75rem' }}
                            onClick={() => handleDownload(doc)}
                            disabled={downloadingId === doc.id}
                            title="Download Secure Stream"
                          >
                            <Download size={12} />
                            {downloadingId === doc.id ? '...' : 'Download'}
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
