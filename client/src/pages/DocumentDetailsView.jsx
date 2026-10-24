import React, { useState, useEffect } from 'react';
import {
  FileText, Download, Edit3, Trash2, Users, ArrowLeft,
  ShieldCheck, Lock, Clock, HardDrive, Check, Copy, AlertCircle,
  Tag, Folder, Calendar, Shield
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useRouter } from '../context/RouterContext';
import { apiRequest, downloadDocumentStream } from '../services/api';
import EditMetadataModal from '../components/EditMetadataModal';
import AccessDeniedPage from './AccessDeniedPage';

export default function DocumentDetailsView({ documentId }) {
  const { user } = useAuth();
  const { navigate } = useRouter();

  const [doc, setDoc] = useState(null);
  const [loading, setLoading] = useState(true);
  const [downloading, setDownloading] = useState(false);
  const [error, setError] = useState(null);
  const [isAccessDenied, setIsAccessDenied] = useState(false);
  const [isNotFound, setIsNotFound] = useState(false);
  const [copiedHash, setCopiedHash] = useState(false);
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);

  useEffect(() => {
    if (documentId) {
      loadDocumentDetails();
    }
  }, [documentId, user]);

  async function loadDocumentDetails() {
    setLoading(true);
    setError(null);
    setIsAccessDenied(false);
    setIsNotFound(false);

    try {
      const res = await apiRequest(`/documents/${documentId}`);
      setDoc(res.document);
    } catch (err) {
      if (err.status === 403 || err.code === 'ACCESS_DENIED') {
        setIsAccessDenied(true);
      } else if (err.status === 404 || err.code === 'NOT_FOUND') {
        setIsNotFound(true);
      } else {
        setError(err.message || 'Failed to retrieve document metadata');
      }
    } finally {
      setLoading(false);
    }
  }

  async function handleDownload() {
    if (!doc) return;
    setDownloading(true);
    try {
      await downloadDocumentStream(doc.id, doc.original_filename);
    } catch (err) {
      alert(`Download failed: ${err.message}`);
    } finally {
      setDownloading(false);
    }
  }

  async function handleDelete() {
    if (!doc) return;
    if (!window.confirm(`Security Confirmation: Are you sure you want to permanently delete "${doc.title}"? This action will be recorded in the audit trail.`)) {
      return;
    }

    try {
      await apiRequest(`/documents/${doc.id}`, { method: 'DELETE' });
      navigate('/documents');
    } catch (err) {
      alert(`Failed to delete document: ${err.message}`);
    }
  }

  function handleCopyHash() {
    if (doc?.file_hash_sha256 && navigator.clipboard) {
      navigator.clipboard.writeText(doc.file_hash_sha256);
      setCopiedHash(true);
      setTimeout(() => setCopiedHash(false), 2000);
    }
  }

  function formatBytes(bytes) {
    if (!bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  function formatDate(isoString) {
    if (!isoString) return 'N/A';
    return new Date(isoString).toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      timeZoneName: 'short'
    });
  }

  if (loading) {
    return (
      <div style={{ maxWidth: '960px', margin: '40px auto', padding: '0 20px', textAlign: 'center' }}>
        <div style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
          Verifying object-level permissions and loading metadata...
        </div>
      </div>
    );
  }

  if (isAccessDenied) {
    return (
      <AccessDeniedPage
        message="You do not have permission to view this document. The document owner has not delegated read access to your identity."
        requiredRole="Document Owner or Explicit Delegated Permission"
      />
    );
  }

  if (isNotFound || !doc) {
    return (
      <div style={{ maxWidth: '600px', margin: '60px auto', padding: '0 20px', textAlign: 'center' }}>
        <div className="card" style={{ padding: '36px 20px' }}>
          <AlertCircle size={32} color="var(--rose-danger)" style={{ margin: '0 auto 12px' }} />
          <h2 style={{ fontSize: '1.25rem', marginBottom: '8px' }}>Document Not Found</h2>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', marginBottom: '20px' }}>
            The requested document ID does not exist or has been deleted.
          </p>
          <button className="btn btn-secondary" onClick={() => navigate('/documents')}>
            <ArrowLeft size={15} /> Return to Documents
          </button>
        </div>
      </div>
    );
  }

  const isOwner = doc.owner_id === user?.id || doc.user_access_level === 'owner';
  const canEdit = isOwner || doc.user_access_level === 'edit';

  return (
    <div style={{ maxWidth: '1000px', margin: '0 auto', padding: '24px 20px', width: '100%' }}>
      {/* Back button & Breadcrumb */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <button
            className="btn btn-secondary"
            onClick={() => navigate('/documents')}
            style={{ padding: '6px 10px' }}
            title="Back to Documents"
          >
            <ArrowLeft size={16} />
          </button>
          <div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Documents / Details
            </div>
            <h1 style={{ fontSize: '1.45rem', color: 'var(--navy-dark)', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span>{doc.title}</span>
            </h1>
          </div>
        </div>

        {/* User's Access Level Badge */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          {isOwner ? (
            <span className="badge badge-emerald">👑 OWNER (FULL CONTROL)</span>
          ) : doc.user_access_level === 'edit' ? (
            <span className="badge badge-blue">✏️ EDIT PRIVILEGES</span>
          ) : (
            <span className="badge badge-gray">👁️ READ-ONLY ACCESS</span>
          )}
        </div>
      </div>

      {error && (
        <div className="alert alert-danger" style={{ marginBottom: '20px' }}>
          <AlertCircle size={16} />
          <div>{error}</div>
        </div>
      )}

      {/* Main Metadata Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '20px', marginBottom: '24px' }}>
        {/* Left Column: Core File & Security Metadata */}
        <div className="card">
          <h2 style={{ fontSize: '1.05rem', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <FileText size={18} color="var(--blue-primary)" />
            <span>Document Specification</span>
          </h2>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', fontSize: '0.825rem' }}>
            <div>
              <div style={{ color: 'var(--text-muted)', marginBottom: '2px' }}>Description / Confidential Memo:</div>
              <div style={{ color: 'var(--text-primary)', background: 'var(--bg-subtle)', padding: '10px 12px', borderRadius: 'var(--radius-md)', minHeight: '48px' }}>
                {doc.description || 'No description provided.'}
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px' }}>
              <span style={{ color: 'var(--text-muted)' }}>Original Filename:</span>
              <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--navy-dark)' }}>
                {doc.original_filename}
              </span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px' }}>
              <span style={{ color: 'var(--text-muted)' }}>MIME Type:</span>
              <span style={{ fontFamily: 'var(--font-mono)' }}>{doc.mime_type}</span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px' }}>
              <span style={{ color: 'var(--text-muted)' }}>File Size:</span>
              <span style={{ fontWeight: 600 }}>{formatBytes(doc.file_size_bytes)}</span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px' }}>
              <span style={{ color: 'var(--text-muted)' }}>Category:</span>
              <span className="badge badge-gray">{doc.category_name || 'Uncategorized'}</span>
            </div>

            <div>
              <span style={{ color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>Classification Tags:</span>
              <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                {Array.isArray(doc.tags) && doc.tags.length > 0 ? (
                  doc.tags.map((tag, idx) => (
                    <span key={idx} className="badge badge-blue">
                      #{tag}
                    </span>
                  ))
                ) : (
                  <span style={{ color: 'var(--text-muted)', fontStyle: 'italic', fontSize: '0.78rem' }}>None</span>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Cryptographic Fingerprint & Ownership */}
        <div className="card">
          <h2 style={{ fontSize: '1.05rem', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <ShieldCheck size={18} color="var(--emerald-success)" />
            <span>Cryptographic Proof & Provenance</span>
          </h2>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', fontSize: '0.825rem' }}>
            {/* SHA-256 Checksum */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                <span style={{ color: 'var(--text-muted)' }}>SHA-256 Checksum:</span>
                <button
                  className="btn btn-secondary"
                  onClick={handleCopyHash}
                  style={{ padding: '2px 8px', fontSize: '0.7rem' }}
                >
                  {copiedHash ? <Check size={12} color="var(--emerald-success)" /> : <Copy size={12} />}
                  {copiedHash ? 'Copied' : 'Copy Hash'}
                </button>
              </div>
              <div
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.75rem',
                  background: 'var(--bg-subtle)',
                  padding: '8px 10px',
                  borderRadius: 'var(--radius-md)',
                  wordBreak: 'break-all',
                  color: 'var(--navy-dark)',
                  border: '1px solid var(--border-subtle)'
                }}
              >
                {doc.file_hash_sha256}
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px' }}>
              <span style={{ color: 'var(--text-muted)' }}>Document ID (UUID):</span>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}>{doc.id}</span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px' }}>
              <span style={{ color: 'var(--text-muted)' }}>Document Owner:</span>
              <span style={{ fontWeight: 600 }}>{doc.owner_name} ({doc.owner_email})</span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '8px' }}>
              <span style={{ color: 'var(--text-muted)' }}>Ingested At:</span>
              <span>{formatDate(doc.created_at)}</span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>Last Metadata Update:</span>
              <span>{formatDate(doc.updated_at)}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Action Toolbar */}
      <div className="card" style={{ marginBottom: '24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <div style={{ fontWeight: 600, fontSize: '0.9rem', color: 'var(--navy-dark)' }}>
            Permitted Cryptographic Actions
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Rendered based on verified server capabilities for this identity.
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          {/* Download Action (Always permitted if user passed read check) */}
          <button
            id="btn-details-download"
            className="btn btn-primary"
            onClick={handleDownload}
            disabled={downloading}
          >
            <Download size={15} />
            {downloading ? 'Streaming...' : 'Download Document'}
          </button>

          {/* Edit Metadata (Owner or Edit permission) */}
          {canEdit && (
            <button
              id="btn-details-edit"
              className="btn btn-secondary"
              onClick={() => setIsEditModalOpen(true)}
            >
              <Edit3 size={15} /> Edit Metadata
            </button>
          )}

          {/* Manage Permissions (Owner only) */}
          {isOwner && (
            <button
              id="btn-details-permissions"
              className="btn btn-navy"
              onClick={() => navigate(`/documents/${doc.id}/permissions`)}
            >
              <Users size={15} /> Sharing & Permissions
            </button>
          )}

          {/* Delete Action (Owner only) */}
          {isOwner && (
            <button
              id="btn-details-delete"
              className="btn btn-danger"
              onClick={handleDelete}
            >
              <Trash2 size={15} /> Delete Document
            </button>
          )}
        </div>
      </div>

      {/* Security Architecture Deep Dive */}
      <div style={{ padding: '16px 20px', background: 'var(--bg-subtle)', borderRadius: 'var(--radius-lg)', border: '1px solid var(--border-subtle)', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
        <div style={{ fontWeight: 600, color: 'var(--navy-dark)', display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '6px' }}>
          <Lock size={14} color="var(--blue-primary)" />
          <span>Zero-Trust Architecture Guardrails in Effect:</span>
        </div>
        <ul style={{ paddingLeft: '20px', lineHeight: '1.6', color: 'var(--text-muted)' }}>
          <li>Downloads are streamed strictly through an authenticated Express proxy. Raw storage URLs are never exposed.</li>
          <li>Viewing this metadata was authenticated, checked against ACLs, and appended to the append-only cryptographic audit ledger.</li>
          <li>Even if a client bypasses UI controls, the Express server verifies object-level authorization on every request.</li>
        </ul>
      </div>

      {/* Edit Metadata Modal */}
      <EditMetadataModal
        isOpen={isEditModalOpen}
        document={doc}
        onClose={() => setIsEditModalOpen(false)}
        onUpdateSuccess={loadDocumentDetails}
      />
    </div>
  );
}
