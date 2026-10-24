import React, { useState } from 'react';
import { FileText, Download, Users, Edit3, Trash2, ShieldCheck, Clock, HardDrive, Key } from 'lucide-react';
import { downloadDocumentStream } from '../services/api';

export default function DocumentCard({ doc, currentUserId, onOpenPermissions, onOpenEdit, onDelete }) {
  const [downloading, setDownloading] = useState(false);
  const [downloadError, setDownloadError] = useState(null);

  const isOwner = doc.owner_id === currentUserId || doc.user_access_level === 'owner';
  const canEdit = isOwner || doc.user_access_level === 'edit';

  const formatFileSize = (bytes) => {
    if (!bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric'
    });
  };

  const handleDownload = async () => {
    setDownloading(true);
    setDownloadError(null);
    try {
      await downloadDocumentStream(doc.id, doc.original_filename);
    } catch (err) {
      setDownloadError(err.message);
      setTimeout(() => setDownloadError(null), 4000);
    } finally {
      setDownloading(false);
    }
  };

  const getAccessBadge = () => {
    if (isOwner) {
      return <span className="badge badge-emerald"><Key size={11} /> OWNER</span>;
    }
    if (doc.user_access_level === 'edit') {
      return <span className="badge badge-cyan"><Edit3 size={11} /> CAN EDIT</span>;
    }
    return <span className="badge badge-indigo">👁️ READ ONLY</span>;
  };

  return (
    <div className="glass-panel glass-panel-glow" style={{ padding: '22px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between', gap: '16px', position: 'relative' }}>
      <div>
        {/* Header Tags & Badges */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px', gap: '8px', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
            <span className="badge badge-indigo" style={{ fontSize: '0.7rem' }}>
              {doc.category_name || 'General Enterprise'}
            </span>
            {Array.isArray(doc.tags) && doc.tags.map((t, idx) => (
              <span key={idx} className="badge" style={{ fontSize: '0.65rem', background: 'rgba(255, 255, 255, 0.06)', color: 'var(--text-secondary)', border: '1px solid rgba(255, 255, 255, 0.1)' }}>
                #{t}
              </span>
            ))}
          </div>
          {getAccessBadge()}
        </div>

        {/* Title & Description */}
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px' }}>
          <div style={{ padding: '10px', background: 'rgba(6, 182, 212, 0.1)', borderRadius: '10px', border: '1px solid rgba(6, 182, 212, 0.25)', color: 'var(--cyan-light)', marginTop: '2px' }}>
            <FileText size={24} />
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <h3 style={{ fontSize: '1.05rem', wordBreak: 'break-word', color: 'var(--text-primary)', marginBottom: '4px' }}>
              {doc.title}
            </h3>
            <p style={{ fontSize: '0.825rem', color: 'var(--text-muted)', lineHeight: '1.4', display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}>
              {doc.description || 'No confidential memo provided.'}
            </p>
          </div>
        </div>

        {/* Metadata info */}
        <div style={{ marginTop: '16px', paddingTop: '14px', borderTop: '1px solid var(--border-subtle)', display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '10px', fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <HardDrive size={13} color="var(--text-muted)" />
            <span>{formatFileSize(doc.file_size_bytes)}</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Clock size={13} color="var(--text-muted)" />
            <span>{formatDate(doc.created_at)}</span>
          </div>
          <div style={{ gridColumn: 'span 2', display: 'flex', alignItems: 'center', gap: '6px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            <span style={{ color: 'var(--text-muted)' }}>Owner:</span>
            <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{doc.owner_name}</span>
            <span style={{ color: 'var(--text-muted)', fontSize: '0.72rem' }}>({doc.owner_email})</span>
          </div>
          <div style={{ gridColumn: 'span 2', display: 'flex', alignItems: 'center', gap: '6px', fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--text-muted)' }}>
            <ShieldCheck size={12} color="var(--emerald-success)" />
            <span>SHA-256: {doc.file_hash_sha256?.substring(0, 16)}...</span>
          </div>
        </div>
      </div>

      {/* Download error alert */}
      {downloadError && (
        <div style={{ padding: '8px 12px', background: 'rgba(244, 63, 94, 0.15)', border: '1px solid rgba(244, 63, 94, 0.4)', borderRadius: 'var(--radius-sm)', color: '#FDA4AF', fontSize: '0.75rem' }}>
          ⚠️ {downloadError}
        </div>
      )}

      {/* Action Toolbar */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', paddingTop: '10px', borderTop: '1px solid var(--border-subtle)' }}>
        <button
          id={`btn-download-${doc.id}`}
          className="btn btn-primary"
          style={{ flex: 1, padding: '8px 12px', fontSize: '0.825rem' }}
          onClick={handleDownload}
          disabled={downloading}
        >
          <Download size={14} />
          {downloading ? 'Streaming...' : 'Secure Download'}
        </button>

        {/* Manage Permissions (Owner Only) */}
        {isOwner && (
          <button
            id={`btn-permissions-${doc.id}`}
            className="btn btn-secondary"
            style={{ padding: '8px 10px' }}
            onClick={() => onOpenPermissions(doc)}
            title="Manage Named Per-Document Permissions"
          >
            <Users size={15} />
          </button>
        )}

        {/* Edit Metadata (Owner or Edit permission) */}
        {canEdit && (
          <button
            id={`btn-edit-${doc.id}`}
            className="btn btn-secondary"
            style={{ padding: '8px 10px' }}
            onClick={() => onOpenEdit(doc)}
            title="Edit Document Title / Description"
          >
            <Edit3 size={15} />
          </button>
        )}

        {/* Delete (Owner Only) */}
        {isOwner && (
          <button
            id={`btn-delete-${doc.id}`}
            className="btn btn-danger"
            style={{ padding: '8px 10px' }}
            onClick={() => onDelete(doc.id, doc.title)}
            title="Soft Delete Document"
          >
            <Trash2 size={15} />
          </button>
        )}
      </div>
    </div>
  );
}
