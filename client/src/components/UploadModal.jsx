import React, { useState, useEffect } from 'react';
import { X, UploadCloud, AlertCircle, CheckCircle2, ShieldAlert } from 'lucide-react';
import { apiRequest } from '../services/api';

export default function UploadModal({ isOpen, onClose, onUploadSuccess }) {
  const [file, setFile] = useState(null);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [tags, setTags] = useState('');
  const [categoryId, setCategoryId] = useState('');
  const [categories, setCategories] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (isOpen) {
      loadCategories();
      // Reset form
      setFile(null);
      setTitle('');
      setDescription('');
      setTags('');
      setError(null);
    }
  }, [isOpen]);

  async function loadCategories() {
    try {
      const res = await apiRequest('/categories');
      setCategories(res.categories || []);
      if (res.categories && res.categories.length > 0) {
        setCategoryId(res.categories[0].id);
      }
    } catch (err) {
      console.warn('Failed to fetch categories:', err);
    }
  }

  const handleFileChange = (e) => {
    const selected = e.target.files[0];
    if (!selected) return;

    if (selected.size > 10 * 1024 * 1024) {
      setError('File exceeds maximum size limit (10MB). Please select a smaller file.');
      setFile(null);
      return;
    }

    const ext = selected.name.substring(selected.name.lastIndexOf('.')).toLowerCase();
    if (ext === '.svg') {
      setError('Security Alert: SVG files are strictly prohibited due to Stored XSS prevention policy.');
      setFile(null);
      return;
    }

    setError(null);
    setFile(selected);
    if (!title) {
      // Auto-fill title from filename without extension
      const baseName = selected.name.replace(/\.[^/.]+$/, "");
      setTitle(baseName);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!file) {
      setError('Please attach a document file.');
      return;
    }

    if (!title.trim()) {
      setError('Document title is required.');
      return;
    }

    setLoading(true);
    setError(null);

    const formData = new FormData();
    formData.append('file', file);
    formData.append('title', title.trim());
    formData.append('description', description.trim());
    if (categoryId) {
      formData.append('category_id', categoryId);
    }
    if (tags.trim()) {
      formData.append('tags', tags.trim());
    }

    try {
      await apiRequest('/documents', {
        method: 'POST',
        body: formData
      });
      onUploadSuccess();
      onClose();
    } catch (err) {
      setError(err.message || 'Failed to upload document.');
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{ padding: '8px', background: 'rgba(6, 182, 212, 0.15)', borderRadius: '8px', color: 'var(--cyan-light)' }}>
              <UploadCloud size={20} />
            </div>
            <div>
              <h2 style={{ fontSize: '1.25rem', color: 'var(--text-primary)' }}>Secure Document Upload</h2>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Encrypted with SHA-256 integrity in private storage
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

        <form onSubmit={handleSubmit}>
          {/* File input / dropzone */}
          <div className="form-group">
            <label className="form-label">Document File (Max 10MB)</label>
            <div style={{ border: '2px dashed rgba(255, 255, 255, 0.15)', borderRadius: 'var(--radius-md)', padding: '24px', textAlign: 'center', background: 'rgba(11, 17, 32, 0.5)', cursor: 'pointer' }}>
              <input
                id="file-upload-input"
                type="file"
                onChange={handleFileChange}
                style={{ display: 'none' }}
                accept=".pdf,.png,.jpg,.jpeg,.docx,.xlsx,.txt"
              />
              <label htmlFor="file-upload-input" style={{ cursor: 'pointer', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px' }}>
                <UploadCloud size={32} color="var(--cyan-light)" />
                {file ? (
                  <div style={{ color: 'var(--emerald-success)', fontWeight: 600, fontSize: '0.9rem' }}>
                    ✓ {file.name} ({(file.size / 1024).toFixed(1)} KB)
                  </div>
                ) : (
                  <>
                    <div style={{ fontSize: '0.9rem', color: 'var(--text-primary)', fontWeight: 600 }}>
                      Click to browse or drop document here
                    </div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      Allowed: PDF, DOCX, XLSX, PNG, JPG, TXT
                    </div>
                  </>
                )}
              </label>
            </div>
          </div>

          {/* Security alert notification */}
          <div style={{ padding: '8px 12px', background: 'rgba(6, 182, 212, 0.08)', border: '1px solid rgba(6, 182, 212, 0.2)', borderRadius: 'var(--radius-md)', fontSize: '0.75rem', color: 'var(--cyan-light)', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <ShieldAlert size={14} />
            <span>Magic byte inspection will verify file authenticity on server. SVGs and executables are blocked.</span>
          </div>

          {/* Title */}
          <div className="form-group">
            <label className="form-label" htmlFor="doc-title-input">Document Title *</label>
            <input
              id="doc-title-input"
              className="form-input"
              type="text"
              placeholder="e.g. Q1_2026_Audit_Report.pdf"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              required
            />
          </div>

          {/* Category */}
          <div className="form-group">
            <label className="form-label" htmlFor="doc-category-select">Enterprise Category</label>
            <select
              id="doc-category-select"
              className="form-select"
              value={categoryId}
              onChange={(e) => setCategoryId(e.target.value)}
            >
              {categories.map((c) => (
                <option key={c.id} value={c.id}>{c.name}</option>
              ))}
            </select>
          </div>

          {/* Optional Tags */}
          <div className="form-group">
            <label className="form-label" htmlFor="doc-tags-input">
              Optional Tags <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>(comma-separated, e.g. financial, audit, q1)</span>
            </label>
            <input
              id="doc-tags-input"
              className="form-input"
              type="text"
              placeholder="e.g. audit, confidential, board-review"
              value={tags}
              onChange={(e) => setTags(e.target.value)}
            />
          </div>

          {/* Description */}
          <div className="form-group">
            <label className="form-label" htmlFor="doc-desc-input">Confidential Memo / Description</label>
            <textarea
              id="doc-desc-input"
              className="form-textarea"
              rows={3}
              placeholder="Brief description of the confidential contents..."
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '24px' }}>
            <button type="button" className="btn btn-secondary" onClick={onClose} disabled={loading}>
              Cancel
            </button>
            <button id="btn-submit-upload" type="submit" className="btn btn-primary" disabled={loading || !file}>
              {loading ? 'Encrypting & Storing...' : 'Upload to Vault'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
