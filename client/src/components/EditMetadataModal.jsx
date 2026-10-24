import React, { useState, useEffect } from 'react';
import { X, Edit3, AlertCircle } from 'lucide-react';
import { apiRequest } from '../services/api';

export default function EditMetadataModal({ isOpen, onClose, document, onUpdateSuccess }) {
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [tags, setTags] = useState('');
  const [categoryId, setCategoryId] = useState('');
  const [categories, setCategories] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (isOpen && document) {
      setTitle(document.title || '');
      setDescription(document.description || '');
      setCategoryId(document.category_id || '');
      if (document.tags) {
        setTags(Array.isArray(document.tags) ? document.tags.join(', ') : String(document.tags));
      } else {
        setTags('');
      }
      setError(null);
      loadCategories();
    }
  }, [isOpen, document]);

  async function loadCategories() {
    try {
      const res = await apiRequest('/categories');
      setCategories(res.categories || []);
    } catch (err) {
      console.warn('Failed to load categories:', err);
    }
  }

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!title.trim()) {
      setError('Document title is required.');
      return;
    }

    setLoading(true);
    setError(null);

    const parsedTags = tags.trim()
      ? tags.split(',').map(t => t.trim().toLowerCase()).filter(Boolean)
      : [];

    try {
      await apiRequest(`/documents/${document.id}`, {
        method: 'PATCH',
        body: {
          title: title.trim(),
          description: description.trim(),
          category_id: categoryId || null,
          tags: parsedTags
        }
      });
      onUpdateSuccess();
      onClose();
    } catch (err) {
      setError(err.message || 'Failed to update metadata.');
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen || !document) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{ padding: '8px', background: 'var(--blue-subtle)', borderRadius: '8px', color: 'var(--blue-primary)' }}>
              <Edit3 size={20} />
            </div>
            <div>
              <h2 style={{ fontSize: '1.25rem', color: 'var(--navy-dark)' }}>Edit Document Metadata</h2>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                {document.original_filename}
              </div>
            </div>
          </div>
          <button onClick={onClose} style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
            <X size={20} />
          </button>
        </div>

        {error && (
          <div className="alert alert-danger" style={{ marginBottom: '16px' }}>
            <AlertCircle size={16} />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label" htmlFor="edit-title-input">Document Title *</label>
            <input
              id="edit-title-input"
              className="form-input"
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              required
            />
          </div>

          <div className="form-group">
            <label className="form-label" htmlFor="edit-category-select">Enterprise Category</label>
            <select
              id="edit-category-select"
              className="form-select"
              value={categoryId}
              onChange={(e) => setCategoryId(e.target.value)}
            >
              <option value="">-- Uncategorized --</option>
              {categories.map((c) => (
                <option key={c.id} value={c.id}>{c.name}</option>
              ))}
            </select>
          </div>

          {/* Optional Tags */}
          <div className="form-group">
            <label className="form-label" htmlFor="edit-tags-input">
              Optional Tags <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>(comma-separated, e.g. financial, audit, q1)</span>
            </label>
            <input
              id="edit-tags-input"
              className="form-input"
              type="text"
              placeholder="e.g. audit, confidential, board-review"
              value={tags}
              onChange={(e) => setTags(e.target.value)}
            />
          </div>

          <div className="form-group">
            <label className="form-label" htmlFor="edit-desc-input">Confidential Memo / Description</label>
            <textarea
              id="edit-desc-input"
              className="form-textarea"
              rows={3}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '20px' }}>
            <button type="button" className="btn btn-secondary" onClick={onClose} disabled={loading}>
              Cancel
            </button>
            <button id="btn-submit-edit" type="submit" className="btn btn-primary" disabled={loading}>
              {loading ? 'Saving Changes...' : 'Save Metadata'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
