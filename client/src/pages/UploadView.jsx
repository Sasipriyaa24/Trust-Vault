import React, { useState, useEffect, useRef } from 'react';
import { UploadCloud, FileText, CheckCircle2, AlertCircle, ArrowLeft, Lock, ShieldAlert, Tag, Folder } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useRouter } from '../context/RouterContext';
import { apiRequest, getAuthToken } from '../services/api';

export default function UploadView() {
  const { user } = useAuth();
  const { navigate } = useRouter();

  const [file, setFile] = useState(null);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [categoryId, setCategoryId] = useState('');
  const [tags, setTags] = useState('');
  const [categories, setCategories] = useState([]);

  const [isDragging, setIsDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [error, setError] = useState(null);
  const [clientWarning, setClientWarning] = useState(null);
  const [uploadedDoc, setUploadedDoc] = useState(null);

  const fileInputRef = useRef(null);

  const allowedExtensions = ['.pdf', '.png', '.jpg', '.jpeg'];

  useEffect(() => {
    loadCategories();
  }, []);

  async function loadCategories() {
    try {
      const res = await apiRequest('/categories');
      setCategories(res.categories || []);
      if (res.categories && res.categories.length > 0) {
        setCategoryId(res.categories[0].id);
      }
    } catch (err) {
      console.warn('Failed to load categories:', err);
    }
  }

  function validateFile(selectedFile) {
    setClientWarning(null);
    if (!selectedFile) return false;

    // 10MB limit
    if (selectedFile.size > 10 * 1024 * 1024) {
      setClientWarning('Security Warning: File exceeds the 10MB limit. Server will reject this payload.');
      return false;
    }

    const ext = selectedFile.name.substring(selectedFile.name.lastIndexOf('.')).toLowerCase();
    if (ext === '.svg') {
      setClientWarning('Security Rejection: SVG files are strictly prohibited due to Stored XSS prevention policy.');
      return false;
    }

    if (!allowedExtensions.includes(ext)) {
      setClientWarning(`Warning: File extension "${ext}" is not in the standard allowlist (${allowedExtensions.join(', ')}).`);
    }

    return true;
  }

  function handleFileSelection(selectedFile) {
    if (!selectedFile) return;
    setError(null);
    validateFile(selectedFile);
    setFile(selectedFile);

    if (!title) {
      const nameWithoutExt = selectedFile.name.replace(/\.[^/.]+$/, '');
      setTitle(nameWithoutExt);
    }
  }

  function handleDragOver(e) {
    e.preventDefault();
    setIsDragging(true);
  }

  function handleDragLeave(e) {
    e.preventDefault();
    setIsDragging(false);
  }

  function handleDrop(e) {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileSelection(e.dataTransfer.files[0]);
    }
  }

  function formatBytes(bytes) {
    if (!bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  function handleUpload(e) {
    e.preventDefault();
    if (!file) {
      setError('Please select or drag a file to upload.');
      return;
    }

    if (!title.trim()) {
      setError('Document title is required.');
      return;
    }

    setError(null);
    setUploading(true);
    setUploadProgress(10);

    const formData = new FormData();
    formData.append('file', file);
    formData.append('document', file);
    formData.append('title', title.trim());
    formData.append('description', description.trim());
    if (categoryId) formData.append('category_id', categoryId);

    const parsedTags = tags.trim()
      ? tags.split(',').map(t => t.trim().toLowerCase()).filter(Boolean)
      : [];
    formData.append('tags', JSON.stringify(parsedTags));

    // Real XMLHttpRequest to report upload progress accurately
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/documents', true);

    const token = getAuthToken();
    if (token) {
      xhr.setRequestHeader('Authorization', `Bearer ${token}`);
    }

    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable) {
        const percent = Math.round((event.loaded / event.total) * 100);
        // Keep between 10% and 90% while uploading
        setUploadProgress(Math.min(95, Math.max(10, percent)));
      }
    };

    xhr.onload = () => {
      setUploading(false);
      setUploadProgress(100);

      try {
        const response = JSON.parse(xhr.responseText);
        if (xhr.status >= 200 && xhr.status < 300) {
          setUploadedDoc(response.document);
        } else {
          setError(response.error || `Upload failed with status ${xhr.status}`);
        }
      } catch (err) {
        setError(`Upload failed with status ${xhr.status}: ${xhr.statusText}`);
      }
    };

    xhr.onerror = () => {
      setUploading(false);
      setError('Network failure while transmitting document to private storage.');
    };

    xhr.send(formData);
  }

  function handleReset() {
    setFile(null);
    setTitle('');
    setDescription('');
    setTags('');
    setError(null);
    setClientWarning(null);
    setUploadedDoc(null);
    setUploadProgress(0);
  }

  const isViewer = user?.system_role === 'viewer';

  return (
    <div style={{ maxWidth: '800px', margin: '0 auto', padding: '24px 20px', width: '100%' }}>
      {/* Header */}
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
            <h1 style={{ fontSize: '1.5rem', color: 'var(--navy-dark)' }}>Upload Document</h1>
            <p style={{ fontSize: '0.825rem', color: 'var(--text-muted)' }}>
              Encrypted ingest to private bucket with SHA-256 verification and file signature validation
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.75rem', padding: '4px 10px', background: 'var(--blue-subtle)', border: '1px solid var(--blue-border)', borderRadius: 'var(--radius-md)', color: 'var(--blue-text)' }}>
          <Lock size={13} /> Strict Object-Level Isolation
        </div>
      </div>

      {/* Role Notice */}
      {isViewer && (
        <div className="alert alert-danger" style={{ marginBottom: '20px' }}>
          <ShieldAlert size={18} style={{ flexShrink: 0, marginTop: '2px' }} />
          <div>
            <strong>Restricted Persona Notice:</strong> Your active role is <code>viewer</code>. 
            The backend will reject document upload requests with a <code>403 Forbidden</code> audit entry.
          </div>
        </div>
      )}

      {/* Success View */}
      {uploadedDoc ? (
        <div className="card" style={{ borderTop: '4px solid var(--emerald-success)', padding: '32px 24px', textAlign: 'center' }}>
          <div
            style={{
              width: '56px',
              height: '56px',
              borderRadius: '50%',
              background: 'var(--emerald-bg)',
              border: '1px solid var(--emerald-border)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              margin: '0 auto 16px',
              color: 'var(--emerald-success)'
            }}
          >
            <CheckCircle2 size={32} />
          </div>

          <h2 style={{ fontSize: '1.3rem', color: 'var(--navy-dark)', marginBottom: '6px' }}>
            Document Upload Complete
          </h2>

          <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem', maxWidth: '480px', margin: '0 auto 20px' }}>
            The document has been securely stored in private storage, hashed with SHA-256, and appended to the tamper-evident audit ledger.
          </p>

          <div
            style={{
              background: 'var(--bg-subtle)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-md)',
              padding: '16px',
              maxWidth: '520px',
              margin: '0 auto 24px',
              textAlign: 'left',
              fontSize: '0.825rem'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
              <span style={{ color: 'var(--text-muted)' }}>Title:</span>
              <span style={{ fontWeight: 600, color: 'var(--navy-dark)' }}>{uploadedDoc.title}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
              <span style={{ color: 'var(--text-muted)' }}>Original File:</span>
              <span style={{ fontFamily: 'var(--font-mono)' }}>{uploadedDoc.original_filename}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
              <span style={{ color: 'var(--text-muted)' }}>Size:</span>
              <span>{formatBytes(uploadedDoc.file_size_bytes)}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>SHA-256 Fingerprint:</span>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: 'var(--blue-text)' }}>
                {uploadedDoc.file_hash_sha256?.substring(0, 16)}...
              </span>
            </div>
          </div>

          <div style={{ display: 'flex', justifyContent: 'center', gap: '12px' }}>
            <button
              id="btn-upload-view-details"
              className="btn btn-primary"
              onClick={() => navigate(`/documents/${uploadedDoc.id}`)}
            >
              <FileText size={15} /> View Document Details
            </button>
            <button
              id="btn-upload-another"
              className="btn btn-secondary"
              onClick={handleReset}
            >
              Upload Another Document
            </button>
          </div>
        </div>
      ) : (
        /* Upload Form */
        <form onSubmit={handleUpload}>
          {error && (
            <div className="alert alert-danger" style={{ marginBottom: '16px' }}>
              <AlertCircle size={18} style={{ flexShrink: 0, marginTop: '2px' }} />
              <div>
                <strong>Upload Error:</strong> {error}
              </div>
            </div>
          )}

          {clientWarning && (
            <div className="alert alert-warning" style={{ marginBottom: '16px' }}>
              <AlertCircle size={18} style={{ flexShrink: 0, marginTop: '2px' }} />
              <div>{clientWarning}</div>
            </div>
          )}

          {/* Drag & Drop File Container */}
          <div className="card" style={{ marginBottom: '20px' }}>
            <label className="form-label" style={{ marginBottom: '8px' }}>File Payload *</label>
            <div
              id="upload-dropzone"
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              style={{
                border: isDragging ? '2px dashed var(--blue-primary)' : '2px dashed var(--border-medium)',
                background: isDragging ? 'var(--blue-subtle)' : 'var(--bg-subtle)',
                borderRadius: 'var(--radius-lg)',
                padding: '36px 20px',
                textAlign: 'center',
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
            >
              <input
                id="file-input-element"
                ref={fileInputRef}
                type="file"
                style={{ display: 'none' }}
                onChange={(e) => handleFileSelection(e.target.files[0])}
                accept=".pdf,.png,.jpg,.jpeg"
              />

              <div
                style={{
                  width: '48px',
                  height: '48px',
                  borderRadius: '50%',
                  background: 'var(--bg-surface)',
                  border: '1px solid var(--border-subtle)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  margin: '0 auto 12px',
                  color: 'var(--blue-primary)'
                }}
              >
                <UploadCloud size={26} />
              </div>

              {file ? (
                <div>
                  <div style={{ fontWeight: 600, color: 'var(--navy-dark)', fontSize: '0.95rem' }}>
                    {file.name}
                  </div>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                    {formatBytes(file.size)} • {file.type || 'Binary Stream'}
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--blue-primary)', marginTop: '8px' }}>
                    Click or drag a different file to replace
                  </div>
                </div>
              ) : (
                <div>
                  <div style={{ fontWeight: 600, color: 'var(--navy-dark)', fontSize: '0.92rem' }}>
                    Click to select or drag and drop document
                  </div>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                    Supported formats: PDF, PNG, JPG, JPEG (Max 10MB)
                  </div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '8px' }}>
                    Strict magic-byte signature check validated server-side. Executable & SVG files blocked.
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Metadata Fields */}
          <div className="card" style={{ marginBottom: '20px' }}>
            <h3 style={{ fontSize: '1rem', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <FileText size={16} color="var(--blue-primary)" />
              <span>Document Metadata</span>
            </h3>

            <div className="form-group">
              <label className="form-label" htmlFor="upload-title">Title *</label>
              <input
                id="upload-title"
                className="form-input"
                type="text"
                required
                placeholder="e.g. Q3 Financial Audit Report"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
              />
            </div>

            <div className="form-group">
              <label className="form-label" htmlFor="upload-description">Confidential Memo / Description</label>
              <textarea
                id="upload-description"
                className="form-textarea"
                rows={3}
                placeholder="Brief summary or retention requirements..."
                value={description}
                onChange={(e) => setDescription(e.target.value)}
              />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '16px' }}>
              <div className="form-group">
                <label className="form-label" htmlFor="upload-category">
                  <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Folder size={14} /> Category
                  </span>
                </label>
                <select
                  id="upload-category"
                  className="form-select"
                  value={categoryId}
                  onChange={(e) => setCategoryId(e.target.value)}
                >
                  {categories.map((cat) => (
                    <option key={cat.id} value={cat.id}>
                      {cat.name}
                    </option>
                  ))}
                  <option value="">Uncategorized</option>
                </select>
              </div>

              <div className="form-group">
                <label className="form-label" htmlFor="upload-tags">
                  <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Tag size={14} /> Tags
                  </span>
                </label>
                <input
                  id="upload-tags"
                  className="form-input"
                  type="text"
                  placeholder="e.g. audit, confidential, finance"
                  value={tags}
                  onChange={(e) => setTags(e.target.value)}
                />
                <div className="form-hint">Comma-separated tags for filtering</div>
              </div>
            </div>
          </div>

          {/* Upload Progress Bar */}
          {uploading && (
            <div className="card" style={{ marginBottom: '20px', padding: '16px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', marginBottom: '6px' }}>
                <span style={{ fontWeight: 600, color: 'var(--navy-dark)' }}>Uploading to Vault Storage...</span>
                <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--blue-primary)', fontWeight: 600 }}>
                  {uploadProgress}%
                </span>
              </div>
              <div style={{ width: '100%', height: '8px', background: 'var(--bg-subtle)', borderRadius: 'var(--radius-full)', overflow: 'hidden' }}>
                <div
                  style={{
                    width: `${uploadProgress}%`,
                    height: '100%',
                    background: 'var(--blue-primary)',
                    borderRadius: 'var(--radius-full)',
                    transition: 'width 0.2s ease'
                  }}
                />
              </div>
            </div>
          )}

          {/* Submit Actions */}
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '12px' }}>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => navigate('/documents')}
              disabled={uploading}
            >
              Cancel
            </button>
            <button
              id="btn-submit-upload"
              type="submit"
              className="btn btn-primary"
              disabled={uploading || !file}
              style={{ minWidth: '140px' }}
            >
              {uploading ? `Uploading (${uploadProgress}%)...` : 'Ingest Document'}
            </button>
          </div>
        </form>
      )}
    </div>
  );
}
