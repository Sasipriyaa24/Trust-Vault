import React, { useState, useEffect } from 'react';
import {
  FileText, Search, Filter, Plus, Download, Users, Edit3, Trash2,
  Calendar, Folder, Tag, ArrowUpDown, RefreshCw, AlertCircle, Eye,
  Lock, CheckCircle2
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useRouter } from '../context/RouterContext';
import { apiRequest, downloadDocumentStream } from '../services/api';
import EditMetadataModal from '../components/EditMetadataModal';

export default function DocumentsView() {
  const { user } = useAuth();
  const { navigate } = useRouter();

  const [documents, setDocuments] = useState([]);
  const [categories, setCategories] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Filters & Search
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('');
  const [ownershipFilter, setOwnershipFilter] = useState('all'); // 'all', 'owned', 'shared'
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');
  const [sortBy, setSortBy] = useState('newest'); // 'newest', 'oldest', 'title_asc', 'title_desc', 'size_desc'

  // Actions state
  const [downloadingId, setDownloadingId] = useState(null);
  const [editDoc, setEditDoc] = useState(null);

  useEffect(() => {
    loadCategories();
  }, []);

  useEffect(() => {
    loadDocuments();
  }, [user, selectedCategory, dateFrom, dateTo]);

  async function loadCategories() {
    try {
      const res = await apiRequest('/categories');
      setCategories(res.categories || []);
    } catch (err) {
      console.warn('Failed to load categories:', err);
    }
  }

  async function loadDocuments() {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams();
      if (searchQuery.trim()) params.append('search', searchQuery.trim());
      if (selectedCategory) params.append('category', selectedCategory);
      if (dateFrom) params.append('dateFrom', dateFrom);
      if (dateTo) params.append('dateTo', dateTo);

      const res = await apiRequest(`/documents?${params.toString()}`);
      setDocuments(res.documents || []);
    } catch (err) {
      console.error('Failed to load documents:', err);
      setError(err.message || 'Failed to retrieve documents');
    } finally {
      setLoading(false);
    }
  }

  function handleSearchSubmit(e) {
    e.preventDefault();
    loadDocuments();
  }

  function handleResetFilters() {
    setSearchQuery('');
    setSelectedCategory('');
    setOwnershipFilter('all');
    setDateFrom('');
    setDateTo('');
    setSortBy('newest');
    setTimeout(() => {
      apiRequest('/documents')
        .then(res => setDocuments(res.documents || []))
        .catch(() => {});
    }, 50);
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

  async function handleDelete(doc) {
    if (!window.confirm(`Are you sure you want to delete "${doc.title}"? This soft-deletes the document and records an audit event.`)) {
      return;
    }

    try {
      await apiRequest(`/documents/${doc.id}`, { method: 'DELETE' });
      await loadDocuments();
    } catch (err) {
      alert(`Delete failed: ${err.message}`);
    }
  }

  // Client-side filtering for ownership and search refinement, plus sorting
  const filteredDocuments = documents.filter((doc) => {
    // Ownership filter
    if (ownershipFilter === 'owned' && doc.owner_id !== user?.id) return false;
    if (ownershipFilter === 'shared' && doc.owner_id === user?.id) return false;

    // Search query match (in title, filename, tags, or description)
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const inTitle = doc.title?.toLowerCase().includes(q);
      const inDesc = doc.description?.toLowerCase().includes(q);
      const inName = doc.original_filename?.toLowerCase().includes(q);
      const inTags = Array.isArray(doc.tags) && doc.tags.some(t => t.toLowerCase().includes(q));
      if (!inTitle && !inDesc && !inName && !inTags) return false;
    }

    return true;
  });

  // Sorting
  const sortedDocuments = [...filteredDocuments].sort((a, b) => {
    if (sortBy === 'newest') {
      return new Date(b.created_at) - new Date(a.created_at);
    }
    if (sortBy === 'oldest') {
      return new Date(a.created_at) - new Date(b.created_at);
    }
    if (sortBy === 'title_asc') {
      return (a.title || '').localeCompare(b.title || '');
    }
    if (sortBy === 'title_desc') {
      return (b.title || '').localeCompare(a.title || '');
    }
    if (sortBy === 'size_desc') {
      return (b.file_size_bytes || 0) - (a.file_size_bytes || 0);
    }
    return 0;
  });

  function formatBytes(bytes) {
    if (!bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  function formatDate(iso) {
    if (!iso) return 'N/A';
    return new Date(iso).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric'
    });
  }

  const canUpload = ['document_owner', 'administrator'].includes(user?.system_role);

  return (
    <div style={{ maxWidth: '1360px', margin: '0 auto', padding: '24px 20px', width: '100%' }}>
      {/* Title & Top Actions */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <h1 style={{ fontSize: '1.6rem', color: 'var(--navy-dark)' }}>My Documents</h1>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            Authorized repository of confidential documents with verified cryptographic access
          </p>
        </div>

        <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
          <button
            className="btn btn-secondary"
            onClick={loadDocuments}
            disabled={loading}
            title="Refresh document repository"
          >
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} /> Refresh
          </button>

          {canUpload && (
            <button
              id="btn-goto-upload"
              className="btn btn-primary"
              onClick={() => navigate('/documents/upload')}
            >
              <Plus size={16} /> Upload Document
            </button>
          )}
        </div>
      </div>

      {error && (
        <div className="alert alert-danger" style={{ marginBottom: '16px' }}>
          <AlertCircle size={16} />
          <div>{error}</div>
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="card" style={{ marginBottom: '20px', padding: '16px' }}>
        <form onSubmit={handleSearchSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {/* Top Row: Search input + Category + Ownership tabs */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '12px', alignItems: 'center' }}>
            {/* Search Input */}
            <div style={{ position: 'relative' }}>
              <input
                id="search-documents-input"
                className="form-input"
                type="text"
                placeholder="Search by title, tags, memo..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                style={{ paddingLeft: '34px' }}
              />
              <Search size={16} color="var(--text-muted)" style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)' }} />
            </div>

            {/* Category Dropdown */}
            <select
              id="filter-category-select"
              className="form-select"
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
            >
              <option value="">All Categories</option>
              {categories.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name}
                </option>
              ))}
            </select>

            {/* Ownership Filter */}
            <select
              id="filter-ownership-select"
              className="form-select"
              value={ownershipFilter}
              onChange={(e) => setOwnershipFilter(e.target.value)}
            >
              <option value="all">All Accessible Documents</option>
              <option value="owned">Owned by Me</option>
              <option value="shared">Shared with Me (Delegated)</option>
            </select>

            {/* Sort Dropdown */}
            <select
              id="sort-documents-select"
              className="form-select"
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value)}
            >
              <option value="newest">Sort: Newest Ingested</option>
              <option value="oldest">Sort: Oldest Ingested</option>
              <option value="title_asc">Sort: Title (A-Z)</option>
              <option value="title_desc">Sort: Title (Z-A)</option>
              <option value="size_desc">Sort: File Size (Largest)</option>
            </select>
          </div>

          {/* Bottom Row: Date Range & Action Buttons */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', borderTop: '1px solid var(--border-subtle)', paddingTop: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', fontSize: '0.8rem' }}>
              <span style={{ color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                <Calendar size={14} /> Date Range:
              </span>
              <input
                id="filter-date-from"
                type="date"
                className="form-input"
                style={{ width: 'auto', padding: '4px 8px', fontSize: '0.78rem' }}
                value={dateFrom}
                onChange={(e) => setDateFrom(e.target.value)}
                placeholder="From"
              />
              <span style={{ color: 'var(--text-muted)' }}>to</span>
              <input
                id="filter-date-to"
                type="date"
                className="form-input"
                style={{ width: 'auto', padding: '4px 8px', fontSize: '0.78rem' }}
                value={dateTo}
                onChange={(e) => setDateTo(e.target.value)}
                placeholder="To"
              />
            </div>

            <div style={{ display: 'flex', gap: '8px' }}>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={handleResetFilters}
                style={{ fontSize: '0.78rem', padding: '6px 10px' }}
              >
                Reset Filters
              </button>
              <button
                type="submit"
                className="btn btn-primary"
                style={{ fontSize: '0.78rem', padding: '6px 12px' }}
              >
                Apply Filters
              </button>
            </div>
          </div>
        </form>
      </div>

      {/* Results Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px', fontSize: '0.825rem', color: 'var(--text-muted)' }}>
        <div>
          Showing <strong>{sortedDocuments.length}</strong> of {documents.length} accessible documents
        </div>
      </div>

      {/* Documents Table */}
      {loading ? (
        <div className="card" style={{ padding: '48px 24px', textAlign: 'center', color: 'var(--text-muted)' }}>
          <RefreshCw size={24} className="animate-spin" style={{ margin: '0 auto 12px', opacity: 0.6 }} />
          <div>Verifying authorization policies and querying vault...</div>
        </div>
      ) : sortedDocuments.length === 0 ? (
        <div className="card" style={{ padding: '48px 24px', textAlign: 'center' }}>
          <div
            style={{
              width: '48px',
              height: '48px',
              borderRadius: '50%',
              background: 'var(--bg-subtle)',
              border: '1px solid var(--border-subtle)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              margin: '0 auto 12px',
              color: 'var(--text-muted)'
            }}
          >
            <FileText size={24} />
          </div>
          <h3 style={{ fontSize: '1.1rem', color: 'var(--navy-dark)', marginBottom: '6px' }}>
            No Documents Found
          </h3>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', maxWidth: '420px', margin: '0 auto 16px' }}>
            {searchQuery || selectedCategory || dateFrom || dateTo || ownershipFilter !== 'all'
              ? 'No documents matched your specific search criteria or date filters.'
              : 'Your identity does not currently own or have delegated access to any documents.'}
          </p>
          {canUpload && (
            <button
              className="btn btn-primary"
              onClick={() => navigate('/documents/upload')}
            >
              <Plus size={15} /> Upload First Document
            </button>
          )}
        </div>
      ) : (
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th style={{ minWidth: '220px' }}>Document</th>
                <th>Category & Tags</th>
                <th>Owner</th>
                <th>Access Level</th>
                <th>Size</th>
                <th>Created</th>
                <th style={{ textAlign: 'right', minWidth: '160px' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {sortedDocuments.map((doc) => {
                const isOwner = doc.owner_id === user?.id || doc.user_access_level === 'owner';
                const canEdit = isOwner || doc.user_access_level === 'edit';

                return (
                  <tr key={doc.id}>
                    {/* Title & Description */}
                    <td>
                      <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
                        <div style={{ padding: '6px', background: 'var(--blue-subtle)', color: 'var(--blue-primary)', borderRadius: '6px', marginTop: '2px' }}>
                          <FileText size={16} />
                        </div>
                        <div>
                          <a
                            href={`/documents/${doc.id}`}
                            onClick={(e) => { e.preventDefault(); navigate(`/documents/${doc.id}`); }}
                            style={{ fontWeight: 600, color: 'var(--navy-dark)', textDecoration: 'none', fontSize: '0.875rem' }}
                            className="hover:underline"
                          >
                            {doc.title}
                          </a>
                          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginTop: '2px' }}>
                            {doc.original_filename}
                          </div>
                        </div>
                      </div>
                    </td>

                    {/* Category & Tags */}
                    <td>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', alignItems: 'flex-start' }}>
                        <span className="badge badge-gray" style={{ fontSize: '0.68rem' }}>
                          {doc.category_name || 'Uncategorized'}
                        </span>
                        {Array.isArray(doc.tags) && doc.tags.length > 0 && (
                          <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                            {doc.tags.slice(0, 3).map((t, idx) => (
                              <span key={idx} className="badge badge-blue" style={{ fontSize: '0.65rem' }}>
                                #{t}
                              </span>
                            ))}
                            {doc.tags.length > 3 && (
                              <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>
                                +{doc.tags.length - 3}
                              </span>
                            )}
                          </div>
                        )}
                      </div>
                    </td>

                    {/* Owner */}
                    <td>
                      <div style={{ fontSize: '0.8rem', fontWeight: 500, color: 'var(--navy-dark)' }}>
                        {doc.owner_name}
                      </div>
                      <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                        {doc.owner_email}
                      </div>
                    </td>

                    {/* Access Level Badge */}
                    <td>
                      {isOwner ? (
                        <span className="badge badge-emerald">👑 Owner</span>
                      ) : doc.user_access_level === 'edit' ? (
                        <span className="badge badge-blue">✏️ Can Edit</span>
                      ) : (
                        <span className="badge badge-gray">👁️ Read</span>
                      )}
                    </td>

                    {/* Size */}
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>
                      {formatBytes(doc.file_size_bytes)}
                    </td>

                    {/* Date */}
                    <td style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                      {formatDate(doc.created_at)}
                    </td>

                    {/* Actions */}
                    <td style={{ textAlign: 'right' }}>
                      <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                        {/* View Details */}
                        <button
                          className="btn btn-secondary"
                          style={{ padding: '5px 8px' }}
                          onClick={() => navigate(`/documents/${doc.id}`)}
                          title="View Details"
                        >
                          <Eye size={13} />
                        </button>

                        {/* Download */}
                        <button
                          className="btn btn-secondary"
                          style={{ padding: '5px 8px' }}
                          onClick={() => handleDownload(doc)}
                          disabled={downloadingId === doc.id}
                          title="Download stream"
                        >
                          <Download size={13} />
                        </button>

                        {/* Sharing (Owner only) */}
                        {isOwner && (
                          <button
                            className="btn btn-secondary"
                            style={{ padding: '5px 8px' }}
                            onClick={() => navigate(`/documents/${doc.id}/permissions`)}
                            title="Manage Sharing & Permissions"
                          >
                            <Users size={13} />
                          </button>
                        )}

                        {/* Edit Metadata (Owner or Edit) */}
                        {canEdit && (
                          <button
                            className="btn btn-secondary"
                            style={{ padding: '5px 8px' }}
                            onClick={() => setEditDoc(doc)}
                            title="Edit Metadata"
                          >
                            <Edit3 size={13} />
                          </button>
                        )}

                        {/* Delete (Owner only) */}
                        {isOwner && (
                          <button
                            className="btn btn-danger"
                            style={{ padding: '5px 8px' }}
                            onClick={() => handleDelete(doc)}
                            title="Delete Document"
                          >
                            <Trash2 size={13} />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Edit Metadata Modal */}
      <EditMetadataModal
        isOpen={Boolean(editDoc)}
        document={editDoc}
        onClose={() => setEditDoc(null)}
        onUpdateSuccess={loadDocuments}
      />
    </div>
  );
}
