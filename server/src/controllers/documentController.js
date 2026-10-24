const crypto = require('crypto');
const uuidv4 = crypto.randomUUID;
const db = require('../db/db');
const storageService = require('../services/storageService');

/**
 * Helper to parse tags safely from various incoming payload formats (JSON array, comma-separated string, or array)
 */
function parseTagsInput(tagsInput) {
  if (!tagsInput) return [];
  if (Array.isArray(tagsInput)) {
    return tagsInput.map(t => String(t).trim().toLowerCase()).filter(Boolean);
  }
  if (typeof tagsInput === 'string') {
    const trimmed = tagsInput.trim();
    if (!trimmed) return [];
    if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
      try {
        const parsed = JSON.parse(trimmed);
        if (Array.isArray(parsed)) {
          return parsed.map(t => String(t).trim().toLowerCase()).filter(Boolean);
        }
      } catch {
        // Fall back to comma-separated split
      }
    }
    return trimmed.split(',').map(t => t.trim().toLowerCase()).filter(Boolean);
  }
  return [];
}

/**
 * Helper to strip sensitive storage keys from API output
 */
function sanitizeDocumentOutput(doc) {
  if (!doc) return null;
  const safe = { ...doc };
  delete safe.storage_path;
  return safe;
}

/**
 * Upload a new document into the private vault.
 */
async function uploadDocument(req, res) {
  // Check that user is document_owner or administrator
  if (!['document_owner', 'administrator'].includes(req.user.system_role)) {
    await db.addAuditLog({
      userId: req.user.id,
      userEmail: req.user.email,
      action: 'DOCUMENT_UPLOAD_BLOCKED',
      status: 'DENIED',
      requestId: req.id,
      ipAddress: req.ip || '127.0.0.1',
      userAgent: req.get('user-agent') || 'Unknown',
      details: {
        reason: 'Viewer role cannot upload documents. Only document_owner or administrator may upload.',
        role: req.user.system_role
      }
    });

    return res.status(403).json({
      error: 'Access Denied: Your account role does not have permission to upload documents.',
      code: 'INSUFFICIENT_UPLOAD_ROLE'
    });
  }

  const { title, description, category_id, tags } = req.body;
  const file = req.file;

  if (!file) {
    return res.status(400).json({
      error: 'File attachment is required.',
      code: 'MISSING_FILE'
    });
  }

  if (!title || typeof title !== 'string' || title.trim().length === 0) {
    return res.status(400).json({
      error: 'Document title is required.',
      code: 'MISSING_TITLE'
    });
  }

  const parsedTags = parseTagsInput(tags);

  // 1. Compute SHA-256 integrity hash of file contents
  const fileHash = crypto
    .createHash('sha256')
    .update(file.buffer)
    .digest('hex');

  // 2. Generate random unguessable storage path
  const docUuid = uuidv4();
  const safeExtension = file.originalname.includes('.')
    ? file.originalname.substring(file.originalname.lastIndexOf('.'))
    : '.bin';
  const storagePath = `vault/${req.user.id}/${docUuid}${safeExtension}`;

  let storageUploaded = false;

  try {
    // 3. Upload raw buffer to private storage vault
    await storageService.uploadFile(storagePath, file.buffer, file.mimetype);
    storageUploaded = true;

    // 4. Save metadata to database (strictly deriving owner_id from req.user.id)
    const document = await db.createDocument({
      id: docUuid,
      title: title.trim(),
      description: description ? description.trim() : '',
      category_id: category_id || null,
      owner_id: req.user.id,
      storage_path: storagePath,
      original_filename: file.sanitizedFilename || file.originalname,
      file_size_bytes: file.size,
      mime_type: file.mimetype,
      file_hash_sha256: fileHash,
      tags: parsedTags
    });

    // 5. Append immutable audit log
    await db.addAuditLog({
      userId: req.user.id,
      userEmail: req.user.email,
      action: 'DOCUMENT_UPLOAD_SUCCESS',
      status: 'SUCCESS',
      documentId: document.id,
      documentTitle: document.title,
      requestId: req.id,
      ipAddress: req.ip || '127.0.0.1',
      userAgent: req.get('user-agent') || 'Unknown',
      details: {
        file_size_bytes: file.size,
        mime_type: file.mimetype,
        file_hash_sha256: fileHash,
        original_filename: document.original_filename,
        tags: document.tags
      }
    });

    res.status(201).json({
      message: 'Document uploaded and securely encrypted in private vault.',
      document: sanitizeDocumentOutput(document)
    });
  } catch (err) {
    // Transactional rollback: Clean up storage file if database or audit log failed
    if (storageUploaded) {
      try {
        await storageService.deleteFile(storagePath);
        console.log(`🧹 Rollback: Cleaned up orphaned storage object at ${storagePath}`);
      } catch (cleanupErr) {
        console.error('Storage cleanup rollback error:', cleanupErr.message);
      }
    }

    // Record auditable failure event for the partial failure / rollback
    try {
      await db.addAuditLog({
        userId: req.user.id,
        userEmail: req.user.email,
        action: 'DOCUMENT_UPLOAD_FAILED',
        status: 'ERROR',
        requestId: req.id,
        ipAddress: req.ip || '127.0.0.1',
        userAgent: req.get('user-agent') || 'Unknown',
        details: {
          reason: err.message,
          storageRolledBack: storageUploaded,
          original_filename: file?.sanitizedFilename || file?.originalname
        }
      });
    } catch (auditErr) {
      console.error('Failed to log upload failure event:', auditErr.message);
    }

    console.error('Document upload error:', err);
    res.status(500).json({
      error: 'Failed to process and store document.',
      details: err.message
    });
  }
}

/**
 * List documents accessible by the current user with filtering & search.
 */
async function listDocuments(req, res) {
  try {
    const { search, category, owner, dateFrom, dateTo, tag } = req.query;

    const documents = await db.listDocumentsForUser(
      req.user.id,
      req.user.system_role,
      { search, category, owner, dateFrom, dateTo, tag }
    );

    const safeDocuments = documents.map(sanitizeDocumentOutput);

    res.json({
      total: safeDocuments.length,
      documents: safeDocuments
    });
  } catch (err) {
    console.error('List documents error:', err);
    res.status(500).json({ error: 'Failed to retrieve documents.' });
  }
}

/**
 * Retrieve document metadata by ID.
 * (Access check verified by authorizeDocumentAccess middleware)
 */
async function getDocumentById(req, res) {
  const doc = req.document; // Populated by authorizeDocumentAccess middleware
  const owner = await db.getProfileById(doc.owner_id);
  const category = doc.category_id ? await db.getCategoryById(doc.category_id) : null;

  await db.addAuditLog({
    userId: req.user.id,
    userEmail: req.user.email,
    action: 'DOCUMENT_METADATA_READ',
    status: 'SUCCESS',
    documentId: doc.id,
    documentTitle: doc.title,
    requestId: req.id,
    ipAddress: req.ip || '127.0.0.1',
    userAgent: req.get('user-agent') || 'Unknown',
    details: { accessLevel: req.userAccessLevel }
  });

  const fullDoc = {
    ...doc,
    tags: doc.tags || [],
    owner_name: owner ? owner.full_name : 'Unknown Owner',
    owner_email: owner ? owner.email : '',
    category_name: category ? category.name : 'Uncategorized',
    user_access_level: req.userAccessLevel
  };

  res.json({
    document: sanitizeDocumentOutput(fullDoc)
  });
}

/**
 * Stream file content directly to client as secure download proxy.
 * (Access check verified by authorizeDocumentAccess middleware)
 */
async function downloadDocument(req, res) {
  const doc = req.document;

  try {
    const fileStream = await storageService.getFileStream(doc.storage_path);

    // Strict Security Headers
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(doc.original_filename)}"`);
    res.setHeader('Content-Type', doc.mime_type || 'application/octet-stream');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', "default-src 'none'");
    res.setHeader('Cache-Control', 'private, no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');

    await db.addAuditLog({
      userId: req.user.id,
      userEmail: req.user.email,
      action: 'DOCUMENT_DOWNLOAD_ALLOWED',
      status: 'SUCCESS',
      documentId: doc.id,
      documentTitle: doc.title,
      requestId: req.id,
      ipAddress: req.ip || '127.0.0.1',
      userAgent: req.get('user-agent') || 'Unknown',
      details: {
        accessLevel: req.userAccessLevel,
        file_hash_sha256: doc.file_hash_sha256
      }
    });

    fileStream.pipe(res);
  } catch (err) {
    console.error('Download stream error:', err);
    res.status(500).json({
      error: 'Failed to retrieve document stream from private storage.',
      details: err.message
    });
  }
}

/**
 * Update document metadata (title, description, category, tags).
 * (Access check verified by authorizeDocumentAccess({ requiredPermission: 'edit' }))
 */
async function updateDocumentMetadata(req, res) {
  const doc = req.document;
  const { title, description, category_id, tags } = req.body;

  if (title !== undefined && (typeof title !== 'string' || title.trim().length === 0)) {
    return res.status(400).json({
      error: 'Document title cannot be empty.',
      code: 'INVALID_TITLE'
    });
  }

  const updates = {};
  if (title !== undefined) updates.title = title;
  if (description !== undefined) updates.description = description;
  if (category_id !== undefined) updates.category_id = category_id;
  if (tags !== undefined) updates.tags = parseTagsInput(tags);

  try {
    const updated = await db.updateDocument(doc.id, updates);

    await db.addAuditLog({
      userId: req.user.id,
      userEmail: req.user.email,
      action: 'DOCUMENT_METADATA_UPDATED',
      status: 'SUCCESS',
      documentId: doc.id,
      documentTitle: updated.title,
      requestId: req.id,
      ipAddress: req.ip || '127.0.0.1',
      userAgent: req.get('user-agent') || 'Unknown',
      details: {
        updatedFields: updates,
        accessLevel: req.userAccessLevel
      }
    });

    res.json({
      message: 'Document metadata updated successfully.',
      document: sanitizeDocumentOutput(updated)
    });
  } catch (err) {
    console.error('Update document error:', err);
    res.status(500).json({
      error: 'Failed to update document metadata.',
      details: err.message
    });
  }
}

/**
 * Delete document (soft-delete).
 * (Access check verified by authorizeDocumentAccess({ allowOwnerOnly: true }))
 */
async function deleteDocument(req, res) {
  const doc = req.document;

  try {
    await db.softDeleteDocument(doc.id);

    await db.addAuditLog({
      userId: req.user.id,
      userEmail: req.user.email,
      action: 'DOCUMENT_DELETED',
      status: 'SUCCESS',
      documentId: doc.id,
      documentTitle: doc.title,
      requestId: req.id,
      ipAddress: req.ip || '127.0.0.1',
      userAgent: req.get('user-agent') || 'Unknown',
      details: { softDelete: true }
    });

    res.json({
      message: 'Document deleted successfully.',
      documentId: doc.id
    });
  } catch (err) {
    console.error('Delete document error:', err);
    res.status(500).json({ error: 'Failed to delete document.' });
  }
}

module.exports = {
  uploadDocument,
  listDocuments,
  getDocumentById,
  downloadDocument,
  updateDocumentMetadata,
  deleteDocument
};
