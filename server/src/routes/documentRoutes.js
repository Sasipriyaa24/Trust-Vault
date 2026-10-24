const express = require('express');
const router = express.Router();
const documentController = require('../controllers/documentController');
const { authenticateToken } = require('../middleware/auth');
const { authorizeDocumentAccess } = require('../middleware/roles');
const { uploadMiddleware } = require('../middleware/upload');

// All document routes require authenticated user
router.use(authenticateToken);

// Document upload: Multer handles memory buffer & magic bytes check
router.post('/', uploadMiddleware, documentController.uploadDocument);

// List/Search accessible documents
router.get('/', documentController.listDocuments);

// Document metadata reading: Enforces object-level permission & logs success/denial
router.get(
  '/:id',
  authorizeDocumentAccess({ requiredPermission: 'read' }),
  documentController.getDocumentById
);

// Zero-Trust Document Download Proxy: Streams directly from private storage
router.get(
  '/:id/download',
  authorizeDocumentAccess({ requiredPermission: 'read' }),
  documentController.downloadDocument
);

// Update document metadata (title, description, category): Requires owner or 'edit' permission
router.patch(
  '/:id',
  authorizeDocumentAccess({ requiredPermission: 'edit' }),
  documentController.updateDocumentMetadata
);

// Soft delete: Strictly requires document owner
router.delete(
  '/:id',
  authorizeDocumentAccess({ allowOwnerOnly: true }),
  documentController.deleteDocument
);

module.exports = router;
