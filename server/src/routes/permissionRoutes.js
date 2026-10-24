const express = require('express');
const router = express.Router({ mergeParams: true });
const permissionController = require('../controllers/permissionController');
const { authenticateToken } = require('../middleware/auth');
const { authorizeDocumentAccess } = require('../middleware/roles');

// Permissions management strictly requires authentication
router.use(authenticateToken);

// List granted permissions for this document: Document Owner or Security Administrator (for compliance/audit inspection)
router.get('/', authorizeDocumentAccess({ allowAdminInspection: true }), permissionController.getPermissions);

// Grant named read or edit permission: Document Owner ONLY
router.post('/', authorizeDocumentAccess({ allowOwnerOnly: true }), permissionController.grantPermission);

// Revoke access immediately: Document Owner ONLY
router.delete('/:targetUserId', authorizeDocumentAccess({ allowOwnerOnly: true }), permissionController.revokePermission);

module.exports = router;
