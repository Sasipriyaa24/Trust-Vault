const db = require('../db/db');

/**
 * Middleware to enforce platform-level system roles ('administrator', 'document_owner', 'viewer')
 */
function requireSystemRole(allowedRoles = []) {
  return async (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'Unauthorized: User not authenticated',
        code: 'UNAUTHENTICATED'
      });
    }

    if (!allowedRoles.includes(req.user.system_role)) {
      await db.addAuditLog({
        userId: req.user.id,
        userEmail: req.user.email,
        action: 'INSUFFICIENT_ROLE_ACCESS_DENIED',
        status: 'DENIED',
        requestId: req.id,
        ipAddress: req.ip || '127.0.0.1',
        userAgent: req.get('user-agent') || 'Unknown',
        details: {
          userRole: req.user.system_role,
          requiredRoles: allowedRoles,
          path: req.originalUrl
        }
      });

      return res.status(403).json({
        error: `Access Denied: Action requires one of the following roles: [${allowedRoles.join(', ')}]. Your current role is '${req.user.system_role}'.`,
        code: 'INSUFFICIENT_SYSTEM_ROLE'
      });
    }

    next();
  };
}

/**
 * Middleware for Object-Level Document Authorization.
 * Enforces Zero-Trust, No Administrator Blanket Read Bypass, and Live Revocation Checks.
 */
function authorizeDocumentAccess({ requiredPermission = 'read', allowOwnerOnly = false, allowAdminInspection = false } = {}) {
  return async (req, res, next) => {
    const documentId = req.params.id;
    const userId = req.user.id;

    if (!documentId || typeof documentId !== 'string') {
      return res.status(400).json({
        error: 'Invalid request: Document ID parameter is missing',
        code: 'MISSING_DOCUMENT_ID'
      });
    }

    // Prevent path traversal, null bytes, and malicious characters in document ID
    if (
      documentId.includes('..') ||
      documentId.includes('/') ||
      documentId.includes('\\') ||
      documentId.includes('\0') ||
      documentId.length > 100
    ) {
      await db.addAuditLog({
        userId: req.user?.id || null,
        userEmail: req.user?.email || null,
        action: 'MALICIOUS_INPUT_DETECTED',
        status: 'DENIED',
        requestId: req.id,
        ipAddress: req.ip || '127.0.0.1',
        userAgent: req.get('user-agent') || 'Unknown',
        details: {
          reason: 'Path traversal or control characters in document ID parameter',
          path: req.originalUrl
        }
      });

      return res.status(400).json({
        error: 'Invalid request: Malformed or dangerous document ID parameter.',
        code: 'INVALID_DOCUMENT_ID'
      });
    }

    try {
      const doc = await db.getDocumentById(documentId);
      if (!doc) {
        // Return 404 to avoid IDOR resource discovery/enumeration
        return res.status(404).json({
          error: 'Document not found or has been deleted',
          code: 'DOCUMENT_NOT_FOUND'
        });
      }

      const isOwner = doc.owner_id === userId;

      // 0. Permission Metadata Inspection (Document Owner or Security Administrator)
      if (allowAdminInspection) {
        if (isOwner) {
          req.document = doc;
          req.userAccessLevel = 'owner';
          return next();
        }

        if (req.user.system_role === 'administrator') {
          req.document = doc;
          req.userAccessLevel = 'admin_inspector';
          return next();
        }

        await db.addAuditLog({
          userId,
          userEmail: req.user.email,
          action: 'PERMISSION_INSPECTION_DENIED',
          status: 'DENIED',
          documentId: doc.id,
          documentTitle: doc.title,
          requestId: req.id,
          ipAddress: req.ip || '127.0.0.1',
          userAgent: req.get('user-agent') || 'Unknown',
          details: {
            attemptedOperation: req.method + ' ' + req.originalUrl,
            reason: 'Permission inspection requires document ownership or administrator role.'
          }
        });

        return res.status(403).json({
          error: 'Access Denied: Only the document owner or a security administrator can inspect permission metadata.',
          code: 'OWNER_ONLY_OPERATION'
        });
      }

      // 1. If operation requires owner exclusively (e.g. deletion, grant/revoke permissions)
      if (allowOwnerOnly) {
        if (!isOwner) {
          await db.addAuditLog({
            userId,
            userEmail: req.user.email,
            action: 'OWNER_PRIVILEGE_VIOLATION_BLOCKED',
            status: 'DENIED',
            documentId: doc.id,
            documentTitle: doc.title,
            requestId: req.id,
            ipAddress: req.ip || '127.0.0.1',
            userAgent: req.get('user-agent') || 'Unknown',
            details: {
              attemptedOperation: req.method + ' ' + req.originalUrl,
              reason: 'Only the designated document owner can perform this operation.'
            }
          });

          return res.status(403).json({
            error: 'Access Denied: Only the document owner can perform this operation.',
            code: 'OWNER_ONLY_OPERATION'
          });
        }

        req.document = doc;
        req.userAccessLevel = 'owner';
        return next();
      }

      // 2. If user is owner, grant full access
      if (isOwner) {
        req.document = doc;
        req.userAccessLevel = 'owner';
        return next();
      }

      // 3. For non-owners: Live query on document_permissions table (Instant Revocation Guarantee)
      const userPerm = await db.getUserPermissionOnDocument(doc.id, userId);

      // Check: Does user have any active permission?
      if (!userPerm) {
        // Explicitly check for administrator attempt without delegation
        const isAdmin = req.user.system_role === 'administrator';
        const actionLabel = isAdmin ? 'ADMIN_BLANKET_BYPASS_BLOCKED' : 'DOCUMENT_ACCESS_DENIED';

        await db.addAuditLog({
          userId,
          userEmail: req.user.email,
          action: actionLabel,
          status: 'DENIED',
          documentId: doc.id,
          documentTitle: doc.title,
          requestId: req.id,
          ipAddress: req.ip || '127.0.0.1',
          userAgent: req.get('user-agent') || 'Unknown',
          details: {
            reason: isAdmin
              ? 'Security Policy Enforcement: Administrators do not have a blanket read bypass on private enterprise documents without explicit owner permission.'
              : 'User does not possess active read/edit permission on this document.',
            requestedPermission: requiredPermission
          }
        });

        return res.status(403).json({
          error: isAdmin
            ? 'Access Denied: Enterprise Security Policy blocks administrator blanket access to document contents. You must be explicitly granted permission by the owner.'
            : 'Access Denied: You do not have permission to access this document.',
          code: 'DOCUMENT_ACCESS_DENIED'
        });
      }

      // 4. Verify permission level ('read' vs 'edit')
      if (requiredPermission === 'edit' && userPerm.permission_level !== 'edit') {
        await db.addAuditLog({
          userId,
          userEmail: req.user.email,
          action: 'DOCUMENT_EDIT_PERMISSION_DENIED',
          status: 'DENIED',
          documentId: doc.id,
          documentTitle: doc.title,
          requestId: req.id,
          ipAddress: req.ip || '127.0.0.1',
          userAgent: req.get('user-agent') || 'Unknown',
          details: {
            currentPermission: userPerm.permission_level,
            requiredPermission: 'edit'
          }
        });

        return res.status(403).json({
          error: 'Access Denied: Your permission is limited to Read-Only.',
          code: 'INSUFFICIENT_DOCUMENT_PERMISSION'
        });
      }

      // Authorized! Attach document and level to request
      req.document = doc;
      req.userAccessLevel = userPerm.permission_level;
      next();
    } catch (err) {
      console.error('Authorizer exception:', err);
      // Fail closed
      return res.status(500).json({
        error: 'Security Failure: Unable to verify document authorization. Request failed closed.',
        code: 'FAIL_CLOSED_ERROR'
      });
    }
  };
}

module.exports = {
  requireSystemRole,
  authorizeDocumentAccess
};
