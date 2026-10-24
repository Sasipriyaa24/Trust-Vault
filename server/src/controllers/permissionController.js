const db = require('../db/db');

/**
 * List all users with granted permissions on this document (Owner only).
 */
async function getPermissions(req, res) {
  const doc = req.document;

  try {
    const permissions = await db.getPermissionsForDocument(doc.id);
    res.json({
      document_id: doc.id,
      document_title: doc.title,
      total_grants: permissions.length,
      permissions
    });
  } catch (err) {
    console.error('Get permissions error:', err);
    res.status(500).json({ error: 'Failed to retrieve permissions.' });
  }
}

/**
 * Grant named read or edit permission to another user (Owner only).
 */
async function grantPermission(req, res) {
  const doc = req.document;
  const { user_email, user_id, permission_level } = req.body;

  if (!permission_level || !['read', 'edit'].includes(permission_level)) {
    return res.status(400).json({
      error: "Invalid permission level. Must be 'read' or 'edit'.",
      code: 'INVALID_PERMISSION_LEVEL'
    });
  }

  try {
    let targetProfile = null;
    if (user_id) {
      targetProfile = await db.getProfileById(user_id);
    } else if (user_email) {
      targetProfile = await db.getProfileByEmail(user_email);
    }

    if (!targetProfile) {
      return res.status(404).json({
        error: 'Target user not found. Please provide a valid registered user email or ID.',
        code: 'TARGET_USER_NOT_FOUND'
      });
    }

    if (!targetProfile.is_active) {
      return res.status(400).json({
        error: 'Cannot grant permission: The target user account is deactivated or suspended.',
        code: 'TARGET_USER_DEACTIVATED'
      });
    }

    if (targetProfile.id === doc.owner_id) {
      return res.status(400).json({
        error: 'Cannot grant permission: The specified user is already the document owner.',
        code: 'USER_IS_OWNER'
      });
    }

    const grant = await db.grantPermission({
      documentId: doc.id,
      userId: targetProfile.id,
      permissionLevel: permission_level,
      grantedBy: req.user.id
    });

    await db.addAuditLog({
      userId: req.user.id,
      userEmail: req.user.email,
      action: 'PERMISSION_GRANTED',
      status: 'SUCCESS',
      documentId: doc.id,
      documentTitle: doc.title,
      requestId: req.id,
      ipAddress: req.ip || '127.0.0.1',
      userAgent: req.get('user-agent') || 'Unknown',
      details: {
        targetUserId: targetProfile.id,
        targetUserEmail: targetProfile.email,
        permissionLevel: permission_level
      }
    });

    res.status(201).json({
      message: `Successfully granted '${permission_level}' access to ${targetProfile.email}`,
      grant: {
        id: grant.id,
        user_id: targetProfile.id,
        user_email: targetProfile.email,
        user_name: targetProfile.full_name,
        permission_level: grant.permission_level,
        created_at: grant.created_at
      }
    });
  } catch (err) {
    console.error('Grant permission error:', err);
    res.status(500).json({
      error: 'Failed to grant permission.',
      details: err.message
    });
  }
}

/**
 * Revoke permission from a user immediately (Owner only).
 */
async function revokePermission(req, res) {
  const doc = req.document;
  const targetUserId = req.params.targetUserId;

  if (targetUserId === doc.owner_id) {
    return res.status(400).json({
      error: 'Cannot revoke permission from the document owner.',
      code: 'CANNOT_REVOKE_OWNER'
    });
  }

  try {
    const targetProfile = await db.getProfileById(targetUserId);

    const revoked = await db.revokePermission(doc.id, targetUserId);
    if (!revoked) {
      return res.status(404).json({
        error: 'No active permission found for this user on the document.',
        code: 'PERMISSION_NOT_FOUND'
      });
    }

    await db.addAuditLog({
      userId: req.user.id,
      userEmail: req.user.email,
      action: 'PERMISSION_REVOKED',
      status: 'SUCCESS',
      documentId: doc.id,
      documentTitle: doc.title,
      requestId: req.id,
      ipAddress: req.ip || '127.0.0.1',
      userAgent: req.get('user-agent') || 'Unknown',
      details: {
        revokedUserId: targetUserId,
        revokedUserEmail: targetProfile ? targetProfile.email : 'Unknown'
      }
    });

    res.json({
      message: `Access successfully revoked for user ${targetProfile ? targetProfile.email : targetUserId}. Immediate revocation enforced.`,
      document_id: doc.id,
      revoked_user_id: targetUserId
    });
  } catch (err) {
    console.error('Revoke permission error:', err);
    res.status(500).json({ error: 'Failed to revoke permission.' });
  }
}

module.exports = {
  getPermissions,
  grantPermission,
  revokePermission
};
