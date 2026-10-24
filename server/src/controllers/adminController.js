const db = require('../db/db');
const { verifyAuditChain } = require('../services/hashChainService');

/**
 * Retrieve global audit trail with filtering and pagination (Admin only).
 */
async function getAuditLogs(req, res) {
  try {
    const {
      limit = 100,
      offset = 0,
      action,
      status,
      outcome,
      userId,
      actor,
      document,
      documentId,
      dateFrom,
      dateTo,
      requestId
    } = req.query;

    const result = await db.getAuditLogs({
      limit: parseInt(limit, 10),
      offset: parseInt(offset, 10),
      action,
      status,
      outcome,
      userId,
      actor,
      document,
      documentId,
      dateFrom,
      dateTo,
      requestId
    });

    res.json(result);
  } catch (err) {
    console.error('Get audit logs error:', err);
    res.status(500).json({ error: 'Failed to retrieve audit records.' });
  }
}

/**
 * Cryptographically verify the entire audit log hash chain (Admin only).
 */
async function verifyAuditIntegrity(req, res) {
  try {
    const logs = await db.getAllAuditLogsForVerification();
    const verification = verifyAuditChain(logs);

    await db.addAuditLog({
      userId: req.user.id,
      userEmail: req.user.email,
      action: 'AUDIT_INTEGRITY_VERIFIED',
      status: verification.isValid ? 'SUCCESS' : 'DENIED',
      requestId: req.id,
      ipAddress: req.ip || '127.0.0.1',
      userAgent: req.get('user-agent') || 'Unknown',
      details: {
        checkedCount: verification.checkedCount,
        isValid: verification.isValid,
        compromisedAtId: verification.compromisedAtId
      }
    });

    res.json({
      timestamp: new Date().toISOString(),
      ...verification
    });
  } catch (err) {
    console.error('Verify audit integrity error:', err);
    res.status(500).json({ error: 'Failed to verify audit ledger.' });
  }
}

/**
 * Security Demonstration Hook:
 * Artificially alters a past log record to demonstrate that the cryptographic verification
 * detects out-of-band database tampering.
 */
async function simulateTampering(req, res) {
  const { logId } = req.body;

  try {
    const idToTamper = logId ? parseInt(logId, 10) : 1;
    db.tamperAuditLogForTesting(idToTamper, {
      action: 'FORGED_AUDIT_ACTION_TAMPERED',
      details: { hacked: true, forged_by: 'adversary' }
    });

    res.json({
      message: `Audit log record ID ${idToTamper} tampered for testing. Run integrity verification now to see tamper detection!`,
      tamperedLogId: idToTamper
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}

/**
 * Restore tampered log record to original state (Admin only).
 */
async function restoreTampering(req, res) {
  const { logId } = req.body;

  try {
    const idToRestore = logId ? parseInt(logId, 10) : 1;
    db.restoreAuditLogForTesting(idToRestore);

    res.json({
      message: `Audit log record ID ${idToRestore} restored to original cryptographic state.`,
      restoredLogId: idToRestore
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}

/**
 * List all user profiles (Admin only).
 */
async function getUsers(req, res) {
  try {
    const profiles = await db.getAllProfiles();
    res.json({
      total: profiles.length,
      users: profiles
    });
  } catch (err) {
    console.error('Get users error:', err);
    res.status(500).json({ error: 'Failed to retrieve users.' });
  }
}

/**
 * Update user status (toggle active/suspended) or update system role (Admin only).
 */
async function updateUserStatus(req, res) {
  const { id } = req.params;
  const { is_active, system_role } = req.body;

  try {
    const targetUser = await db.getProfileById(id);
    if (!targetUser) {
      return res.status(404).json({ error: 'User not found.' });
    }

    // Prevent admin from deactivating self
    if (id === req.user.id && is_active === false) {
      return res.status(400).json({
        error: 'Security Policy: Administrators cannot deactivate their own active account.',
        code: 'CANNOT_DEACTIVATE_SELF'
      });
    }

    const updates = {};
    if (is_active !== undefined) updates.is_active = Boolean(is_active);
    if (system_role !== undefined) {
      if (!['administrator', 'document_owner', 'viewer'].includes(system_role)) {
        return res.status(400).json({ error: 'Invalid system role.' });
      }
      updates.system_role = system_role;
    }

    const updated = await db.updateProfile(id, updates);

    await db.addAuditLog({
      userId: req.user.id,
      userEmail: req.user.email,
      action: 'USER_PROFILE_ADMIN_MODIFIED',
      status: 'SUCCESS',
      requestId: req.id,
      ipAddress: req.ip || '127.0.0.1',
      userAgent: req.get('user-agent') || 'Unknown',
      details: {
        targetUserId: id,
        targetEmail: targetUser.email,
        modifications: updates
      }
    });

    res.json({
      message: 'User profile updated successfully.',
      user: updated
    });
  } catch (err) {
    console.error('Update user status error:', err);
    res.status(500).json({ error: 'Failed to update user status.' });
  }
}

module.exports = {
  getAuditLogs,
  verifyAuditIntegrity,
  simulateTampering,
  restoreTampering,
  getUsers,
  updateUserStatus
};
