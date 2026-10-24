const crypto = require('crypto');
const config = require('../config/env');

const GENESIS_HASH = '0'.repeat(64);

/**
 * Standardize details object into a deterministic string representation
 */
function serializeDetails(details) {
  if (!details || typeof details !== 'object') {
    return '{}';
  }
  const keys = Object.keys(details).sort();
  const sortedObj = {};
  for (const k of keys) {
    sortedObj[k] = details[k];
  }
  return JSON.stringify(sortedObj);
}

/**
 * Computes cryptographic hash for an audit log entry chained to its predecessor.
 */
function computeAuditHash({
  previousHash,
  id,
  timestamp,
  userId,
  action,
  status,
  documentId,
  requestId,
  details,
}) {
  const prev = previousHash || GENESIS_HASH;
  const ts = new Date(timestamp).toISOString();
  const uid = userId || 'ANONYMOUS';
  const act = action || 'UNKNOWN';
  const stat = status || 'SUCCESS';
  const docId = documentId || 'NONE';
  const reqId = requestId || 'NONE';
  const det = serializeDetails(details);

  const payload = [prev, id, ts, uid, act, stat, docId, reqId, det].join('::');

  return crypto
    .createHmac('sha256', config.auditHmacSecret)
    .update(payload)
    .digest('hex');
}

/**
 * Verifies the integrity of an ordered sequence of audit logs.
 * Returns detailed diagnostics on whether the ledger is pristine or tampered.
 */
function verifyAuditChain(logs) {
  if (!logs || logs.length === 0) {
    return {
      isValid: true,
      checkedCount: 0,
      compromisedAtId: null,
      message: 'Audit ledger is empty. Chain is intact.',
    };
  }

  // Ensure logs are sorted by ID ascending
  const sorted = [...logs].sort((a, b) => Number(a.id) - Number(b.id));

  for (let i = 0; i < sorted.length; i++) {
    const current = sorted[i];

    // Check previous hash pointer
    if (i === 0) {
      if (current.previous_hash !== GENESIS_HASH) {
        return {
          isValid: false,
          checkedCount: i + 1,
          compromisedAtId: current.id,
          message: `Genesis block tampering detected at ID ${current.id}. Expected genesis hash ${GENESIS_HASH}, found ${current.previous_hash}.`,
        };
      }
    } else {
      const prev = sorted[i - 1];
      if (current.previous_hash !== prev.current_hash) {
        return {
          isValid: false,
          checkedCount: i + 1,
          compromisedAtId: current.id,
          message: `Hash chain break detected between ID ${prev.id} and ID ${current.id}. Previous hash pointer mismatch.`,
        };
      }
    }

    // Check current hash HMAC computation
    const expectedHash = computeAuditHash({
      previousHash: current.previous_hash,
      id: current.id,
      timestamp: current.timestamp,
      userId: current.user_id,
      action: current.action,
      status: current.status,
      documentId: current.document_id,
      requestId: current.request_id,
      details: current.details,
    });

    if (current.current_hash !== expectedHash) {
      return {
        isValid: false,
        checkedCount: i + 1,
        compromisedAtId: current.id,
        message: `Cryptographic signature mismatch at ID ${current.id}. Record content has been modified out-of-band!`,
      };
    }
  }

  return {
    isValid: true,
    checkedCount: sorted.length,
    compromisedAtId: null,
    message: `All ${sorted.length} audit records verified cryptographically. Chain is authentic and unbroken.`,
  };
}

module.exports = {
  GENESIS_HASH,
  computeAuditHash,
  verifyAuditChain,
};
