const jwt = require('jsonwebtoken');
const config = require('../config/env');
const db = require('../db/db');

/**
 * Authentication Middleware:
 * Verifies Supabase JWT access token and queries authoritative database
 * to derive trusted user identity and role (never trust client payload).
 */
async function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    return res.status(401).json({
      error: 'Access Denied: Missing Authorization header',
      code: 'AUTH_HEADER_MISSING'
    });
  }

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return res.status(401).json({
      error: 'Access Denied: Malformed Authorization header. Format: Bearer <token>',
      code: 'AUTH_HEADER_MALFORMED'
    });
  }

  const token = parts[1];

  try {
    // Cryptographically verify token signature
    const decoded = jwt.verify(token, config.supabaseJwtSecret, {
      algorithms: ['HS256']
    });

    const userId = decoded.sub || decoded.id;
    if (!userId) {
      return res.status(401).json({
        error: 'Access Denied: Invalid token payload (missing subject claim)',
        code: 'INVALID_TOKEN_CLAIMS'
      });
    }

    // Server-Side Identity & Role Resolution from Authoritative Database
    const profile = await db.getProfileById(userId);
    if (!profile) {
      await db.addAuditLog({
        userId,
        userEmail: decoded.email || null,
        action: 'UNAUTHORIZED_ACCESS_ATTEMPT',
        status: 'DENIED',
        requestId: req.id,
        ipAddress: req.ip || '127.0.0.1',
        userAgent: req.get('user-agent') || 'Unknown',
        details: { reason: 'Token valid but user profile does not exist in database' }
      });

      return res.status(401).json({
        error: 'Access Denied: User profile does not exist',
        code: 'USER_NOT_FOUND'
      });
    }

    // Check account active status
    if (!profile.is_active) {
      await db.addAuditLog({
        userId: profile.id,
        userEmail: profile.email,
        action: 'DEACTIVATED_USER_ACCESS_BLOCKED',
        status: 'DENIED',
        requestId: req.id,
        ipAddress: req.ip || '127.0.0.1',
        userAgent: req.get('user-agent') || 'Unknown',
        details: { reason: 'Deactivated account attempted API operation' }
      });

      return res.status(403).json({
        error: 'Access Denied: Your account has been suspended or deactivated. Contact a security administrator.',
        code: 'ACCOUNT_DEACTIVATED'
      });
    }

    // Attach trusted server-derived identity
    req.user = {
      id: profile.id,
      email: profile.email,
      full_name: profile.full_name,
      system_role: profile.system_role, // Authoritative role from DB
      is_active: profile.is_active
    };

    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({
        error: 'Access Denied: Authentication token has expired. Please log in again.',
        code: 'TOKEN_EXPIRED'
      });
    }

    await db.addAuditLog({
      userId: null,
      userEmail: null,
      action: 'INVALID_TOKEN_REJECTED',
      status: 'DENIED',
      requestId: req.id,
      ipAddress: req.ip || '127.0.0.1',
      userAgent: req.get('user-agent') || 'Unknown',
      details: { error: err.name, path: req.originalUrl }
    });

    return res.status(401).json({
      error: 'Access Denied: Invalid or forged authentication token.',
      code: 'TOKEN_INVALID'
    });
  }
}

module.exports = {
  authenticateToken
};
