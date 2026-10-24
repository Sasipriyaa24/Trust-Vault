/**
 * TrustVault Enterprise Audit Sanitizer & Anti-Log-Injection Engine
 * 
 * Enforces strict security boundaries:
 * 1. Log Injection Defense: Strips CRLF (\r, \n) and ASCII control characters ([\x00-\x1F\x7F])
 *    to prevent log forging, carriage return injection, and terminal escape sequence poisoning.
 * 2. Secret Redaction: Automatically scrubs passwords, session tokens, authorization headers,
 *    cookies, and raw binary file contents.
 * 3. Bounded Payload Size: Prevents Denial of Service via oversized metadata payloads.
 */

const SENSITIVE_KEYS_REGEX = /^(password|passwd|pass|token|secret|authorization|auth|bearer|cookie|credential|credit_card|private_key|salt|file_buffer|buffer|filebytes|raw_file|content|body)$/i;

/**
 * Sanitizes a single string against CRLF and control-character log injection.
 * Truncates output to maxLength to prevent storage exhaustion attacks.
 */
function sanitizeString(val, maxLength = 500) {
  if (val === null || val === undefined) return '';
  const str = String(val);
  // Strip control characters (0x00-0x1F, 0x7F) including \r and \n to prevent CRLF injection
  const cleaned = str.replace(/[\x00-\x1F\x7F]/g, ' ').replace(/\s+/g, ' ').trim();
  if (cleaned.length > maxLength) {
    return cleaned.substring(0, maxLength) + '...[TRUNCATED]';
  }
  return cleaned;
}

/**
 * Recursively sanitizes an audit details object.
 * Strips sensitive credential keys and cleans nested string values.
 */
function sanitizeAuditDetails(details, depth = 0) {
  if (!details || typeof details !== 'object' || depth > 5) {
    if (typeof details === 'string') {
      return sanitizeString(details, 300);
    }
    return {};
  }

  // Handle Buffer or binary data
  if (Buffer.isBuffer(details)) {
    return '[REDACTED_BINARY_BUFFER]';
  }

  if (Array.isArray(details)) {
    return details.slice(0, 50).map(item => {
      if (typeof item === 'object' && item !== null) {
        return sanitizeAuditDetails(item, depth + 1);
      }
      return typeof item === 'string' ? sanitizeString(item, 200) : item;
    });
  }

  const sanitized = {};
  for (const [key, val] of Object.entries(details)) {
    // 1. Binary content redaction: Never log raw file bytes or binary buffers
    if (Buffer.isBuffer(val)) {
      sanitized[key] = '[REDACTED_BINARY_BUFFER]';
      continue;
    }

    // 2. Secret Redaction: Never log passwords, tokens, auth headers or secrets
    if (SENSITIVE_KEYS_REGEX.test(key)) {
      sanitized[key] = '[REDACTED_SENSITIVE_CREDENTIAL]';
      continue;
    }

    if (val === null || val === undefined) {
      sanitized[key] = val;
    } else if (typeof val === 'string') {
      sanitized[key] = sanitizeString(val, 500);
    } else if (typeof val === 'number' || typeof val === 'boolean') {
      sanitized[key] = val;
    } else if (typeof val === 'object') {
      sanitized[key] = sanitizeAuditDetails(val, depth + 1);
    } else {
      sanitized[key] = sanitizeString(String(val), 200);
    }
  }

  return sanitized;
}

/**
 * Validates and sanitizes audit action names to strict alphanumeric uppercase identifiers.
 */
function sanitizeAction(action) {
  if (!action || typeof action !== 'string') return 'UNKNOWN_ACTION';
  const cleaned = action.toUpperCase().replace(/[^A-Z0-9_]/g, '_').substring(0, 64);
  return cleaned || 'UNKNOWN_ACTION';
}

/**
 * Validates and normalizes audit status outcome.
 */
function sanitizeStatus(status) {
  if (!status || typeof status !== 'string') return 'SUCCESS';
  const upper = status.toUpperCase().trim();
  if (['SUCCESS', 'DENIED', 'ERROR'].includes(upper)) {
    return upper;
  }
  return 'SUCCESS';
}

module.exports = {
  sanitizeString,
  sanitizeAuditDetails,
  sanitizeAction,
  sanitizeStatus
};
