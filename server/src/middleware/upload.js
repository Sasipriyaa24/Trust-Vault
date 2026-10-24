const multer = require('multer');
const path = require('path');
const config = require('../config/env');
const db = require('../db/db');

// In-memory buffer storage
const memoryStorage = multer.memoryStorage();

// Allowed MIME types mapped to expected file signatures (Magic Bytes)
const MAGIC_SIGNATURES = {
  // PDF: %PDF (25 50 44 46)
  'application/pdf': [
    [0x25, 0x50, 0x44, 0x46]
  ],
  // PNG: 89 50 4E 47 0D 0A 1A 0A
  'image/png': [
    [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]
  ],
  // JPEG: FF D8 FF
  'image/jpeg': [
    [0xFF, 0xD8, 0xFF]
  ],
  'image/jpg': [
    [0xFF, 0xD8, 0xFF]
  ],
  'image/pjpeg': [
    [0xFF, 0xD8, 0xFF]
  ],
  // DOCX / XLSX (ZIP-based): PK.. (50 4B 03 04)
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': [
    [0x50, 0x4B, 0x03, 0x04]
  ],
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': [
    [0x50, 0x4B, 0x03, 0x04]
  ],
  // Plain text (must NOT contain null bytes or executable headers)
  'text/plain': []
};

// Forbidden extensions that are dangerous or could contain active scripts
const FORBIDDEN_EXTENSIONS = new Set([
  '.exe', '.bat', '.cmd', '.sh', '.bash', '.bin', '.dll', '.so',
  '.svg', '.xml', '.html', '.htm', '.xhtml', '.js', '.mjs', '.php',
  '.py', '.rb', '.pl', '.vbs', '.ps1', '.jar', '.war', '.cgi'
]);

// Allowed extensions
const ALLOWED_EXTENSIONS = new Set([
  '.pdf', '.png', '.jpg', '.jpeg', '.docx', '.xlsx', '.txt'
]);

/**
 * Sanitizes original filename: strips path traversal, removes null bytes and control chars.
 */
function sanitizeFilename(filename) {
  if (!filename) return 'unnamed_file.bin';
  // Strip path traversal and directory separators
  const base = path.basename(filename);
  // Remove null bytes and control characters
  return base.replace(/[\x00-\x1F\x7F<>:"/\\|?*]/g, '_').trim();
}

/**
 * Validates buffer magic bytes against declared MIME type.
 */
function verifyMagicBytes(buffer, mimeType) {
  if (!buffer || buffer.length === 0) return false;

  // Check for dangerous executable signatures first (defense in depth)
  // Windows MZ header (4D 5A)
  if (buffer.length >= 2 && buffer[0] === 0x4D && buffer[1] === 0x5A) {
    return false;
  }
  // Linux ELF header (7F 45 4C 46)
  if (buffer.length >= 4 && buffer[0] === 0x7F && buffer[1] === 0x45 && buffer[2] === 0x4C && buffer[3] === 0x46) {
    return false;
  }

  // Strip charset or other parameters, e.g. "text/plain; charset=utf-8" -> "text/plain"
  const cleanMime = (mimeType || '').split(';')[0].trim().toLowerCase();

  // Text files: ensure no null bytes in the first 1024 bytes
  if (cleanMime === 'text/plain') {
    for (let i = 0; i < Math.min(buffer.length, 1024); i++) {
      if (buffer[i] === 0x00) return false; // Null byte indicates binary
    }
    return true;
  }

  // Map known aliases
  const mimeMap = {
    'application/x-pdf': 'application/pdf',
    'image/pjpeg': 'image/jpeg',
    'image/jpg': 'image/jpeg',
    'application/x-zip-compressed': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/zip': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
  };
  const targetMime = mimeMap[cleanMime] || cleanMime;

  let signatures = MAGIC_SIGNATURES[targetMime];

  // If MIME type is generic (e.g. application/octet-stream or empty), check all allowed binary signatures
  if (!signatures && (cleanMime === 'application/octet-stream' || !cleanMime)) {
    signatures = [
      [0x25, 0x50, 0x44, 0x46], // PDF
      [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], // PNG
      [0xFF, 0xD8, 0xFF], // JPEG
      [0x50, 0x4B, 0x03, 0x04] // DOCX / XLSX
    ];
  }

  if (!signatures) return false;

  return signatures.some(signature => {
    if (buffer.length < signature.length) return false;
    for (let i = 0; i < signature.length; i++) {
      if (buffer[i] !== signature[i]) return false;
    }
    return true;
  });
}

// Multer upload middleware: Accepts either 'file' or 'document' field name
const multerUpload = multer({
  storage: memoryStorage,
  limits: {
    fileSize: config.maxFileSizeBytes, // 10MB
    files: 5
  },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();

    // Check forbidden extensions (e.g. .svg, .exe, .html)
    if (FORBIDDEN_EXTENSIONS.has(ext)) {
      return cb(new Error(`Security Alert: File type ${ext} is prohibited due to security policy.`));
    }

    if (!ALLOWED_EXTENSIONS.has(ext)) {
      return cb(new Error(`Unsupported file type ${ext}. Allowed formats: PDF, PNG, JPG, DOCX, XLSX, TXT.`));
    }

    cb(null, true);
  }
}).fields([
  { name: 'file', maxCount: 1 },
  { name: 'document', maxCount: 1 }
]);

/**
 * Express middleware that wraps multer and performs deep buffer magic byte inspection.
 */
function uploadMiddleware(req, res, next) {
  multerUpload(req, res, async (err) => {
    // Normalize req.file from fields upload
    if (!req.file && req.files) {
      req.file = req.files['file']?.[0] || req.files['document']?.[0];
    }
    if (err) {
      if (err.code === 'LIMIT_FILE_SIZE') {
        await db.addAuditLog({
          userId: req.user?.id || null,
          userEmail: req.user?.email || null,
          action: 'DOCUMENT_UPLOAD_DENIED',
          status: 'DENIED',
          requestId: req.id,
          ipAddress: req.ip || '127.0.0.1',
          userAgent: req.get('user-agent') || 'Unknown',
          details: { reason: 'File exceeds maximum size limit (10MB)' }
        });
        return res.status(400).json({
          error: 'File size exceeds maximum allowed limit of 10MB',
          code: 'FILE_TOO_LARGE'
        });
      }

      await db.addAuditLog({
        userId: req.user?.id || null,
        userEmail: req.user?.email || null,
        action: 'DOCUMENT_UPLOAD_DENIED',
        status: 'DENIED',
        requestId: req.id,
        ipAddress: req.ip || '127.0.0.1',
        userAgent: req.get('user-agent') || 'Unknown',
        details: { reason: err.message }
      });
      return res.status(400).json({
        error: err.message,
        code: 'FILE_VALIDATION_ERROR'
      });
    }

    if (!req.file) {
      return res.status(400).json({
        error: 'No file uploaded. Please attach a document file.',
        code: 'MISSING_FILE'
      });
    }

    // Reject empty files
    if (!req.file.buffer || req.file.buffer.length === 0) {
      await db.addAuditLog({
        userId: req.user?.id || null,
        userEmail: req.user?.email || null,
        action: 'DOCUMENT_UPLOAD_DENIED',
        status: 'DENIED',
        requestId: req.id,
        ipAddress: req.ip || '127.0.0.1',
        userAgent: req.get('user-agent') || 'Unknown',
        details: { reason: 'Uploaded file is empty (0 bytes)' }
      });
      return res.status(400).json({
        error: 'Uploaded file cannot be empty (0 bytes).',
        code: 'EMPTY_FILE'
      });
    }

    // Sanitize filename
    req.file.sanitizedFilename = sanitizeFilename(req.file.originalname);

    // Deep Magic Byte Inspection
    const isValidSignature = verifyMagicBytes(req.file.buffer, req.file.mimetype);
    if (!isValidSignature) {
      await db.addAuditLog({
        userId: req.user?.id || null,
        userEmail: req.user?.email || null,
        action: 'MALICIOUS_UPLOAD_ATTEMPT_BLOCKED',
        status: 'DENIED',
        requestId: req.id,
        ipAddress: req.ip || '127.0.0.1',
        userAgent: req.get('user-agent') || 'Unknown',
        details: {
          declaredMime: req.file.mimetype,
          filename: req.file.originalname,
          reason: 'File contents do not match declared file signature (Magic Bytes mismatch or executable payload)'
        }
      });
      return res.status(400).json({
        error: 'Security Verification Failed: The file binary header does not match its declared type. Upload rejected.',
        code: 'MAGIC_BYTES_MISMATCH'
      });
    }

    next();
  });
}

module.exports = {
  uploadMiddleware,
  sanitizeFilename,
  verifyMagicBytes
};
