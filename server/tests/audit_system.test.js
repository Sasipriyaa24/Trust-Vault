const request = require('supertest');
const app = require('../src/app');
const db = require('../src/db/db');
const { generateToken } = require('../src/controllers/authController');
const { verifyAuditChain } = require('../src/services/hashChainService');
const { sanitizeAuditDetails, sanitizeString } = require('../src/utils/auditSanitizer');

describe('🛡️ TrustVault Audit System & Security Integrity Test Suite', () => {
  let adminToken;
  let ownerToken;
  let aliceToken;
  let viewerToken;

  const adminUser = {
    id: 'u1111111-1111-1111-1111-111111111111',
    email: 'admin@trustvault.internal',
    full_name: 'Security Administrator',
    system_role: 'administrator'
  };

  const ownerUser = {
    id: 'u2222222-2222-2222-2222-222222222222',
    email: 'owner@trustvault.internal',
    full_name: 'Primary Document Owner',
    system_role: 'document_owner'
  };

  const aliceUser = {
    id: 'u3333333-3333-3333-3333-333333333333',
    email: 'alice@trustvault.internal',
    full_name: 'Alice Cooper (Collaborator)',
    system_role: 'document_owner'
  };

  const viewerUser = {
    id: 'u4444444-4444-4444-4444-444444444444',
    email: 'viewer@trustvault.internal',
    full_name: 'External Audit Viewer',
    system_role: 'viewer'
  };

  const seededDocId = 'd1111111-1111-1111-1111-111111111111';

  beforeEach(() => {
    db.reset();
    adminToken = generateToken(adminUser);
    ownerToken = generateToken(ownerUser);
    aliceToken = generateToken(aliceUser);
    viewerToken = generateToken(viewerUser);
  });

  // ===========================================================================
  // 1. AUTHORIZED AUDIT ENDPOINT ACCESS & ISOLATION
  // ===========================================================================
  describe('1. Audit Endpoint Authorization & Access Control', () => {
    it('should reject unauthenticated requests to /api/admin/audit-logs with 401', async () => {
      const res = await request(app).get('/api/admin/audit-logs');
      expect(res.status).toBe(401);
      expect(res.body.code).toBe('AUTH_HEADER_MISSING');
    });

    it('should reject viewer role from reading audit logs with 403 and record unauthorized attempt', async () => {
      const res = await request(app)
        .get('/api/admin/audit-logs')
        .set('Authorization', `Bearer ${viewerToken}`)
        .set('X-Request-ID', 'req-viewer-unauthorized-audit');

      expect(res.status).toBe(403);
      expect(res.body.code).toBe('INSUFFICIENT_SYSTEM_ROLE');

      // Verify the denied attempt was recorded in the audit trail
      const logs = await db.getAllAuditLogsForVerification();
      const deniedLog = logs.find(l => l.request_id === 'req-viewer-unauthorized-audit');
      expect(deniedLog).toBeDefined();
      expect(deniedLog.action).toBe('INSUFFICIENT_ROLE_ACCESS_DENIED');
      expect(deniedLog.status).toBe('DENIED');
      expect(deniedLog.user_id).toBe(viewerUser.id);
    });

    it('should reject document_owner role from reading audit logs with 403', async () => {
      const res = await request(app)
        .get('/api/admin/audit-logs')
        .set('Authorization', `Bearer ${ownerToken}`);

      expect(res.status).toBe(403);
      expect(res.body.code).toBe('INSUFFICIENT_SYSTEM_ROLE');
    });

    it('should reject non-admin from running cryptographic audit chain verification', async () => {
      const res = await request(app)
        .get('/api/admin/audit-logs/verify')
        .set('Authorization', `Bearer ${aliceToken}`);

      expect(res.status).toBe(403);
      expect(res.body.code).toBe('INSUFFICIENT_SYSTEM_ROLE');
    });

    it('should allow administrator to retrieve audit logs with pagination and total count', async () => {
      const res = await request(app)
        .get('/api/admin/audit-logs?limit=10&offset=0')
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(200);
      expect(res.body.logs).toBeDefined();
      expect(Array.isArray(res.body.logs)).toBe(true);
      expect(res.body.total).toBeGreaterThanOrEqual(1);
      expect(res.body.logs[0].current_hash).toBeDefined();
      expect(res.body.logs[0].previous_hash).toBeDefined();
    });
  });

  // ===========================================================================
  // 2. APPEND-ONLY IMMUTABILITY & TAMPER PREVENTION
  // ===========================================================================
  describe('2. Append-Only Immutability & Modification Rejection', () => {
    it('should throw security exception when attempting application-level updateAuditLog', () => {
      expect(() => {
        db.updateAuditLog();
      }).toThrow(/SECURITY VIOLATION: audit_logs is an append-only ledger/);
    });

    it('should throw security exception when attempting application-level deleteAuditLog', () => {
      expect(() => {
        db.deleteAuditLog();
      }).toThrow(/SECURITY VIOLATION: audit_logs is an append-only ledger/);
    });

    it('should return 404 / route not found for any HTTP mutation attempt on audit records', async () => {
      const resPut = await request(app)
        .put('/api/admin/audit-logs/1')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ action: 'TAMPERED' });
      expect(resPut.status).toBe(404);

      const resDelete = await request(app)
        .delete('/api/admin/audit-logs/1')
        .set('Authorization', `Bearer ${adminToken}`);
      expect(resDelete.status).toBe(404);
    });
  });

  // ===========================================================================
  // 3. CRYPTOGRAPHIC HASH CHAIN & TAMPER DETECTION
  // ===========================================================================
  describe('3. Cryptographic Hash Chain & Tamper Detection', () => {
    it('should verify that an untampered audit chain is cryptographically valid', async () => {
      const res = await request(app)
        .get('/api/admin/audit-logs/verify')
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(200);
      expect(res.body.isValid).toBe(true);
      expect(res.body.compromisedAtId).toBeNull();
      expect(res.body.checkedCount).toBeGreaterThanOrEqual(1);
    });

    it('should DETECT out-of-band tampering when a past audit record action is altered', async () => {
      // 1. Add some audit entries
      await db.addAuditLog({
        userId: ownerUser.id,
        userEmail: ownerUser.email,
        action: 'DOCUMENT_UPLOAD_SUCCESS',
        status: 'SUCCESS',
        requestId: 'req-chain-test-1',
        details: { note: 'legitimate entry' }
      });

      // 2. Tamper with record ID 1 out-of-band
      db.tamperAuditLogForTesting(1, { action: 'FORGED_AUDIT_ACTION_TAMPERED' });

      // 3. Run verification
      const verifyRes = await request(app)
        .get('/api/admin/audit-logs/verify')
        .set('Authorization', `Bearer ${adminToken}`);

      expect(verifyRes.status).toBe(200);
      expect(verifyRes.body.isValid).toBe(false);
      expect(verifyRes.body.compromisedAtId).toBe(1);
      expect(verifyRes.body.message).toContain('Cryptographic signature mismatch');
    });

    it('should DETECT tampering when an adversary modifies the previous_hash link', async () => {
      // 1. Add record
      const entry2 = await db.addAuditLog({
        userId: ownerUser.id,
        userEmail: ownerUser.email,
        action: 'DOCUMENT_DOWNLOAD_ALLOWED',
        status: 'SUCCESS',
        requestId: 'req-chain-test-2',
        details: { note: 'second block' }
      });

      // 2. Break previous hash link on entry 2
      db.tamperAuditLogForTesting(entry2.id, { previous_hash: '1'.repeat(64) });

      // 3. Verify detection
      const logs = await db.getAllAuditLogsForVerification();
      const verification = verifyAuditChain(logs);

      expect(verification.isValid).toBe(false);
      expect(verification.compromisedAtId).toBe(entry2.id);
      expect(verification.message).toContain('Previous hash pointer mismatch');
    });

    it('should DETECT tampering when the genesis block previous hash is altered', async () => {
      // Tamper genesis block previous hash
      db.tamperAuditLogForTesting(1, { previous_hash: 'f'.repeat(64) });

      const logs = await db.getAllAuditLogsForVerification();
      const verification = verifyAuditChain(logs);

      expect(verification.isValid).toBe(false);
      expect(verification.compromisedAtId).toBe(1);
      expect(verification.message).toContain('Genesis block tampering detected');
    });
  });

  // ===========================================================================
  // 4. MISSING EVENTS ON DENIED ACCESS (ZERO-DROP AUDIT INTEGRITY)
  // ===========================================================================
  describe('4. Zero-Drop Audit Integrity on Denied Access Attempts', () => {
    it('should record audit event when login fails due to invalid credentials', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .set('X-Request-ID', 'req-login-fail-1')
        .send({ email: 'nonexistent@trustvault.internal', password: 'wrongpassword' });

      expect(res.status).toBe(401);

      const logs = await db.getAllAuditLogsForVerification();
      const loginFailLog = logs.find(l => l.request_id === 'req-login-fail-1');
      expect(loginFailLog).toBeDefined();
      expect(loginFailLog.action).toBe('USER_LOGIN_FAILED');
      expect(loginFailLog.status).toBe('DENIED');
      expect(loginFailLog.user_email).toBe('nonexistent@trustvault.internal');
      expect(loginFailLog.details.reason).toBe('User not found');
    });

    it('should record audit event when login is attempted with missing credentials', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .set('X-Request-ID', 'req-login-missing-creds')
        .send({ email: 'owner@trustvault.internal' }); // Missing password

      expect(res.status).toBe(400);

      const logs = await db.getAllAuditLogsForVerification();
      const auditEntry = logs.find(l => l.request_id === 'req-login-missing-creds');
      expect(auditEntry).toBeDefined();
      expect(auditEntry.action).toBe('USER_LOGIN_FAILED');
      expect(auditEntry.status).toBe('DENIED');
    });

    it('should record audit event when unauthorized user attempts to read another user document metadata', async () => {
      const res = await request(app)
        .get(`/api/documents/${seededDocId}`)
        .set('Authorization', `Bearer ${viewerToken}`)
        .set('X-Request-ID', 'req-idor-meta-denied');

      expect(res.status).toBe(403);

      const logs = await db.getAllAuditLogsForVerification();
      const auditLog = logs.find(l => l.request_id === 'req-idor-meta-denied');
      expect(auditLog).toBeDefined();
      expect(auditLog.action).toBe('DOCUMENT_ACCESS_DENIED');
      expect(auditLog.status).toBe('DENIED');
      expect(auditLog.user_id).toBe(viewerUser.id);
      expect(auditLog.document_id).toBe(seededDocId);
    });

    it('should record audit event when unauthorized user attempts to download document bytes', async () => {
      const res = await request(app)
        .get(`/api/documents/${seededDocId}/download`)
        .set('Authorization', `Bearer ${viewerToken}`)
        .set('X-Request-ID', 'req-idor-download-denied');

      expect(res.status).toBe(403);

      const logs = await db.getAllAuditLogsForVerification();
      const auditLog = logs.find(l => l.request_id === 'req-idor-download-denied');
      expect(auditLog).toBeDefined();
      expect(auditLog.action).toBe('DOCUMENT_ACCESS_DENIED');
      expect(auditLog.status).toBe('DENIED');
      expect(auditLog.user_id).toBe(viewerUser.id);
    });

    it('should record audit event when administrator attempts ungranted document read (admin blanket bypass blocked)', async () => {
      const res = await request(app)
        .get(`/api/documents/${seededDocId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .set('X-Request-ID', 'req-admin-bypass-blocked');

      expect(res.status).toBe(403);

      const logs = await db.getAllAuditLogsForVerification();
      const auditLog = logs.find(l => l.request_id === 'req-admin-bypass-blocked');
      expect(auditLog).toBeDefined();
      expect(auditLog.action).toBe('ADMIN_BLANKET_BYPASS_BLOCKED');
      expect(auditLog.status).toBe('DENIED');
      expect(auditLog.user_id).toBe(adminUser.id);
      expect(auditLog.details.reason).toContain('Administrators do not have a blanket read bypass');
    });

    it('should record audit event when read-only collaborator attempts to edit document metadata', async () => {
      // Grant read-only access to Alice
      await db.grantPermission({
        documentId: seededDocId,
        userId: aliceUser.id,
        permissionLevel: 'read',
        grantedBy: ownerUser.id
      });

      const res = await request(app)
        .patch(`/api/documents/${seededDocId}`)
        .set('Authorization', `Bearer ${aliceToken}`)
        .set('X-Request-ID', 'req-alice-unauthorized-edit')
        .send({ title: 'Hacked Title' });

      expect(res.status).toBe(403);

      const logs = await db.getAllAuditLogsForVerification();
      const editDeniedLog = logs.find(l => l.request_id === 'req-alice-unauthorized-edit');
      expect(editDeniedLog).toBeDefined();
      expect(editDeniedLog.action).toBe('DOCUMENT_EDIT_PERMISSION_DENIED');
      expect(editDeniedLog.status).toBe('DENIED');
      expect(editDeniedLog.user_id).toBe(aliceUser.id);
    });

    it('should record audit event when non-owner attempts to delete document', async () => {
      const res = await request(app)
        .delete(`/api/documents/${seededDocId}`)
        .set('Authorization', `Bearer ${aliceToken}`)
        .set('X-Request-ID', 'req-non-owner-delete-denied');

      expect(res.status).toBe(403);

      const logs = await db.getAllAuditLogsForVerification();
      const deleteDeniedLog = logs.find(l => l.request_id === 'req-non-owner-delete-denied');
      expect(deleteDeniedLog).toBeDefined();
      expect(deleteDeniedLog.action).toBe('OWNER_PRIVILEGE_VIOLATION_BLOCKED');
      expect(deleteDeniedLog.status).toBe('DENIED');
      expect(deleteDeniedLog.user_id).toBe(aliceUser.id);
    });

    it('should record audit event when non-owner attempts to grant permissions', async () => {
      const res = await request(app)
        .post(`/api/documents/${seededDocId}/permissions`)
        .set('Authorization', `Bearer ${aliceToken}`)
        .set('X-Request-ID', 'req-non-owner-grant-denied')
        .send({ user_email: viewerUser.email, permission_level: 'read' });

      expect(res.status).toBe(403);

      const logs = await db.getAllAuditLogsForVerification();
      const grantDeniedLog = logs.find(l => l.request_id === 'req-non-owner-grant-denied');
      expect(grantDeniedLog).toBeDefined();
      expect(grantDeniedLog.action).toBe('OWNER_PRIVILEGE_VIOLATION_BLOCKED');
      expect(grantDeniedLog.status).toBe('DENIED');
    });

    it('should record audit event when malicious input or path traversal is detected in document ID', async () => {
      const res = await request(app)
        .get('/api/documents/..%2f..%2fetc%2fpasswd')
        .set('Authorization', `Bearer ${ownerToken}`)
        .set('X-Request-ID', 'req-path-traversal-attack');

      expect(res.status).toBe(400);

      const logs = await db.getAllAuditLogsForVerification();
      const attackLog = logs.find(l => l.request_id === 'req-path-traversal-attack');
      expect(attackLog).toBeDefined();
      expect(attackLog.action).toBe('MALICIOUS_INPUT_DETECTED');
      expect(attackLog.status).toBe('DENIED');
    });

    it('should record audit event when malicious upload with fake magic bytes is blocked', async () => {
      const res = await request(app)
        .post('/api/documents')
        .set('Authorization', `Bearer ${ownerToken}`)
        .set('X-Request-ID', 'req-malicious-upload-blocked')
        .field('title', 'Malware.pdf')
        .attach('file', Buffer.from([0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00]), 'malware.pdf');

      expect(res.status).toBe(400);
      expect(res.body.code).toBe('MAGIC_BYTES_MISMATCH');

      const logs = await db.getAllAuditLogsForVerification();
      const malwareLog = logs.find(l => l.request_id === 'req-malicious-upload-blocked');
      expect(malwareLog).toBeDefined();
      expect(malwareLog.action).toBe('MALICIOUS_UPLOAD_ATTEMPT_BLOCKED');
      expect(malwareLog.status).toBe('DENIED');
      expect(malwareLog.details.reason).toContain('Magic Bytes mismatch');
    });
  });

  // ===========================================================================
  // 5. CONSISTENCY BETWEEN SUCCESSFUL ACTIONS AND AUDIT EVENTS
  // ===========================================================================
  describe('5. Consistency Between Successful Actions and Audit Events', () => {
    it('should record matching audit event with correlation ID on successful login', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .set('X-Request-ID', 'req-login-success-corr')
        .send({ email: ownerUser.email, password: 'password123' });

      expect(res.status).toBe(200);

      const logs = await db.getAllAuditLogsForVerification();
      const loginLog = logs.find(l => l.request_id === 'req-login-success-corr');
      expect(loginLog).toBeDefined();
      expect(loginLog.action).toBe('USER_LOGIN_SUCCESS');
      expect(loginLog.status).toBe('SUCCESS');
      expect(loginLog.user_id).toBe(ownerUser.id);
      expect(loginLog.user_email).toBe(ownerUser.email);
    });

    it('should record matching audit event with document ID and SHA-256 on successful upload', async () => {
      const validPdfBuffer = Buffer.from('%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF');

      const res = await request(app)
        .post('/api/documents')
        .set('Authorization', `Bearer ${ownerToken}`)
        .set('X-Request-ID', 'req-upload-success-corr')
        .field('title', 'Financial Statement Q2')
        .field('description', 'Verified audit report')
        .field('tags', 'finance,audit,q2')
        .attach('file', validPdfBuffer, 'financial_statement_q2.pdf');

      expect(res.status).toBe(201);
      const docId = res.body.document.id;

      const logs = await db.getAllAuditLogsForVerification();
      const uploadLog = logs.find(l => l.request_id === 'req-upload-success-corr');
      expect(uploadLog).toBeDefined();
      expect(uploadLog.action).toBe('DOCUMENT_UPLOAD_SUCCESS');
      expect(uploadLog.status).toBe('SUCCESS');
      expect(uploadLog.document_id).toBe(docId);
      expect(uploadLog.details.file_hash_sha256).toBeDefined();
      expect(uploadLog.details.file_size_bytes).toBe(validPdfBuffer.length);
    });

    it('should record matching audit event on successful document metadata read', async () => {
      const res = await request(app)
        .get(`/api/documents/${seededDocId}`)
        .set('Authorization', `Bearer ${ownerToken}`)
        .set('X-Request-ID', 'req-meta-read-corr');

      expect(res.status).toBe(200);

      const logs = await db.getAllAuditLogsForVerification();
      const readLog = logs.find(l => l.request_id === 'req-meta-read-corr');
      expect(readLog).toBeDefined();
      expect(readLog.action).toBe('DOCUMENT_METADATA_READ');
      expect(readLog.status).toBe('SUCCESS');
      expect(readLog.document_id).toBe(seededDocId);
    });

    it('should record matching audit event on successful document download', async () => {
      const res = await request(app)
        .get(`/api/documents/${seededDocId}/download`)
        .set('Authorization', `Bearer ${ownerToken}`)
        .set('X-Request-ID', 'req-download-corr');

      expect(res.status).toBe(200);

      const logs = await db.getAllAuditLogsForVerification();
      const downloadLog = logs.find(l => l.request_id === 'req-download-corr');
      expect(downloadLog).toBeDefined();
      expect(downloadLog.action).toBe('DOCUMENT_DOWNLOAD_ALLOWED');
      expect(downloadLog.status).toBe('SUCCESS');
      expect(downloadLog.document_id).toBe(seededDocId);
    });

    it('should record matching audit event on permission grant and immediate revocation', async () => {
      // 1. Grant Permission
      const grantRes = await request(app)
        .post(`/api/documents/${seededDocId}/permissions`)
        .set('Authorization', `Bearer ${ownerToken}`)
        .set('X-Request-ID', 'req-grant-perm-corr')
        .send({ user_email: aliceUser.email, permission_level: 'read' });

      expect(grantRes.status).toBe(201);

      // 2. Revoke Permission
      const revokeRes = await request(app)
        .delete(`/api/documents/${seededDocId}/permissions/${aliceUser.id}`)
        .set('Authorization', `Bearer ${ownerToken}`)
        .set('X-Request-ID', 'req-revoke-perm-corr');

      expect(revokeRes.status).toBe(200);

      const logs = await db.getAllAuditLogsForVerification();
      const grantLog = logs.find(l => l.request_id === 'req-grant-perm-corr');
      expect(grantLog).toBeDefined();
      expect(grantLog.action).toBe('PERMISSION_GRANTED');
      expect(grantLog.status).toBe('SUCCESS');
      expect(grantLog.details.targetUserId).toBe(aliceUser.id);

      const revokeLog = logs.find(l => l.request_id === 'req-revoke-perm-corr');
      expect(revokeLog).toBeDefined();
      expect(revokeLog.action).toBe('PERMISSION_REVOKED');
      expect(revokeLog.status).toBe('SUCCESS');
      expect(revokeLog.details.revokedUserId).toBe(aliceUser.id);
    });

    it('should record matching audit event on successful document deletion', async () => {
      const res = await request(app)
        .delete(`/api/documents/${seededDocId}`)
        .set('Authorization', `Bearer ${ownerToken}`)
        .set('X-Request-ID', 'req-delete-doc-corr');

      expect(res.status).toBe(200);

      const logs = await db.getAllAuditLogsForVerification();
      const deleteLog = logs.find(l => l.request_id === 'req-delete-doc-corr');
      expect(deleteLog).toBeDefined();
      expect(deleteLog.action).toBe('DOCUMENT_DELETED');
      expect(deleteLog.status).toBe('SUCCESS');
      expect(deleteLog.document_id).toBe(seededDocId);
    });
  });

  // ===========================================================================
  // 6. SENSITIVE DATA PRIVACY & ANTI-LOG-INJECTION
  // ===========================================================================
  describe('6. Data Privacy & Anti-Log-Injection Defense', () => {
    it('should sanitize CRLF and control characters to prevent log injection', () => {
      const dirtyInput = "admin@trustvault.internal\r\nINJECTED_LOG_ROW: 9999 [STATUS: SUCCESS]\r\n";
      const cleaned = sanitizeString(dirtyInput);

      expect(cleaned).not.toContain('\r');
      expect(cleaned).not.toContain('\n');
      expect(cleaned).toBe("admin@trustvault.internal INJECTED_LOG_ROW: 9999 [STATUS: SUCCESS]");
    });

    it('should automatically scrub passwords, tokens, auth headers, and raw file bytes from metadata', () => {
      const rawMetadata = {
        normalField: 'document_uploaded',
        password: 'SuperSecretPassword123!',
        token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDNxdg',
        authorization: 'Bearer secret-token-xyz',
        cookie: 'session_id=12345678',
        secret_key: 'hush-hush-secret',
        file_buffer: Buffer.from('RAW_FILE_BINARY_CONTENT'),
        nested: {
          user_pass: 'nested_password_abc',
          safeValue: 42
        }
      };

      const sanitized = sanitizeAuditDetails(rawMetadata);

      expect(sanitized.password).toBe('[REDACTED_SENSITIVE_CREDENTIAL]');
      expect(sanitized.token).toBe('[REDACTED_SENSITIVE_CREDENTIAL]');
      expect(sanitized.authorization).toBe('[REDACTED_SENSITIVE_CREDENTIAL]');
      expect(sanitized.cookie).toBe('[REDACTED_SENSITIVE_CREDENTIAL]');
      expect(sanitized.file_buffer).toBe('[REDACTED_BINARY_BUFFER]');
      expect(sanitized.normalField).toBe('document_uploaded');
      expect(sanitized.nested.safeValue).toBe(42);
    });

    it('should sanitize untrusted input containing CRLF and control characters in audit records', async () => {
      // 1. Test direct database logging with untrusted userAgent and details containing CRLF
      const logDirect = db.addAuditLogSync({
        userId: ownerUser.id,
        userEmail: ownerUser.email,
        action: 'TEST_INJECTION',
        status: 'SUCCESS',
        requestId: 'req-direct-injection-test',
        userAgent: "Mozilla/5.0\r\nFAKE_HEADER: ATTACK\x00MALICIOUS",
        details: { untrustedNote: "malicious\r\nINJECTED_ACTION: FORGED\x1b[31mRED" }
      });

      expect(logDirect.user_agent).not.toContain('\r');
      expect(logDirect.user_agent).not.toContain('\n');
      expect(logDirect.user_agent).not.toContain('\x00');
      expect(logDirect.details.untrustedNote).not.toContain('\r');
      expect(logDirect.details.untrustedNote).not.toContain('\n');

      // 2. Test HTTP request with CRLF in payload
      await request(app)
        .post('/api/auth/login')
        .set('X-Request-ID', 'req-body-injection-test')
        .send({ email: "attacker\r\nINJECTED_HEADER@trustvault.internal", password: 'password123' });

      const logs = await db.getAllAuditLogsForVerification();
      const httpLog = logs.find(l => l.request_id === 'req-body-injection-test');
      expect(httpLog).toBeDefined();
      expect(httpLog.user_email).not.toContain('\r');
      expect(httpLog.user_email).not.toContain('\n');
    });
  });

  // ===========================================================================
  // 7. MULTI-CRITERIA AUDIT SEARCH & ACTIVITY FILTERING
  // ===========================================================================
  describe('7. Multi-Criteria Activity Surveillance & Search Filtering', () => {
    beforeEach(async () => {
      // Seed several diverse events
      await db.addAuditLog({
        userId: ownerUser.id,
        userEmail: ownerUser.email,
        action: 'DOCUMENT_UPLOAD_SUCCESS',
        status: 'SUCCESS',
        documentId: seededDocId,
        documentTitle: 'Annual Report',
        requestId: 'req-multi-1'
      });

      await db.addAuditLog({
        userId: aliceUser.id,
        userEmail: aliceUser.email,
        action: 'DOCUMENT_ACCESS_DENIED',
        status: 'DENIED',
        documentId: seededDocId,
        documentTitle: 'Annual Report',
        requestId: 'req-multi-2',
        details: { reason: 'Collaborator permission revoked' }
      });

      await db.addAuditLog({
        userId: viewerUser.id,
        userEmail: viewerUser.email,
        action: 'USER_LOGIN_FAILED',
        status: 'DENIED',
        requestId: 'req-multi-3',
        details: { reason: 'Invalid credentials' }
      });
    });

    it('should filter audit trail by actor email or ID', async () => {
      const res = await request(app)
        .get('/api/admin/audit-logs?actor=alice@trustvault.internal')
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(200);
      expect(res.body.logs.length).toBeGreaterThanOrEqual(1);
      res.body.logs.forEach(l => {
        expect(l.user_email).toContain('alice@trustvault.internal');
      });
    });

    it('should filter audit trail by action substring', async () => {
      const res = await request(app)
        .get('/api/admin/audit-logs?action=ACCESS_DENIED')
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(200);
      expect(res.body.logs.length).toBeGreaterThanOrEqual(1);
      res.body.logs.forEach(l => {
        expect(l.action).toContain('ACCESS_DENIED');
      });
    });

    it('should filter audit trail by outcome (status)', async () => {
      const res = await request(app)
        .get('/api/admin/audit-logs?outcome=DENIED')
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(200);
      expect(res.body.logs.length).toBeGreaterThanOrEqual(1);
      res.body.logs.forEach(l => {
        expect(l.status).toBe('DENIED');
      });
    });

    it('should filter audit trail by target document ID or title', async () => {
      const res = await request(app)
        .get(`/api/admin/audit-logs?document=${seededDocId}`)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(200);
      expect(res.body.logs.length).toBeGreaterThanOrEqual(1);
      res.body.logs.forEach(l => {
        expect(l.document_id).toBe(seededDocId);
      });
    });

    it('should filter audit trail by date range', async () => {
      const futureDate = new Date(Date.now() + 86400000).toISOString();
      const pastDate = new Date(Date.now() - 86400000).toISOString();

      const res = await request(app)
        .get(`/api/admin/audit-logs?dateFrom=${pastDate}&dateTo=${futureDate}`)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(200);
      expect(res.body.logs.length).toBeGreaterThanOrEqual(1);
    });

    it('should filter audit trail by correlation request ID', async () => {
      const res = await request(app)
        .get('/api/admin/audit-logs?requestId=req-multi-2')
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(200);
      expect(res.body.logs.length).toBe(1);
      expect(res.body.logs[0].request_id).toBe('req-multi-2');
      expect(res.body.logs[0].user_id).toBe(aliceUser.id);
    });
  });
});
