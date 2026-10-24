const request = require('supertest');
const app = require('../src/app');
const db = require('../src/db/db');
const { generateToken } = require('../src/controllers/authController');

describe('🛡️ TrustVault Automated Security & Vulnerability Test Suite', () => {
  let adminUser;
  let ownerUser;
  let secondaryOwner;
  let viewerUser;

  let adminToken;
  let ownerToken;
  let secondaryOwnerToken;
  let viewerToken;

  beforeEach(async () => {
    // Reset database to pristine state before each test
    db.reset();

    adminUser = await db.getProfileByEmail('admin@trustvault.internal');
    ownerUser = await db.getProfileByEmail('owner@trustvault.internal');
    secondaryOwner = await db.getProfileByEmail('alice@trustvault.internal');
    viewerUser = await db.getProfileByEmail('viewer@trustvault.internal');

    adminToken = generateToken(adminUser);
    ownerToken = generateToken(ownerUser);
    secondaryOwnerToken = generateToken(secondaryOwner);
    viewerToken = generateToken(viewerUser);
  });

  // ===========================================================================
  // 1. AUTHENTICATION & IDENTITY VERIFICATION
  // ===========================================================================
  describe('1. Authentication & Fail-Closed Guardrails', () => {
    it('should fail-closed and reject requests without Authorization header', async () => {
      const res = await request(app).get('/api/documents');
      expect(res.status).toBe(401);
      expect(res.body.code).toBe('AUTH_HEADER_MISSING');
    });

    it('should reject malformed or tampered JWT signatures', async () => {
      const forgedToken = ownerToken.slice(0, -6) + 'abcdef';
      const res = await request(app)
        .get('/api/documents')
        .set('Authorization', `Bearer ${forgedToken}`);
      expect(res.status).toBe(401);
      expect(res.body.code).toBe('TOKEN_INVALID');
    });

    it('should immediately block deactivated user accounts from API access', async () => {
      // Deactivate viewer account
      await db.updateProfile(viewerUser.id, { is_active: false });

      const res = await request(app)
        .get('/api/documents')
        .set('Authorization', `Bearer ${viewerToken}`);

      expect(res.status).toBe(403);
      expect(res.body.code).toBe('ACCOUNT_DEACTIVATED');

      // Verify security audit entry was written
      const logs = await db.getAuditLogs({ action: 'DEACTIVATED_USER_ACCESS_BLOCKED' });
      expect(logs.logs.length).toBeGreaterThan(0);
      expect(logs.logs[0].status).toBe('DENIED');
    });
  });

  // ===========================================================================
  // 2. INSECURE DIRECT OBJECT REFERENCE (IDOR) PREVENTION
  // ===========================================================================
  describe('2. Insecure Direct Object Reference (IDOR) Defense', () => {
    let ownerDoc;

    beforeEach(async () => {
      // Owner uploads a confidential financial audit
      const uploadRes = await request(app)
        .post('/api/documents')
        .set('Authorization', `Bearer ${ownerToken}`)
        .field('title', 'Confidential_Executive_Salaries.pdf')
        .field('description', 'Highly confidential payroll report.')
        .attach('file', Buffer.from('%PDF-1.4\n1 0 obj\nPayroll Data\n%%EOF'), 'salaries.pdf');

      expect(uploadRes.status).toBe(201);
      ownerDoc = uploadRes.body.document;
    });

    it('IDOR Check: Unauthorized user cannot read another users document metadata', async () => {
      // Viewer attempts to access Owner document by guessing its ID
      const res = await request(app)
        .get(`/api/documents/${ownerDoc.id}`)
        .set('Authorization', `Bearer ${viewerToken}`);

      expect(res.status).toBe(403);
      expect(res.body.code).toBe('DOCUMENT_ACCESS_DENIED');

      // Verify audit trail logged the denial
      const logs = await db.getAuditLogs({ action: 'DOCUMENT_ACCESS_DENIED', status: 'DENIED' });
      expect(logs.logs.length).toBeGreaterThan(0);
      expect(logs.logs[0].user_id).toBe(viewerUser.id);
      expect(logs.logs[0].document_id).toBe(ownerDoc.id);
    });

    it('IDOR Check: Unauthorized user cannot download another users document stream', async () => {
      // Secondary Owner (Alice) attempts to download Owner document without permission
      const res = await request(app)
        .get(`/api/documents/${ownerDoc.id}/download`)
        .set('Authorization', `Bearer ${secondaryOwnerToken}`);

      expect(res.status).toBe(403);
      expect(res.body.code).toBe('DOCUMENT_ACCESS_DENIED');
    });

    it('IDOR Check: Non-owner cannot modify document metadata', async () => {
      const res = await request(app)
        .patch(`/api/documents/${ownerDoc.id}`)
        .set('Authorization', `Bearer ${viewerToken}`)
        .send({ title: 'Hacked Title By Adversary' });

      expect(res.status).toBe(403);
      expect(res.body.code).toBe('DOCUMENT_ACCESS_DENIED');

      // Verify document was NOT changed
      const doc = await db.getDocumentById(ownerDoc.id);
      expect(doc.title).toBe('Confidential_Executive_Salaries.pdf');
    });

    it('IDOR Check: Non-owner cannot delete another users document', async () => {
      const res = await request(app)
        .delete(`/api/documents/${ownerDoc.id}`)
        .set('Authorization', `Bearer ${secondaryOwnerToken}`);

      expect(res.status).toBe(403);
      expect(res.body.code).toBe('OWNER_ONLY_OPERATION');

      // Verify document still exists
      const doc = await db.getDocumentById(ownerDoc.id);
      expect(doc).not.toBeNull();
      expect(doc.is_deleted).toBe(false);
    });
  });

  // ===========================================================================
  // 3. NO BLANKET ADMINISTRATOR BYPASS VERIFICATION
  // ===========================================================================
  describe('3. Strict Admin Document Isolation (No Blanket Bypass)', () => {
    let privateDoc;

    beforeEach(async () => {
      const uploadRes = await request(app)
        .post('/api/documents')
        .set('Authorization', `Bearer ${ownerToken}`)
        .field('title', 'Classified_Trade_Secret.pdf')
        .attach('file', Buffer.from('%PDF-1.4\nConfidential Blueprint\n%%EOF'), 'secret.pdf');

      privateDoc = uploadRes.body.document;
    });

    it('should BLOCK administrators from reading private document metadata without explicit grant', async () => {
      const res = await request(app)
        .get(`/api/documents/${privateDoc.id}`)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(403);
      expect(res.body.code).toBe('DOCUMENT_ACCESS_DENIED');
      expect(res.body.error).toContain('Enterprise Security Policy blocks administrator blanket access');

      // Verify high-priority security audit record
      const logs = await db.getAuditLogs({ action: 'ADMIN_BLANKET_BYPASS_BLOCKED' });
      expect(logs.logs.length).toBeGreaterThan(0);
      expect(logs.logs[0].user_id).toBe(adminUser.id);
      expect(logs.logs[0].status).toBe('DENIED');
    });

    it('should BLOCK administrators from downloading private document file bytes without explicit grant', async () => {
      const res = await request(app)
        .get(`/api/documents/${privateDoc.id}/download`)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(403);
      expect(res.body.code).toBe('DOCUMENT_ACCESS_DENIED');
    });
  });

  // ===========================================================================
  // 4. NAMED PERMISSIONS & INSTANT REVOCATION (ZERO STALE CACHE)
  // ===========================================================================
  describe('4. Named Permissions & Immediate Access Revocation', () => {
    let sharedDoc;

    beforeEach(async () => {
      const uploadRes = await request(app)
        .post('/api/documents')
        .set('Authorization', `Bearer ${ownerToken}`)
        .field('title', 'Collaborative_Quarterly_Strategy.pdf')
        .attach('file', Buffer.from('%PDF-1.4\nQuarterly Goals\n%%EOF'), 'strategy.pdf');

      sharedDoc = uploadRes.body.document;
    });

    it('should grant read access, allow download, and enforce immediate revocation', async () => {
      // Step 1: Viewer has no access initially
      let checkInitial = await request(app)
        .get(`/api/documents/${sharedDoc.id}/download`)
        .set('Authorization', `Bearer ${viewerToken}`);
      expect(checkInitial.status).toBe(403);

      // Step 2: Owner grants 'read' permission to viewer
      const grantRes = await request(app)
        .post(`/api/documents/${sharedDoc.id}/permissions`)
        .set('Authorization', `Bearer ${ownerToken}`)
        .send({
          user_id: viewerUser.id,
          permission_level: 'read'
        });
      expect(grantRes.status).toBe(201);
      expect(grantRes.body.grant.permission_level).toBe('read');

      // Step 3: Viewer can now download document
      const downloadRes = await request(app)
        .get(`/api/documents/${sharedDoc.id}/download`)
        .set('Authorization', `Bearer ${viewerToken}`);
      expect(downloadRes.status).toBe(200);
      expect(downloadRes.headers['x-content-type-options']).toBe('nosniff');

      // Step 4: Viewer cannot edit with read-only permission
      const editRes = await request(app)
        .patch(`/api/documents/${sharedDoc.id}`)
        .set('Authorization', `Bearer ${viewerToken}`)
        .send({ title: 'Tampered Title' });
      expect(editRes.status).toBe(403);
      expect(editRes.body.code).toBe('INSUFFICIENT_DOCUMENT_PERMISSION');

      // Step 5: Owner revokes access immediately
      const revokeRes = await request(app)
        .delete(`/api/documents/${sharedDoc.id}/permissions/${viewerUser.id}`)
        .set('Authorization', `Bearer ${ownerToken}`);
      expect(revokeRes.status).toBe(200);

      // Step 6: Instant Revocation Verification - Subsequent download fails immediately
      const immediateRevocationCheck = await request(app)
        .get(`/api/documents/${sharedDoc.id}/download`)
        .set('Authorization', `Bearer ${viewerToken}`);
      expect(immediateRevocationCheck.status).toBe(403);
      expect(immediateRevocationCheck.body.code).toBe('DOCUMENT_ACCESS_DENIED');
    });
  });

  // ===========================================================================
  // 5. FILE UPLOAD HARDENING & MAGIC BYTES INSPECTION
  // ===========================================================================
  describe('5. Upload Validation & Anti-Malware Safeguards', () => {
    it('should block viewers from uploading documents (Role Privilege Enforcement)', async () => {
      const res = await request(app)
        .post('/api/documents')
        .set('Authorization', `Bearer ${viewerToken}`)
        .field('title', 'Viewer_Upload_Attempt.pdf')
        .attach('file', Buffer.from('%PDF-1.4\nTest\n%%EOF'), 'test.pdf');

      expect(res.status).toBe(403);
      expect(res.body.code).toBe('INSUFFICIENT_UPLOAD_ROLE');
    });

    it('should reject dangerous files with executable magic bytes disguised as PDF', async () => {
      // Windows MZ header (0x4D 0x5A) disguised as .pdf
      const fakePdfBuffer = Buffer.from([0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]);

      const res = await request(app)
        .post('/api/documents')
        .set('Authorization', `Bearer ${ownerToken}`)
        .field('title', 'Malware_Exploit.pdf')
        .attach('file', fakePdfBuffer, 'trojan.pdf');

      expect(res.status).toBe(400);
      expect(res.body.code).toBe('MAGIC_BYTES_MISMATCH');

      // Verify malicious attempt was logged
      const logs = await db.getAuditLogs({ action: 'MALICIOUS_UPLOAD_ATTEMPT_BLOCKED' });
      expect(logs.logs.length).toBeGreaterThan(0);
    });

    it('should reject SVG uploads to prevent Stored Cross-Site Scripting (XSS)', async () => {
      const svgBuffer = Buffer.from('<svg><script>alert(1)</script></svg>');

      const res = await request(app)
        .post('/api/documents')
        .set('Authorization', `Bearer ${ownerToken}`)
        .field('title', 'Vector_Image.svg')
        .attach('file', svgBuffer, 'image.svg');

      expect(res.status).toBe(400);
      expect(res.body.code).toBe('FILE_VALIDATION_ERROR');
      expect(res.body.error).toContain('prohibited due to security policy');
    });
  });

  // ===========================================================================
  // 6. AUDIT TRAIL IMMUTABILITY & TAMPER DETECTION
  // ===========================================================================
  describe('6. Cryptographic Audit Chain Integrity & Tamper Detection', () => {
    it('should block non-administrators from accessing global audit logs', async () => {
      const res = await request(app)
        .get('/api/admin/audit-logs')
        .set('Authorization', `Bearer ${ownerToken}`);

      expect(res.status).toBe(403);
      expect(res.body.code).toBe('INSUFFICIENT_SYSTEM_ROLE');
    });

    it('should verify that an untampered audit ledger passes cryptographic integrity verification', async () => {
      const res = await request(app)
        .get('/api/admin/audit-logs/verify')
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(200);
      expect(res.body.isValid).toBe(true);
      expect(res.body.compromisedAtId).toBeNull();
      expect(res.body.checkedCount).toBeGreaterThan(0);
    });

    it('should DETECT out-of-band tampering when a past audit record is modified', async () => {
      // 1. Simulate an adversary directly modifying record ID 1 in the database
      const tamperRes = await request(app)
        .post('/api/admin/audit-logs/simulate-tampering')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ logId: 1 });
      expect(tamperRes.status).toBe(200);

      // 2. Administrator runs cryptographic verification
      const verifyRes = await request(app)
        .get('/api/admin/audit-logs/verify')
        .set('Authorization', `Bearer ${adminToken}`);

      expect(verifyRes.status).toBe(200);
      // Cryptographic verification MUST detect the breach!
      expect(verifyRes.body.isValid).toBe(false);
      expect(verifyRes.body.compromisedAtId).toBe(1);
      expect(verifyRes.body.message).toContain('Cryptographic signature mismatch');
    });
  });
});
