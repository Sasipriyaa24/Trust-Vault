const request = require('supertest');
const app = require('../src/app');
const db = require('../src/db/db');
const { generateToken } = require('../src/controllers/authController');

describe('🔒 TrustVault Schema & Authentication Defense Test Suite', () => {
  let adminUser;
  let ownerUser;
  let adversaryUser;
  let viewerUser;

  let adminToken;
  let ownerToken;
  let adversaryToken;
  let viewerToken;

  beforeEach(async () => {
    db.reset();

    adminUser = await db.getProfileByEmail('admin@trustvault.internal');
    ownerUser = await db.getProfileByEmail('owner@trustvault.internal');
    adversaryUser = await db.getProfileByEmail('alice@trustvault.internal');
    viewerUser = await db.getProfileByEmail('viewer@trustvault.internal');

    adminToken = generateToken(adminUser);
    ownerToken = generateToken(ownerUser);
    adversaryToken = generateToken(adversaryUser);
    viewerToken = generateToken(viewerUser);
  });

  // ===========================================================================
  // 1. ROLE ESCALATION TESTS
  // ===========================================================================
  describe('1. Role Escalation Prevention', () => {
    it('should reject or downgrade client attempts to self-assign administrator role during registration', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          email: 'attacker@trustvault.internal',
          password: 'Password123!',
          full_name: 'Attacker Self Escalator',
          system_role: 'administrator' // Attempt to elevate to admin
        });

      expect(res.status).toBe(201);
      // The role MUST NOT be administrator; server-side sanitization forces safe role
      expect(res.body.user.system_role).not.toBe('administrator');
      expect(res.body.user.system_role).toBe('viewer');

      // Verify the persisted database profile has NOT been elevated
      const profile = await db.getProfileByEmail('attacker@trustvault.internal');
      expect(profile.system_role).toBe('viewer');
    });

    it('should block non-administrators from accessing the user role management endpoint', async () => {
      const res = await request(app)
        .patch(`/api/admin/users/${viewerUser.id}/status`)
        .set('Authorization', `Bearer ${viewerToken}`)
        .send({ system_role: 'administrator' });

      expect(res.status).toBe(403);
      expect(res.body.code).toBe('INSUFFICIENT_SYSTEM_ROLE');

      // Verify role in database remains unchanged
      const profile = await db.getProfileById(viewerUser.id);
      expect(profile.system_role).toBe('viewer');
    });

    it('should derive user identity strictly from authoritative server data, ignoring client role fields', async () => {
      // Adversary sends an upload request with client-injected role: 'administrator'
      const res = await request(app)
        .post('/api/documents')
        .set('Authorization', `Bearer ${viewerToken}`)
        .field('title', 'Attempted_Admin_Upload.pdf')
        .field('role', 'administrator') // Spoofed body param
        .field('system_role', 'administrator') // Spoofed body param
        .attach('file', Buffer.from('%PDF-1.4\nTest\n%%EOF'), 'test.pdf');

      // Server must check DB system_role ('viewer') and reject with 403
      expect(res.status).toBe(403);
      expect(res.body.code).toBe('INSUFFICIENT_UPLOAD_ROLE');
    });
  });

  // ===========================================================================
  // 2. UNAUTHORISED CROSS-USER DATABASE ACCESS (IDOR) TESTS
  // ===========================================================================
  describe('2. Unauthorised Cross-User Document Access (IDOR)', () => {
    let victimDoc;

    beforeEach(async () => {
      const uploadRes = await request(app)
        .post('/api/documents')
        .set('Authorization', `Bearer ${ownerToken}`)
        .field('title', 'Victim_Confidential_Legal_Settlement.pdf')
        .field('description', 'Strictly confidential arbitration agreement.')
        .attach('file', Buffer.from('%PDF-1.4\nConfidential Terms\n%%EOF'), 'settlement.pdf');

      expect(uploadRes.status).toBe(201);
      victimDoc = uploadRes.body.document;
    });

    it('should block an unauthorized user from reading anothers document metadata (IDOR)', async () => {
      const res = await request(app)
        .get(`/api/documents/${victimDoc.id}`)
        .set('Authorization', `Bearer ${adversaryToken}`);

      expect(res.status).toBe(403);
      expect(res.body.code).toBe('DOCUMENT_ACCESS_DENIED');

      // Verify audit log captured the unauthorized access attempt
      const logs = await db.getAuditLogs({ action: 'DOCUMENT_ACCESS_DENIED', status: 'DENIED' });
      expect(logs.logs.length).toBeGreaterThan(0);
      expect(logs.logs[0].user_id).toBe(adversaryUser.id);
      expect(logs.logs[0].document_id).toBe(victimDoc.id);
    });

    it('should block an unauthorized user from downloading anothers document file stream', async () => {
      const res = await request(app)
        .get(`/api/documents/${victimDoc.id}/download`)
        .set('Authorization', `Bearer ${adversaryToken}`);

      expect(res.status).toBe(403);
      expect(res.body.code).toBe('DOCUMENT_ACCESS_DENIED');
    });

    it('should block an unauthorized user from updating metadata of anothers document', async () => {
      const res = await request(app)
        .patch(`/api/documents/${victimDoc.id}`)
        .set('Authorization', `Bearer ${adversaryToken}`)
        .send({
          title: 'Adversary Overwritten Title',
          description: 'Hacked by unauthorized user'
        });

      expect(res.status).toBe(403);
      expect(res.body.code).toBe('DOCUMENT_ACCESS_DENIED');

      // Verify original metadata was untampered
      const currentDoc = await db.getDocumentById(victimDoc.id);
      expect(currentDoc.title).toBe('Victim_Confidential_Legal_Settlement.pdf');
    });

    it('should block an unauthorized user from granting permissions on anothers document', async () => {
      const res = await request(app)
        .post(`/api/documents/${victimDoc.id}/permissions`)
        .set('Authorization', `Bearer ${adversaryToken}`)
        .send({
          user_id: viewerUser.id,
          permission_level: 'read'
        });

      expect(res.status).toBe(403);
      expect(res.body.code).toBe('OWNER_ONLY_OPERATION');
    });

    it('should block an unauthorized user from revoking permissions on anothers document', async () => {
      // First, owner grants permission to viewer
      await request(app)
        .post(`/api/documents/${victimDoc.id}/permissions`)
        .set('Authorization', `Bearer ${ownerToken}`)
        .send({
          user_id: viewerUser.id,
          permission_level: 'read'
        });

      // Adversary attempts to revoke viewer's permission
      const res = await request(app)
        .delete(`/api/documents/${victimDoc.id}/permissions/${viewerUser.id}`)
        .set('Authorization', `Bearer ${adversaryToken}`);

      expect(res.status).toBe(403);
      expect(res.body.code).toBe('OWNER_ONLY_OPERATION');

      // Verify viewer still has access
      const perm = await db.getUserPermissionOnDocument(victimDoc.id, viewerUser.id);
      expect(perm).not.toBeNull();
      expect(perm.permission_level).toBe('read');
    });
  });

  // ===========================================================================
  // 3. STRICT ADMIN DOCUMENT ISOLATION (NO BLANKET BYPASS)
  // ===========================================================================
  describe('3. Admin Content Isolation (No Blanket Bypass)', () => {
    let privateDoc;

    beforeEach(async () => {
      const uploadRes = await request(app)
        .post('/api/documents')
        .set('Authorization', `Bearer ${ownerToken}`)
        .field('title', 'Board_Of_Directors_Deliberation.pdf')
        .attach('file', Buffer.from('%PDF-1.4\nBoard Deliberations\n%%EOF'), 'board.pdf');

      privateDoc = uploadRes.body.document;
    });

    it('should enforce that administrators CANNOT read private document metadata without explicit delegation', async () => {
      const res = await request(app)
        .get(`/api/documents/${privateDoc.id}`)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(403);
      expect(res.body.code).toBe('DOCUMENT_ACCESS_DENIED');
      expect(res.body.error).toContain('Enterprise Security Policy blocks administrator blanket access');

      // Verify specific admin bypass security log was recorded
      const logs = await db.getAuditLogs({ action: 'ADMIN_BLANKET_BYPASS_BLOCKED' });
      expect(logs.logs.length).toBeGreaterThan(0);
      expect(logs.logs[0].user_id).toBe(adminUser.id);
      expect(logs.logs[0].status).toBe('DENIED');
    });

    it('should enforce that administrators CANNOT download private document file bytes without explicit delegation', async () => {
      const res = await request(app)
        .get(`/api/documents/${privateDoc.id}/download`)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(403);
      expect(res.body.code).toBe('DOCUMENT_ACCESS_DENIED');
    });
  });

  // ===========================================================================
  // 4. AUDIT LOG IMMUTABILITY & ACCESS RESTRICTIONS
  // ===========================================================================
  describe('4. Audit Log Access Isolation & Immutability', () => {
    it('should restrict audit trail viewing strictly to administrators', async () => {
      const ownerRes = await request(app)
        .get('/api/admin/audit-logs')
        .set('Authorization', `Bearer ${ownerToken}`);
      expect(ownerRes.status).toBe(403);

      const viewerRes = await request(app)
        .get('/api/admin/audit-logs')
        .set('Authorization', `Bearer ${viewerToken}`);
      expect(viewerRes.status).toBe(403);

      const adminRes = await request(app)
        .get('/api/admin/audit-logs')
        .set('Authorization', `Bearer ${adminToken}`);
      expect(adminRes.status).toBe(200);
      expect(Array.isArray(adminRes.body.logs)).toBe(true);
    });

    it('should detect out-of-band tampering in the audit log hash chain', async () => {
      // Trigger tampering on record 1
      await request(app)
        .post('/api/admin/audit-logs/simulate-tampering')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ logId: 1 });

      // Run verification
      const verifyRes = await request(app)
        .get('/api/admin/audit-logs/verify')
        .set('Authorization', `Bearer ${adminToken}`);

      expect(verifyRes.status).toBe(200);
      expect(verifyRes.body.isValid).toBe(false);
      expect(verifyRes.body.compromisedAtId).toBe(1);
    });
  });
});
