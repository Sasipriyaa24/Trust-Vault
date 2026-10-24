const request = require('supertest');
const express = require('express');
const app = require('../src/app');
const db = require('../src/db/db');
const { generateToken } = require('../src/controllers/authController');
const { authenticateToken } = require('../src/middleware/auth');
const { authorizeDocumentAccess } = require('../src/middleware/roles');

describe('🔐 TrustVault Document-Specific Permission System Integration Test Suite', () => {
  let adminUser;
  let ownerUser; // User B
  let aliceUser; // User A (Secondary Owner)
  let viewerUser; // Read-only / Guest

  let adminToken;
  let ownerToken;
  let aliceToken;
  let viewerToken;

  const samplePdf = Buffer.from('%PDF-1.4\nConfidential Proprietary Agreement\n%%EOF');

  beforeEach(async () => {
    db.reset();

    adminUser = await db.getProfileByEmail('admin@trustvault.internal');
    ownerUser = await db.getProfileByEmail('owner@trustvault.internal');
    aliceUser = await db.getProfileByEmail('alice@trustvault.internal');
    viewerUser = await db.getProfileByEmail('viewer@trustvault.internal');

    adminToken = generateToken(adminUser);
    ownerToken = generateToken(ownerUser);
    aliceToken = generateToken(aliceUser);
    viewerToken = generateToken(viewerUser);
  });

  // ===========================================================================
  // TEST 1: User A cannot read User B's document
  // Dependent Authorization Check:
  //   authorizeDocumentAccess({ requiredPermission: 'read' }) in documentRoutes.js
  // Why test fails if check removed:
  //   Without this check, getDocumentById executes and returns User B's confidential
  //   document metadata directly to User A.
  // ===========================================================================
  it('1. User A cannot read User B\'s document metadata (IDOR Defense)', async () => {
    // User B (Owner) uploads a document
    const uploadRes = await request(app)
      .post('/api/documents')
      .set('Authorization', `Bearer ${ownerToken}`)
      .field('title', 'UserB_Confidential_Patent.pdf')
      .attach('file', samplePdf, 'patent.pdf');
    expect(uploadRes.status).toBe(201);
    const docId = uploadRes.body.document.id;

    // User A (Alice) attempts to read User B's document metadata
    const readRes = await request(app)
      .get(`/api/documents/${docId}`)
      .set('Authorization', `Bearer ${aliceToken}`);

    expect(readRes.status).toBe(403);
    expect(readRes.body.code).toBe('DOCUMENT_ACCESS_DENIED');
    expect(readRes.body.document).toBeUndefined();

    // Verify audit log captured the denied read attempt
    const logs = await db.getAuditLogs({ action: 'DOCUMENT_ACCESS_DENIED', status: 'DENIED' });
    expect(logs.logs.length).toBeGreaterThan(0);
    expect(logs.logs[0].user_id).toBe(aliceUser.id);
    expect(logs.logs[0].document_id).toBe(docId);
  });

  // ===========================================================================
  // TEST 2: User A cannot download, edit or delete User B's document
  // Dependent Authorization Checks:
  //   - Download: authorizeDocumentAccess({ requiredPermission: 'read' })
  //   - Edit: authorizeDocumentAccess({ requiredPermission: 'edit' })
  //   - Delete: authorizeDocumentAccess({ allowOwnerOnly: true })
  // Why test fails if checks removed:
  //   - downloadDocument would stream confidential file bytes to an unauthorized principal.
  //   - updateDocumentMetadata would let an attacker overwrite User B's title/memos.
  //   - deleteDocument would let an attacker wipe or soft-delete User B's records.
  // ===========================================================================
  it('2. User A cannot download, edit or delete User B\'s document', async () => {
    // User B (Owner) uploads a document
    const uploadRes = await request(app)
      .post('/api/documents')
      .set('Authorization', `Bearer ${ownerToken}`)
      .field('title', 'UserB_Merger_Agreement.pdf')
      .attach('file', samplePdf, 'merger.pdf');
    const docId = uploadRes.body.document.id;

    // A. User A attempts download
    const downloadRes = await request(app)
      .get(`/api/documents/${docId}/download`)
      .set('Authorization', `Bearer ${aliceToken}`);
    expect(downloadRes.status).toBe(403);
    expect(downloadRes.body.code).toBe('DOCUMENT_ACCESS_DENIED');

    // B. User A attempts edit
    const editRes = await request(app)
      .patch(`/api/documents/${docId}`)
      .set('Authorization', `Bearer ${aliceToken}`)
      .send({ title: 'Adversary_Modified_Title.pdf' });
    expect(editRes.status).toBe(403);
    expect(editRes.body.code).toBe('DOCUMENT_ACCESS_DENIED');

    // C. User A attempts delete
    const deleteRes = await request(app)
      .delete(`/api/documents/${docId}`)
      .set('Authorization', `Bearer ${aliceToken}`);
    expect(deleteRes.status).toBe(403);
    expect(deleteRes.body.code).toBe('OWNER_ONLY_OPERATION');

    // Verify document was not deleted or modified in DB
    const pristineDoc = await db.getDocumentById(docId);
    expect(pristineDoc.title).toBe('UserB_Merger_Agreement.pdf');
    expect(pristineDoc.is_deleted).toBe(false);
  });

  // ===========================================================================
  // TEST 3: User A cannot grant access to User B's document
  // Dependent Authorization Check:
  //   authorizeDocumentAccess({ allowOwnerOnly: true }) in permissionRoutes.js
  // Why test fails if check removed:
  //   Without this check, any user who knows or guesses a document ID could
  //   grant themselves or arbitrary third parties read/edit access to another's vault.
  // ===========================================================================
  it('3. User A cannot grant access to User B\'s document', async () => {
    // User B (Owner) uploads a document
    const uploadRes = await request(app)
      .post('/api/documents')
      .set('Authorization', `Bearer ${ownerToken}`)
      .field('title', 'UserB_Trade_Secrets.pdf')
      .attach('file', samplePdf, 'secrets.pdf');
    const docId = uploadRes.body.document.id;

    // User A (Alice) attempts to grant 'read' access to Viewer
    const grantRes = await request(app)
      .post(`/api/documents/${docId}/permissions`)
      .set('Authorization', `Bearer ${aliceToken}`)
      .send({
        user_id: viewerUser.id,
        permission_level: 'read'
      });

    expect(grantRes.status).toBe(403);
    expect(grantRes.body.code).toBe('OWNER_ONLY_OPERATION');

    // Verify no permission grant exists in DB
    const perms = await db.getPermissionsForDocument(docId);
    expect(perms.length).toBe(0);
  });

  // ===========================================================================
  // TEST 4: A viewer cannot promote themselves to owner or admin
  // Dependent Authorization Checks:
  //   - authController.register server-side role sanitizer (strips requested administrator role)
  //   - requireSystemRole(['administrator']) on PATCH /api/admin/users/:id/status
  //   - documentController.updateDocumentMetadata dropped owner_id parameter
  // Why test fails if checks removed:
  //   - A guest/viewer could send { system_role: 'administrator' } or call admin governance
  //     endpoints to gain full admin powers or hijack document ownership.
  // ===========================================================================
  it('4. A viewer cannot promote themselves to owner or admin', async () => {
    // A. Registration privilege escalation attempt
    const registerRes = await request(app)
      .post('/api/auth/register')
      .send({
        email: 'malicious_viewer@trustvault.internal',
        password: 'Password123!',
        full_name: 'Privilege Escalation Attacker',
        system_role: 'administrator' // Spoofed attempt
      });
    expect(registerRes.status).toBe(201);
    expect(registerRes.body.user.system_role).toBe('viewer'); // Server forces viewer

    // B. Role status elevation attempt via admin endpoint
    const elevateRes = await request(app)
      .patch(`/api/admin/users/${viewerUser.id}/status`)
      .set('Authorization', `Bearer ${viewerToken}`)
      .send({ system_role: 'administrator' });
    expect(elevateRes.status).toBe(403);
    expect(elevateRes.body.code).toBe('INSUFFICIENT_SYSTEM_ROLE');

    // Verify viewer profile in DB is still 'viewer'
    const viewerProfile = await db.getProfileById(viewerUser.id);
    expect(viewerProfile.system_role).toBe('viewer');

    // C. Ownership hijacking attempt on an existing document
    const uploadRes = await request(app)
      .post('/api/documents')
      .set('Authorization', `Bearer ${ownerToken}`)
      .field('title', 'Corporate_Vault_Master.pdf')
      .attach('file', samplePdf, 'master.pdf');
    const docId = uploadRes.body.document.id;

    // Viewer attempts to hijack owner_id
    const hijackRes = await request(app)
      .patch(`/api/documents/${docId}`)
      .set('Authorization', `Bearer ${viewerToken}`)
      .send({ owner_id: viewerUser.id });
    expect(hijackRes.status).toBe(403);

    const doc = await db.getDocumentById(docId);
    expect(doc.owner_id).toBe(ownerUser.id);
    expect(doc.owner_id).not.toBe(viewerUser.id);
  });

  // ===========================================================================
  // TEST 5: A user with read permission cannot perform edit operations
  // Dependent Authorization Check:
  //   authorizeDocumentAccess({ requiredPermission: 'edit' }) checking
  //   userPerm.permission_level === 'edit'
  // Why test fails if check removed:
  //   Without checking requiredPermission === 'edit', any collaborator with a
  //   read-only grant could alter file titles, categories, and descriptions.
  // ===========================================================================
  it('5. A user with read permission cannot perform edit operations', async () => {
    // Owner uploads document
    const uploadRes = await request(app)
      .post('/api/documents')
      .set('Authorization', `Bearer ${ownerToken}`)
      .field('title', 'Immutable_Financial_Audit.pdf')
      .attach('file', samplePdf, 'audit.pdf');
    const docId = uploadRes.body.document.id;

    // Owner grants 'read' access to Viewer
    const grantRes = await request(app)
      .post(`/api/documents/${docId}/permissions`)
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({
        user_id: viewerUser.id,
        permission_level: 'read'
      });
    expect(grantRes.status).toBe(201);

    // Viewer can read metadata
    const readRes = await request(app)
      .get(`/api/documents/${docId}`)
      .set('Authorization', `Bearer ${viewerToken}`);
    expect(readRes.status).toBe(200);

    // Viewer attempts to edit metadata -> 403 INSUFFICIENT_DOCUMENT_PERMISSION
    const editRes = await request(app)
      .patch(`/api/documents/${docId}`)
      .set('Authorization', `Bearer ${viewerToken}`)
      .send({ title: 'Tampered_By_ReadOnly_Viewer.pdf' });

    expect(editRes.status).toBe(403);
    expect(editRes.body.code).toBe('INSUFFICIENT_DOCUMENT_PERMISSION');

    // Verify document was not modified
    const currentDoc = await db.getDocumentById(docId);
    expect(currentDoc.title).toBe('Immutable_Financial_Audit.pdf');
  });

  // ===========================================================================
  // TEST 6: An owner can grant read permission and the named viewer can access
  // Dependent Authorization Logic:
  //   db.grantPermission inserts unique (document_id, user_id) tuple;
  //   authorizeDocumentAccess checks database dynamically and allows read.
  // ===========================================================================
  it('6. An owner can grant read permission and the named viewer can access the document', async () => {
    // Owner uploads document
    const uploadRes = await request(app)
      .post('/api/documents')
      .set('Authorization', `Bearer ${ownerToken}`)
      .field('title', 'Onboarding_Security_Guide.pdf')
      .attach('file', samplePdf, 'guide.pdf');
    const docId = uploadRes.body.document.id;

    // Verify viewer initially cannot access
    const preCheck = await request(app)
      .get(`/api/documents/${docId}`)
      .set('Authorization', `Bearer ${viewerToken}`);
    expect(preCheck.status).toBe(403);

    // Owner grants read permission by user_email
    const grantRes = await request(app)
      .post(`/api/documents/${docId}/permissions`)
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({
        user_email: viewerUser.email,
        permission_level: 'read'
      });
    expect(grantRes.status).toBe(201);
    expect(grantRes.body.grant.permission_level).toBe('read');
    expect(grantRes.body.grant.user_id).toBe(viewerUser.id);

    // Named viewer accesses document metadata
    const metaRes = await request(app)
      .get(`/api/documents/${docId}`)
      .set('Authorization', `Bearer ${viewerToken}`);
    expect(metaRes.status).toBe(200);
    expect(metaRes.body.document.title).toBe('Onboarding_Security_Guide.pdf');
    expect(metaRes.body.document.user_access_level).toBe('read');

    // Named viewer downloads document stream
    const downloadRes = await request(app)
      .get(`/api/documents/${docId}/download`)
      .set('Authorization', `Bearer ${viewerToken}`);
    expect(downloadRes.status).toBe(200);
    expect(downloadRes.body.toString()).toContain('%PDF-1.4');
  });

  // ===========================================================================
  // TEST 7: An owner can revoke access and the next request is denied
  // Dependent Authorization Check:
  //   Live DB lookup in authorizeDocumentAccess without stale caching.
  // Why test fails if check removed:
  //   If access control used static tokens or stale caching, the revoked viewer
  //   would retain access until expiration.
  // ===========================================================================
  it('7. An owner can revoke access and the next request is immediately denied', async () => {
    // Owner uploads document
    const uploadRes = await request(app)
      .post('/api/documents')
      .set('Authorization', `Bearer ${ownerToken}`)
      .field('title', 'Confidential_Executive_Payroll.pdf')
      .attach('file', samplePdf, 'payroll.pdf');
    const docId = uploadRes.body.document.id;

    // Grant read access
    await request(app)
      .post(`/api/documents/${docId}/permissions`)
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({ user_id: viewerUser.id, permission_level: 'read' });

    // Confirm access works
    const accessOk = await request(app)
      .get(`/api/documents/${docId}`)
      .set('Authorization', `Bearer ${viewerToken}`);
    expect(accessOk.status).toBe(200);

    // Owner revokes access
    const revokeRes = await request(app)
      .delete(`/api/documents/${docId}/permissions/${viewerUser.id}`)
      .set('Authorization', `Bearer ${ownerToken}`);
    expect(revokeRes.status).toBe(200);
    expect(revokeRes.body.revoked_user_id).toBe(viewerUser.id);

    // Immediate next request from viewer MUST be denied with 403
    const nextReq = await request(app)
      .get(`/api/documents/${docId}/download`)
      .set('Authorization', `Bearer ${viewerToken}`);
    expect(nextReq.status).toBe(403);
    expect(nextReq.body.code).toBe('DOCUMENT_ACCESS_DENIED');
  });

  // ===========================================================================
  // TEST 8: A revoked viewer cannot access the file through another endpoint
  //         or previously obtained application link
  // Dependent Authorization Architecture:
  //   - Zero permanent public URLs.
  //   - Private storage bucket with zero public policies.
  //   - Live authorization on all document routes: GET /:id, GET /:id/download,
  //     PATCH /:id, DELETE /:id, and GET / (list/search).
  // ===========================================================================
  it('8. A revoked viewer cannot access the file through another endpoint or previously obtained application link', async () => {
    // Owner uploads document
    const uploadRes = await request(app)
      .post('/api/documents')
      .set('Authorization', `Bearer ${ownerToken}`)
      .field('title', 'Classified_Acquisition_TermSheet.pdf')
      .field('description', 'Strictly confidential terms')
      .attach('file', samplePdf, 'termsheet.pdf');
    const docId = uploadRes.body.document.id;

    // Grant then revoke
    await request(app)
      .post(`/api/documents/${docId}/permissions`)
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({ user_id: viewerUser.id, permission_level: 'read' });

    await request(app)
      .delete(`/api/documents/${docId}/permissions/${viewerUser.id}`)
      .set('Authorization', `Bearer ${ownerToken}`);

    // Endpoint A: Metadata reading -> 403
    const metaCheck = await request(app)
      .get(`/api/documents/${docId}`)
      .set('Authorization', `Bearer ${viewerToken}`);
    expect(metaCheck.status).toBe(403);
    expect(metaCheck.body.code).toBe('DOCUMENT_ACCESS_DENIED');

    // Endpoint B: Stream downloading -> 403
    const downloadCheck = await request(app)
      .get(`/api/documents/${docId}/download`)
      .set('Authorization', `Bearer ${viewerToken}`);
    expect(downloadCheck.status).toBe(403);
    expect(downloadCheck.body.code).toBe('DOCUMENT_ACCESS_DENIED');

    // Endpoint C: Updating metadata -> 403
    const editCheck = await request(app)
      .patch(`/api/documents/${docId}`)
      .set('Authorization', `Bearer ${viewerToken}`)
      .send({ title: 'Adversary Title' });
    expect(editCheck.status).toBe(403);
    expect(editCheck.body.code).toBe('DOCUMENT_ACCESS_DENIED');

    // Endpoint D: Search / List discovery -> Omitted from results
    const searchCheck = await request(app)
      .get('/api/documents?search=TermSheet')
      .set('Authorization', `Bearer ${viewerToken}`);
    expect(searchCheck.status).toBe(200);
    expect(searchCheck.body.documents.length).toBe(0);

    // Endpoint E: Inspecting permissions -> 403
    const permCheck = await request(app)
      .get(`/api/documents/${docId}/permissions`)
      .set('Authorization', `Bearer ${viewerToken}`);
    expect(permCheck.status).toBe(403);
  });

  // ===========================================================================
  // TEST 9: A tampered document ID cannot bypass authorization
  // Dependent Authorization Checks:
  //   - Path traversal validation in roles.js (detects .. / \\ \0)
  //   - Database existence check (404)
  //   - Ownership and permission check on the tampered ID (403)
  // Why test fails if checks removed:
  //   Path traversal could access local file system files or bucket roots;
  //   tampered IDs could access unauthorized resources without permission checks.
  // ===========================================================================
  it('9. A tampered document ID cannot bypass authorization', async () => {
    // A. Path traversal attempt in ID
    const traversalRes = await request(app)
      .get('/api/documents/..%2F..%2Fvault%2Fprivate.key')
      .set('Authorization', `Bearer ${aliceToken}`);
    expect(traversalRes.status).toBe(400);
    expect(traversalRes.body.code).toBe('INVALID_DOCUMENT_ID');

    // B. Tampered non-existent UUID
    const nonExistentId = '11111111-9999-9999-9999-111111111111';
    const nonExistentRes = await request(app)
      .get(`/api/documents/${nonExistentId}`)
      .set('Authorization', `Bearer ${aliceToken}`);
    expect(nonExistentRes.status).toBe(404);
    expect(nonExistentRes.body.code).toBe('DOCUMENT_NOT_FOUND');

    // C. Tampered valid UUID belonging to User B
    const uploadRes = await request(app)
      .post('/api/documents')
      .set('Authorization', `Bearer ${ownerToken}`)
      .field('title', 'Target_Victim_Document.pdf')
      .attach('file', samplePdf, 'target.pdf');
    const victimDocId = uploadRes.body.document.id;

    // Attacker modifies request URL to target victimDocId
    const idorRes = await request(app)
      .get(`/api/documents/${victimDocId}/download`)
      .set('Authorization', `Bearer ${aliceToken}`);
    expect(idorRes.status).toBe(403);
    expect(idorRes.body.code).toBe('DOCUMENT_ACCESS_DENIED');
  });

  // ===========================================================================
  // TEST 10: Missing authorization middleware causes relevant security tests to fail
  // Demonstration:
  //   We mount an express route WITHOUT authorizeDocumentAccess vs WITH authorizeDocumentAccess.
  //   This explicitly proves that without the middleware, an unauthorized user
  //   gets 200 OK (security breach), whereas WITH the middleware, they are blocked (403).
  // ===========================================================================
  it('10. Missing authorization middleware causes security tests to fail', async () => {
    // Setup test document in DB
    const doc = await db.createDocument({
      title: 'Secret_Kernel_Dump.pdf',
      owner_id: ownerUser.id,
      storage_path: 'vault/u2/secret.pdf',
      original_filename: 'dump.pdf',
      file_size_bytes: 1024,
      mime_type: 'application/pdf',
      file_hash_sha256: 'a'.repeat(64)
    });

    // Sub-App 1: Vulnerable test router (simulates developer omitting authorizeDocumentAccess)
    const vulnerableApp = express();
    vulnerableApp.use(express.json());
    vulnerableApp.get(
      '/api/test-docs/:id',
      authenticateToken,
      // NOTE: authorizeDocumentAccess is MISSING here!
      async (req, res) => {
        const item = await db.getDocumentById(req.params.id);
        res.json({ document: item });
      }
    );

    // Alice requests User B's document through the vulnerable endpoint
    const vulnerableRes = await request(vulnerableApp)
      .get(`/api/test-docs/${doc.id}`)
      .set('Authorization', `Bearer ${aliceToken}`);

    // In the absence of the middleware, Alice inappropriately obtains the document (Status 200)
    expect(vulnerableRes.status).toBe(200);
    expect(vulnerableRes.body.document.id).toBe(doc.id);

    // Sub-App 2: Secured test router (WITH authorizeDocumentAccess properly applied)
    const securedApp = express();
    securedApp.use(express.json());
    securedApp.get(
      '/api/test-docs/:id',
      authenticateToken,
      authorizeDocumentAccess({ requiredPermission: 'read' }), // Load-bearing security guard
      async (req, res) => {
        res.json({ document: req.document });
      }
    );

    // Alice requests User B's document through the secured endpoint
    const securedRes = await request(securedApp)
      .get(`/api/test-docs/${doc.id}`)
      .set('Authorization', `Bearer ${aliceToken}`);

    // With the middleware, Alice is strictly blocked with 403 Forbidden
    expect(securedRes.status).toBe(403);
    expect(securedRes.body.code).toBe('DOCUMENT_ACCESS_DENIED');
  });

  // ===========================================================================
  // TEST 11: Admin inspection vs content bypass separation
  // The admin can inspect permission metadata and audit events but cannot
  // bypass content authorization.
  // ===========================================================================
  it('11. Admin can inspect permission metadata and audit events but cannot bypass content authorization', async () => {
    // Owner uploads document
    const uploadRes = await request(app)
      .post('/api/documents')
      .set('Authorization', `Bearer ${ownerToken}`)
      .field('title', 'Executive_Whistleblower_Complaint.pdf')
      .attach('file', samplePdf, 'complaint.pdf');
    const docId = uploadRes.body.document.id;

    // Owner grants read access to Alice
    await request(app)
      .post(`/api/documents/${docId}/permissions`)
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({ user_id: aliceUser.id, permission_level: 'read' });

    // A. Administrator CAN inspect permission metadata for compliance auditing
    const adminPermRes = await request(app)
      .get(`/api/documents/${docId}/permissions`)
      .set('Authorization', `Bearer ${adminToken}`);
    expect(adminPermRes.status).toBe(200);
    expect(adminPermRes.body.total_grants).toBe(1);
    expect(adminPermRes.body.permissions[0].user_id).toBe(aliceUser.id);

    // B. Administrator CANNOT read document content metadata (BLOCKED)
    const adminContentRes = await request(app)
      .get(`/api/documents/${docId}`)
      .set('Authorization', `Bearer ${adminToken}`);
    expect(adminContentRes.status).toBe(403);
    expect(adminContentRes.body.code).toBe('DOCUMENT_ACCESS_DENIED');
    expect(adminContentRes.body.error).toContain('blocks administrator blanket access');

    // C. Administrator CANNOT download document file stream (BLOCKED)
    const adminDownloadRes = await request(app)
      .get(`/api/documents/${docId}/download`)
      .set('Authorization', `Bearer ${adminToken}`);
    expect(adminDownloadRes.status).toBe(403);
    expect(adminDownloadRes.body.code).toBe('DOCUMENT_ACCESS_DENIED');

    // D. Administrator CANNOT grant or revoke permissions on Owner's document (BLOCKED)
    const adminGrantRes = await request(app)
      .post(`/api/documents/${docId}/permissions`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ user_id: viewerUser.id, permission_level: 'read' });
    expect(adminGrantRes.status).toBe(403);
    expect(adminGrantRes.body.code).toBe('OWNER_ONLY_OPERATION');

    // E. Administrator CAN inspect global audit trail
    const adminAuditRes = await request(app)
      .get('/api/admin/audit-logs')
      .set('Authorization', `Bearer ${adminToken}`);
    expect(adminAuditRes.status).toBe(200);
    expect(adminAuditRes.body.logs.length).toBeGreaterThan(0);
  });
});
