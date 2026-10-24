const request = require('supertest');
const app = require('../src/app');
const db = require('../src/db/db');
const storageService = require('../src/services/storageService');
const { generateToken } = require('../src/controllers/authController');

describe('📦 TrustVault Document Management Integration Test Suite', () => {
  let adminUser;
  let ownerUser;
  let secondaryOwner;
  let viewerUser;

  let adminToken;
  let ownerToken;
  let secondaryOwnerToken;
  let viewerToken;

  // Valid PDF binary header buffer
  const validPdfBuffer = Buffer.from('%PDF-1.5\n%Valid enterprise document content\n%%EOF');
  // Valid PNG binary buffer
  const validPngBuffer = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D]);
  // Valid JPEG binary buffer
  const validJpegBuffer = Buffer.from([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46]);

  beforeEach(async () => {
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
  // 1. ALLOWED ACCESS
  // ===========================================================================
  describe('1. Allowed Access Workflows', () => {
    it('should allow document owner to upload, list, view metadata, and stream download', async () => {
      // 1. Upload document with category and tags
      const uploadRes = await request(app)
        .post('/api/documents')
        .set('Authorization', `Bearer ${ownerToken}`)
        .field('title', 'Q2_Financial_Audit_2026.pdf')
        .field('description', 'Confidential quarterly financials')
        .field('category_id', 'c1111111-1111-1111-1111-111111111111')
        .field('tags', 'financial, audit, q2-2026')
        .attach('file', validPdfBuffer, 'Q2_Financial_Audit_2026.pdf');

      expect(uploadRes.status).toBe(201);
      expect(uploadRes.body.document).toBeDefined();
      expect(uploadRes.body.document.title).toBe('Q2_Financial_Audit_2026.pdf');
      expect(uploadRes.body.document.tags).toEqual(['financial', 'audit', 'q2-2026']);
      // Sensitive internal storage path MUST NOT be exposed to client
      expect(uploadRes.body.document.storage_path).toBeUndefined();

      const docId = uploadRes.body.document.id;

      // 2. List documents
      const listRes = await request(app)
        .get('/api/documents')
        .set('Authorization', `Bearer ${ownerToken}`);

      expect(listRes.status).toBe(200);
      expect(listRes.body.documents.some(d => d.id === docId)).toBe(true);

      // 3. View document metadata
      const metaRes = await request(app)
        .get(`/api/documents/${docId}`)
        .set('Authorization', `Bearer ${ownerToken}`);

      expect(metaRes.status).toBe(200);
      expect(metaRes.body.document.id).toBe(docId);
      expect(metaRes.body.document.title).toBe('Q2_Financial_Audit_2026.pdf');
      expect(metaRes.body.document.category_name).toBe('Financial Reports');
      expect(metaRes.body.document.tags).toContain('financial');
      expect(metaRes.body.document.user_access_level).toBe('owner');
      expect(metaRes.body.document.storage_path).toBeUndefined();

      // 4. Download document stream
      const downloadRes = await request(app)
        .get(`/api/documents/${docId}/download`)
        .set('Authorization', `Bearer ${ownerToken}`);

      expect(downloadRes.status).toBe(200);
      expect(downloadRes.headers['x-content-type-options']).toBe('nosniff');
      expect(downloadRes.headers['content-disposition']).toContain('attachment');
      expect(downloadRes.headers['cache-control']).toContain('no-store');
      expect(downloadRes.body.toString()).toContain('%PDF-1.5');
    });

    it('should allow collaborator with read access to view metadata and download, but not edit', async () => {
      // Owner uploads a document
      const uploadRes = await request(app)
        .post('/api/documents')
        .set('Authorization', `Bearer ${ownerToken}`)
        .field('title', 'Shared_Architecture_Doc.pdf')
        .attach('file', validPdfBuffer, 'architecture.pdf');
      const docId = uploadRes.body.document.id;

      // Owner grants 'read' access to viewer
      await request(app)
        .post(`/api/documents/${docId}/permissions`)
        .set('Authorization', `Bearer ${ownerToken}`)
        .send({ user_id: viewerUser.id, permission_level: 'read' });

      // Viewer reads metadata
      const metaRes = await request(app)
        .get(`/api/documents/${docId}`)
        .set('Authorization', `Bearer ${viewerToken}`);
      expect(metaRes.status).toBe(200);
      expect(metaRes.body.document.user_access_level).toBe('read');

      // Viewer downloads document stream
      const streamRes = await request(app)
        .get(`/api/documents/${docId}/download`)
        .set('Authorization', `Bearer ${viewerToken}`);
      expect(streamRes.status).toBe(200);
      expect(streamRes.body.toString()).toContain('%PDF-1.5');

      // Viewer attempts to update metadata -> 403 Forbidden
      const updateRes = await request(app)
        .patch(`/api/documents/${docId}`)
        .set('Authorization', `Bearer ${viewerToken}`)
        .send({ title: 'Unauthorized Modification' });
      expect(updateRes.status).toBe(403);
      expect(updateRes.body.code).toBe('INSUFFICIENT_DOCUMENT_PERMISSION');
    });

    it('should allow collaborator with edit access to update metadata and tags', async () => {
      // Owner uploads document
      const uploadRes = await request(app)
        .post('/api/documents')
        .set('Authorization', `Bearer ${ownerToken}`)
        .field('title', 'Draft_Legal_Agreement.pdf')
        .field('tags', 'draft, legal')
        .attach('file', validPdfBuffer, 'draft.pdf');
      const docId = uploadRes.body.document.id;

      // Owner grants 'edit' access to secondary owner (Alice)
      await request(app)
        .post(`/api/documents/${docId}/permissions`)
        .set('Authorization', `Bearer ${ownerToken}`)
        .send({ user_id: secondaryOwner.id, permission_level: 'edit' });

      // Alice updates metadata and tags
      const updateRes = await request(app)
        .patch(`/api/documents/${docId}`)
        .set('Authorization', `Bearer ${secondaryOwnerToken}`)
        .send({
          title: 'Finalized_Legal_Agreement.pdf',
          description: 'Reviewed and amended by Legal counsel',
          tags: ['finalized', 'legal', 'approved']
        });

      expect(updateRes.status).toBe(200);
      expect(updateRes.body.document.title).toBe('Finalized_Legal_Agreement.pdf');
      expect(updateRes.body.document.tags).toEqual(['finalized', 'legal', 'approved']);

      // Alice attempts to delete document -> 403 (Owner only policy)
      const deleteRes = await request(app)
        .delete(`/api/documents/${docId}`)
        .set('Authorization', `Bearer ${secondaryOwnerToken}`);
      expect(deleteRes.status).toBe(403);
      expect(deleteRes.body.code).toBe('OWNER_ONLY_OPERATION');
    });
  });

  // ===========================================================================
  // 2. UNAUTHORIZED ACCESS
  // ===========================================================================
  describe('2. Unauthorized Access & Privilege Enforcement', () => {
    let privateDocId;

    beforeEach(async () => {
      const uploadRes = await request(app)
        .post('/api/documents')
        .set('Authorization', `Bearer ${ownerToken}`)
        .field('title', 'Private_M&A_Strategy.pdf')
        .attach('file', validPdfBuffer, 'mna.pdf');
      privateDocId = uploadRes.body.document.id;
    });

    it('should reject unauthenticated requests without Authorization header (401)', async () => {
      const res = await request(app).get(`/api/documents/${privateDocId}`);
      expect(res.status).toBe(401);
      expect(res.body.code).toBe('AUTH_HEADER_MISSING');
    });

    it('should block viewer role from uploading documents (403)', async () => {
      const res = await request(app)
        .post('/api/documents')
        .set('Authorization', `Bearer ${viewerToken}`)
        .field('title', 'Viewer_Upload.pdf')
        .attach('file', validPdfBuffer, 'viewer.pdf');

      expect(res.status).toBe(403);
      expect(res.body.code).toBe('INSUFFICIENT_UPLOAD_ROLE');
    });

    it('should block unauthorized user from reading private metadata (403 IDOR)', async () => {
      const res = await request(app)
        .get(`/api/documents/${privateDocId}`)
        .set('Authorization', `Bearer ${secondaryOwnerToken}`);

      expect(res.status).toBe(403);
      expect(res.body.code).toBe('DOCUMENT_ACCESS_DENIED');
      // Verify no sensitive document metadata is leaked in the error
      expect(res.body.title).toBeUndefined();
      expect(res.body.storage_path).toBeUndefined();
    });

    it('should block unauthorized user from downloading document stream (403)', async () => {
      const res = await request(app)
        .get(`/api/documents/${privateDocId}/download`)
        .set('Authorization', `Bearer ${secondaryOwnerToken}`);

      expect(res.status).toBe(403);
      expect(res.body.code).toBe('DOCUMENT_ACCESS_DENIED');
    });

    it('should block administrator without delegation from reading or downloading private documents', async () => {
      // Admin attempts metadata read
      const metaRes = await request(app)
        .get(`/api/documents/${privateDocId}`)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(metaRes.status).toBe(403);
      expect(metaRes.body.code).toBe('DOCUMENT_ACCESS_DENIED');

      // Admin attempts file download
      const downloadRes = await request(app)
        .get(`/api/documents/${privateDocId}/download`)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(downloadRes.status).toBe(403);
      expect(downloadRes.body.code).toBe('DOCUMENT_ACCESS_DENIED');
    });
  });

  // ===========================================================================
  // 3. TAMPERED IDS & PATH TRAVERSAL
  // ===========================================================================
  describe('3. Tampered IDs & Parameter Integrity', () => {
    it('should reject path traversal in document ID parameter (400)', async () => {
      const res = await request(app)
        .get('/api/documents/..%2F..%2Fetc%2Fpasswd')
        .set('Authorization', `Bearer ${ownerToken}`);

      expect(res.status).toBe(400);
      expect(res.body.code).toBe('INVALID_DOCUMENT_ID');
    });

    it('should return 404 for non-existent document UUID', async () => {
      const nonExistentUuid = '00000000-0000-0000-0000-000000000000';
      const res = await request(app)
        .get(`/api/documents/${nonExistentUuid}`)
        .set('Authorization', `Bearer ${ownerToken}`);

      expect(res.status).toBe(404);
      expect(res.body.code).toBe('DOCUMENT_NOT_FOUND');
    });

    it('should ignore client-supplied owner_id or storage_path during upload and derive them safely', async () => {
      const res = await request(app)
        .post('/api/documents')
        .set('Authorization', `Bearer ${secondaryOwnerToken}`)
        .field('title', 'Spoof_Owner_Attempt.pdf')
        .field('owner_id', ownerUser.id) // Attempt to spoof owner as Primary Owner
        .field('storage_path', 'vault/hacked/trojan.pdf') // Attempt to inject custom storage path
        .attach('file', validPdfBuffer, 'spoof.pdf');

      expect(res.status).toBe(201);
      // The owner MUST be Alice (the authenticated caller from JWT), not the spoofed ownerUser
      expect(res.body.document.owner_id).toBe(secondaryOwner.id);
      expect(res.body.document.owner_id).not.toBe(ownerUser.id);
      expect(res.body.document.storage_path).toBeUndefined();

      // Verify in DB directly
      const created = await db.getDocumentById(res.body.document.id);
      expect(created.owner_id).toBe(secondaryOwner.id);
      expect(created.storage_path).not.toBe('vault/hacked/trojan.pdf');
      expect(created.storage_path).toContain(secondaryOwner.id);
    });
  });

  // ===========================================================================
  // 4. MALFORMED UPLOADS
  // ===========================================================================
  describe('4. Malformed Uploads', () => {
    it('should reject upload when file attachment is missing (400)', async () => {
      const res = await request(app)
        .post('/api/documents')
        .set('Authorization', `Bearer ${ownerToken}`)
        .field('title', 'Document_Without_File.pdf');

      expect(res.status).toBe(400);
      expect(res.body.code).toBe('MISSING_FILE');
    });

    it('should reject upload when file is empty / 0 bytes (400)', async () => {
      const emptyBuffer = Buffer.alloc(0);
      const res = await request(app)
        .post('/api/documents')
        .set('Authorization', `Bearer ${ownerToken}`)
        .field('title', 'Empty_File.pdf')
        .attach('file', emptyBuffer, 'empty.pdf');

      expect(res.status).toBe(400);
      expect(res.body.code).toBe('EMPTY_FILE');
    });

    it('should reject upload when document title is missing or whitespace (400)', async () => {
      const res = await request(app)
        .post('/api/documents')
        .set('Authorization', `Bearer ${ownerToken}`)
        .field('title', '   ')
        .attach('file', validPdfBuffer, 'blank_title.pdf');

      expect(res.status).toBe(400);
      expect(res.body.code).toBe('MISSING_TITLE');
    });
  });

  // ===========================================================================
  // 5. OVERSIZED FILES
  // ===========================================================================
  describe('5. Oversized Files', () => {
    it('should reject uploads exceeding 10MB limit with 400 FILE_TOO_LARGE', async () => {
      // 10.5 MB buffer
      const largeBuffer = Buffer.alloc(10.5 * 1024 * 1024, 0x25); // % repeated

      const res = await request(app)
        .post('/api/documents')
        .set('Authorization', `Bearer ${ownerToken}`)
        .field('title', 'Too_Large_Audit.pdf')
        .attach('file', largeBuffer, 'huge.pdf');

      expect(res.status).toBe(400);
      expect(res.body.code).toBe('FILE_TOO_LARGE');

      // Verify security audit denial log
      const logs = await db.getAuditLogs({ action: 'DOCUMENT_UPLOAD_DENIED' });
      expect(logs.logs.length).toBeGreaterThan(0);
      expect(logs.logs[0].details.reason).toContain('exceeds maximum size');
    });
  });

  // ===========================================================================
  // 6. INVALID FILE TYPES & MALWARE INSPECTION
  // ===========================================================================
  describe('6. Invalid File Types & Malware Safeguards', () => {
    it('should reject prohibited executable extensions (.exe, .sh) (400)', async () => {
      const res = await request(app)
        .post('/api/documents')
        .set('Authorization', `Bearer ${ownerToken}`)
        .field('title', 'Exploit_Payload.exe')
        .attach('file', Buffer.from('echo hacked'), 'payload.exe');

      expect(res.status).toBe(400);
      expect(res.body.code).toBe('FILE_VALIDATION_ERROR');
      expect(res.body.error).toContain('prohibited due to security policy');
    });

    it('should reject SVG files to prevent Stored Cross-Site Scripting (XSS)', async () => {
      const svgPayload = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.cookie)</script></svg>');
      const res = await request(app)
        .post('/api/documents')
        .set('Authorization', `Bearer ${ownerToken}`)
        .field('title', 'Logo.svg')
        .attach('file', svgPayload, 'logo.svg');

      expect(res.status).toBe(400);
      expect(res.body.code).toBe('FILE_VALIDATION_ERROR');
    });

    it('should reject file disguised as PDF with Windows MZ executable magic bytes', async () => {
      const fakePdfMz = Buffer.from([0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]);
      const res = await request(app)
        .post('/api/documents')
        .set('Authorization', `Bearer ${ownerToken}`)
        .field('title', 'Trojan_Disguised.pdf')
        .attach('file', fakePdfMz, 'trojan.pdf');

      expect(res.status).toBe(400);
      expect(res.body.code).toBe('MAGIC_BYTES_MISMATCH');
    });

    it('should reject file with .pdf extension containing random non-PDF bytes', async () => {
      const randomGarbage = Buffer.from('HELLO_THIS_IS_NOT_A_PDF_DOCUMENT_BINARY');
      const res = await request(app)
        .post('/api/documents')
        .set('Authorization', `Bearer ${ownerToken}`)
        .field('title', 'Fake_Header.pdf')
        .attach('file', randomGarbage, 'fake.pdf');

      expect(res.status).toBe(400);
      expect(res.body.code).toBe('MAGIC_BYTES_MISMATCH');
    });

    it('should allow valid PNG and JPEG image uploads with correct magic headers', async () => {
      // PNG
      const pngRes = await request(app)
        .post('/api/documents')
        .set('Authorization', `Bearer ${ownerToken}`)
        .field('title', 'Network_Diagram.png')
        .attach('file', validPngBuffer, 'diagram.png');
      expect(pngRes.status).toBe(201);
      expect(pngRes.body.document.mime_type).toBe('image/png');

      // JPEG
      const jpegRes = await request(app)
        .post('/api/documents')
        .set('Authorization', `Bearer ${ownerToken}`)
        .field('title', 'Security_Badge.jpeg')
        .attach('file', validJpegBuffer, 'badge.jpeg');
      expect(jpegRes.status).toBe(201);
      expect(jpegRes.body.document.mime_type).toBe('image/jpeg');
    });
  });

  // ===========================================================================
  // 7. DELETION & LIFECYCLE
  // ===========================================================================
  describe('7. Document Deletion & Lifecycle', () => {
    let docToDelete;

    beforeEach(async () => {
      const uploadRes = await request(app)
        .post('/api/documents')
        .set('Authorization', `Bearer ${ownerToken}`)
        .field('title', 'Document_To_Be_Deleted.pdf')
        .attach('file', validPdfBuffer, 'delete_me.pdf');
      docToDelete = uploadRes.body.document;
    });

    it('should allow document owner to delete document (soft delete)', async () => {
      const deleteRes = await request(app)
        .delete(`/api/documents/${docToDelete.id}`)
        .set('Authorization', `Bearer ${ownerToken}`);

      expect(deleteRes.status).toBe(200);
      expect(deleteRes.body.documentId).toBe(docToDelete.id);

      // Verify document is no longer listed
      const listRes = await request(app)
        .get('/api/documents')
        .set('Authorization', `Bearer ${ownerToken}`);
      expect(listRes.body.documents.some(d => d.id === docToDelete.id)).toBe(false);

      // Verify subsequent GET returns 404
      const getRes = await request(app)
        .get(`/api/documents/${docToDelete.id}`)
        .set('Authorization', `Bearer ${ownerToken}`);
      expect(getRes.status).toBe(404);
      expect(getRes.body.code).toBe('DOCUMENT_NOT_FOUND');

      // Verify subsequent download returns 404
      const downloadRes = await request(app)
        .get(`/api/documents/${docToDelete.id}/download`)
        .set('Authorization', `Bearer ${ownerToken}`);
      expect(downloadRes.status).toBe(404);

      // Verify immutable audit log recorded the deletion
      const logs = await db.getAuditLogs({ action: 'DOCUMENT_DELETED' });
      expect(logs.logs.length).toBeGreaterThan(0);
      expect(logs.logs[0].document_id).toBe(docToDelete.id);
    });

    it('should block non-owners from deleting document (403)', async () => {
      const deleteRes = await request(app)
        .delete(`/api/documents/${docToDelete.id}`)
        .set('Authorization', `Bearer ${secondaryOwnerToken}`);

      expect(deleteRes.status).toBe(403);
      expect(deleteRes.body.code).toBe('OWNER_ONLY_OPERATION');

      // Document still exists
      const checkRes = await request(app)
        .get(`/api/documents/${docToDelete.id}`)
        .set('Authorization', `Bearer ${ownerToken}`);
      expect(checkRes.status).toBe(200);
    });
  });

  // ===========================================================================
  // 8. SEARCH, FILTERING & ISOLATION
  // ===========================================================================
  describe('8. Search, Filtering & Discovery Isolation', () => {
    beforeEach(async () => {
      // Owner creates Financial doc with tags
      await request(app)
        .post('/api/documents')
        .set('Authorization', `Bearer ${ownerToken}`)
        .field('title', 'Alpha_Tax_Filing.pdf')
        .field('description', 'Q1 Internal Tax Audit Records')
        .field('category_id', 'c1111111-1111-1111-1111-111111111111') // Financial Reports
        .field('tags', 'tax, audit, 2026')
        .attach('file', validPdfBuffer, 'tax.pdf');

      // Owner creates Engineering doc
      await request(app)
        .post('/api/documents')
        .set('Authorization', `Bearer ${ownerToken}`)
        .field('title', 'Beta_Kubernetes_Cluster_Security.pdf')
        .field('description', 'Zero trust architecture blueprint')
        .field('category_id', 'c3333333-3333-3333-3333-333333333333') // Engineering
        .field('tags', 'kubernetes, zero-trust, devops')
        .attach('file', validPdfBuffer, 'k8s.pdf');

      // Alice (Secondary Owner) creates confidential HR doc
      await request(app)
        .post('/api/documents')
        .set('Authorization', `Bearer ${secondaryOwnerToken}`)
        .field('title', 'Gamma_Executive_Bonus_Plan.pdf')
        .field('description', 'Confidential executive bonuses for 2026')
        .field('category_id', 'c4444444-4444-4444-4444-444444444444') // Human Resources
        .field('tags', 'compensation, executive, hr')
        .attach('file', validPdfBuffer, 'bonus.pdf');
    });

    it('should isolate search results: Primary Owner cannot discover Alice documents', async () => {
      const res = await request(app)
        .get('/api/documents?search=Bonus')
        .set('Authorization', `Bearer ${ownerToken}`);

      expect(res.status).toBe(200);
      expect(res.body.documents.length).toBe(0);
    });

    it('should filter documents by category', async () => {
      const res = await request(app)
        .get('/api/documents?category=c3333333-3333-3333-3333-333333333333')
        .set('Authorization', `Bearer ${ownerToken}`);

      expect(res.status).toBe(200);
      expect(res.body.documents.length).toBe(1);
      expect(res.body.documents[0].title).toBe('Beta_Kubernetes_Cluster_Security.pdf');
    });

    it('should filter documents by tag', async () => {
      const res = await request(app)
        .get('/api/documents?tag=devops')
        .set('Authorization', `Bearer ${ownerToken}`);

      expect(res.status).toBe(200);
      expect(res.body.documents.length).toBe(1);
      expect(res.body.documents[0].title).toBe('Beta_Kubernetes_Cluster_Security.pdf');
    });

    it('should search documents across title, description, or tags', async () => {
      // Search matching tag 'tax'
      const res = await request(app)
        .get('/api/documents?search=tax')
        .set('Authorization', `Bearer ${ownerToken}`);

      expect(res.status).toBe(200);
      expect(res.body.documents.some(d => d.title === 'Alpha_Tax_Filing.pdf')).toBe(true);
    });

    it('should filter documents by owner email or name', async () => {
      const res = await request(app)
        .get('/api/documents?owner=owner@trustvault.internal')
        .set('Authorization', `Bearer ${ownerToken}`);

      expect(res.status).toBe(200);
      expect(res.body.documents.every(d => d.owner_id === ownerUser.id)).toBe(true);
    });
  });

  // ===========================================================================
  // 9. PARTIAL UPLOAD FAILURE & STORAGE CONSISTENCY (ROLLBACK)
  // ===========================================================================
  describe('9. Storage & Database Consistency on Partial Upload Failures', () => {
    it('should clean up storage vault when database insertion fails during upload', async () => {
      // Spy on db.createDocument to throw simulated exception
      const originalCreate = db.createDocument.bind(db);
      jest.spyOn(db, 'createDocument').mockImplementationOnce(async () => {
        throw new Error('Simulated Database Crash during document insertion');
      });

      const spyDelete = jest.spyOn(storageService, 'deleteFile');

      const res = await request(app)
        .post('/api/documents')
        .set('Authorization', `Bearer ${ownerToken}`)
        .field('title', 'Failure_Simulation.pdf')
        .attach('file', validPdfBuffer, 'fail.pdf');

      expect(res.status).toBe(500);
      expect(res.body.error).toContain('Failed to process and store document');

      // Verify storage rollback cleanup was triggered
      expect(spyDelete).toHaveBeenCalled();

      // Restore original
      jest.restoreAllMocks();
    });
  });
});
