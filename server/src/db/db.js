const { randomUUID: uuidv4 } = require('crypto');
const { computeAuditHash, verifyAuditChain, GENESIS_HASH } = require('../services/hashChainService');
const { sanitizeString, sanitizeAuditDetails, sanitizeAction, sanitizeStatus } = require('../utils/auditSanitizer');

/**
 * In-Memory & Supabase-Compatible Data Store
 * Provides ACID-like in-process relational semantics with strict foreign keys,
 * unique constraints, immutability triggers, and seed data.
 */
class TrustVaultDatabase {
  constructor() {
    this.reset();
  }

  reset() {
    this.profiles = new Map();
    this.categories = new Map();
    this.documents = new Map();
    this.documentPermissions = new Map(); // key: `${document_id}:${user_id}`
    this.auditLogs = []; // Array of audit log records, ordered by id
    this.auditLogIdCounter = 1;

    this.seedDefaults();
  }

  seedDefaults() {
    // Seed Categories
    const defaultCategories = [
      { id: 'c1111111-1111-1111-1111-111111111111', name: 'Financial Reports', description: 'Quarterly earnings, audits, balance sheets, tax filings' },
      { id: 'c2222222-2222-2222-2222-222222222222', name: 'Legal & Compliance', description: 'NDAs, customer contracts, regulatory agreements, licenses' },
      { id: 'c3333333-3333-3333-3333-333333333333', name: 'Engineering & Architecture', description: 'System designs, security specs, API schemas, blueprints' },
      { id: 'c4444444-4444-4444-4444-444444444444', name: 'Human Resources', description: 'Offer letters, compensation guidelines, performance reviews' },
      { id: 'c5555555-5555-5555-5555-555555555555', name: 'General Enterprise', description: 'Company policies, handbooks, general memos' }
    ];

    for (const cat of defaultCategories) {
      this.categories.set(cat.id, { ...cat, created_at: new Date('2026-01-01T00:00:00.000Z') });
    }

    // Seed Demo Profiles
    const defaultProfiles = [
      {
        id: 'u1111111-1111-1111-1111-111111111111',
        email: 'admin@trustvault.internal',
        full_name: 'Security Administrator',
        system_role: 'administrator',
        password: 'password123',
        is_active: true,
        created_at: new Date('2026-01-01T00:00:00.000Z'),
        updated_at: new Date('2026-01-01T00:00:00.000Z')
      },
      {
        id: 'u2222222-2222-2222-2222-222222222222',
        email: 'owner@trustvault.internal',
        full_name: 'Primary Document Owner',
        system_role: 'document_owner',
        password: 'password123',
        is_active: true,
        created_at: new Date('2026-01-01T00:00:00.000Z'),
        updated_at: new Date('2026-01-01T00:00:00.000Z')
      },
      {
        id: 'u3333333-3333-3333-3333-333333333333',
        email: 'alice@trustvault.internal',
        full_name: 'Alice Cooper (Secondary Owner)',
        system_role: 'document_owner',
        password: 'password123',
        is_active: true,
        created_at: new Date('2026-01-02T00:00:00.000Z'),
        updated_at: new Date('2026-01-02T00:00:00.000Z')
      },
      {
        id: 'u4444444-4444-4444-4444-444444444444',
        email: 'viewer@trustvault.internal',
        full_name: 'External Audit Viewer',
        system_role: 'viewer',
        password: 'password123',
        is_active: true,
        created_at: new Date('2026-01-03T00:00:00.000Z'),
        updated_at: new Date('2026-01-03T00:00:00.000Z')
      }
    ];

    for (const p of defaultProfiles) {
      this.profiles.set(p.id, p);
    }

    // Seed Sample Document for Primary Owner
    const sampleDocId = 'd1111111-1111-1111-1111-111111111111';
    this.documents.set(sampleDocId, {
      id: sampleDocId,
      title: 'Q1_2026_Enterprise_Security_Audit.pdf',
      description: 'Confidential executive summary of perimeter security and penetration test results.',
      category_id: 'c1111111-1111-1111-1111-111111111111',
      owner_id: 'u2222222-2222-2222-2222-222222222222',
      storage_path: 'vault/u2222222-2222-2222-2222-222222222222/sample-q1-audit.pdf',
      original_filename: 'Q1_2026_Enterprise_Security_Audit.pdf',
      file_size_bytes: 142580,
      mime_type: 'application/pdf',
      file_hash_sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
      tags: ['audit', 'q1-2026', 'confidential', 'security'],
      is_deleted: false,
      created_at: new Date('2026-01-15T10:00:00.000Z'),
      updated_at: new Date('2026-01-15T10:00:00.000Z')
    });

    // Seed Initial Genesis Audit Log
    this.addAuditLogSync({
      userId: 'u1111111-1111-1111-1111-111111111111',
      userEmail: 'admin@trustvault.internal',
      action: 'SYSTEM_INITIALIZATION',
      status: 'SUCCESS',
      documentId: null,
      documentTitle: null,
      requestId: 'req-genesis-system-init',
      ipAddress: '127.0.0.1',
      userAgent: 'TrustVault System Kernel',
      details: { message: 'TrustVault security kernel initialized with genesis hash.' }
    });
  }

  // --- Profile Operations ---
  async getProfileById(id) {
    return this.profiles.get(id) || null;
  }

  async getProfileByEmail(email) {
    if (!email) return null;
    const normalized = email.toLowerCase().trim();
    for (const p of this.profiles.values()) {
      if (p.email.toLowerCase() === normalized) return p;
    }
    return null;
  }

  async createProfile({ id = uuidv4(), email, full_name, system_role = 'viewer', password = null, is_active = true }) {
    const existing = await this.getProfileByEmail(email);
    if (existing) {
      throw new Error(`Profile with email ${email} already exists`);
    }
    const profile = {
      id,
      email: email.toLowerCase().trim(),
      full_name,
      system_role,
      password,
      is_active,
      created_at: new Date(),
      updated_at: new Date()
    };
    this.profiles.set(id, profile);
    return profile;
  }

  async updateProfile(id, updates) {
    const profile = this.profiles.get(id);
    if (!profile) return null;
    const allowed = ['full_name', 'system_role', 'is_active'];
    for (const key of allowed) {
      if (updates[key] !== undefined) {
        profile[key] = updates[key];
      }
    }
    profile.updated_at = new Date();
    this.profiles.set(id, profile);
    return profile;
  }

  async getAllProfiles() {
    return Array.from(this.profiles.values()).map(p => ({
      id: p.id,
      email: p.email,
      full_name: p.full_name,
      system_role: p.system_role,
      is_active: p.is_active,
      created_at: p.created_at
    }));
  }

  // --- Category Operations ---
  async getAllCategories() {
    return Array.from(this.categories.values());
  }

  async getCategoryById(id) {
    return this.categories.get(id) || null;
  }

  async createCategory({ name, description }) {
    for (const cat of this.categories.values()) {
      if (cat.name.toLowerCase() === name.toLowerCase().trim()) {
        throw new Error(`Category ${name} already exists`);
      }
    }
    const cat = {
      id: uuidv4(),
      name: name.trim(),
      description: description ? description.trim() : '',
      created_at: new Date()
    };
    this.categories.set(cat.id, cat);
    return cat;
  }

  // --- Document Operations ---
  async createDocument({
    id = uuidv4(),
    title,
    description = '',
    category_id = null,
    owner_id,
    storage_path,
    original_filename,
    file_size_bytes,
    mime_type,
    file_hash_sha256,
    tags = []
  }) {
    if (!this.profiles.has(owner_id)) {
      throw new Error(`Foreign key violation: owner_id ${owner_id} does not exist`);
    }
    if (category_id && !this.categories.has(category_id)) {
      throw new Error(`Foreign key violation: category_id ${category_id} does not exist`);
    }

    const cleanTags = Array.isArray(tags)
      ? Array.from(new Set(tags.map(t => String(t).trim().toLowerCase()).filter(Boolean)))
      : [];

    const doc = {
      id,
      title: title.trim(),
      description: description ? description.trim() : '',
      category_id,
      owner_id,
      storage_path,
      original_filename,
      file_size_bytes,
      mime_type,
      file_hash_sha256,
      tags: cleanTags,
      is_deleted: false,
      created_at: new Date(),
      updated_at: new Date()
    };
    this.documents.set(id, doc);
    return doc;
  }

  async getDocumentById(id) {
    const doc = this.documents.get(id);
    if (!doc || doc.is_deleted) return null;
    return doc;
  }

  async updateDocument(id, updates) {
    const doc = this.documents.get(id);
    if (!doc || doc.is_deleted) return null;
    if (updates.title !== undefined) doc.title = updates.title.trim();
    if (updates.description !== undefined) doc.description = updates.description.trim();
    if (updates.category_id !== undefined) {
      if (updates.category_id && !this.categories.has(updates.category_id)) {
        throw new Error(`Foreign key violation: category_id ${updates.category_id} does not exist`);
      }
      doc.category_id = updates.category_id;
    }
    if (updates.tags !== undefined) {
      doc.tags = Array.isArray(updates.tags)
        ? Array.from(new Set(updates.tags.map(t => String(t).trim().toLowerCase()).filter(Boolean)))
        : [];
    }
    doc.updated_at = new Date();
    this.documents.set(id, doc);
    return doc;
  }

  async softDeleteDocument(id) {
    const doc = this.documents.get(id);
    if (!doc) return false;
    doc.is_deleted = true;
    doc.updated_at = new Date();
    this.documents.set(id, doc);
    return true;
  }

  async listDocumentsForUser(userId, systemRole, filters = {}) {
    const results = [];
    const { search, category, owner, dateFrom, dateTo, tag } = filters;

    for (const doc of this.documents.values()) {
      if (doc.is_deleted) continue;

      // Access control condition:
      // A user can see document if they are the owner OR have granted permission
      const isOwner = doc.owner_id === userId;
      const permKey = `${doc.id}:${userId}`;
      const hasPermission = this.documentPermissions.has(permKey);

      // Note: Even administrators DO NOT see private documents unless they own it or have explicit permission
      if (!isOwner && !hasPermission) {
        continue;
      }

      // Filter: Search query (case-insensitive in title, description, or tags)
      if (search) {
        const query = search.toLowerCase().trim();
        const matchesTitle = doc.title.toLowerCase().includes(query);
        const matchesDesc = (doc.description || '').toLowerCase().includes(query);
        const matchesTag = (doc.tags || []).some(t => t.toLowerCase().includes(query));
        if (!matchesTitle && !matchesDesc && !matchesTag) continue;
      }

      // Filter: Category
      if (category && doc.category_id !== category) {
        continue;
      }

      // Filter: Tag
      if (tag) {
        const queryTag = tag.toLowerCase().trim();
        const hasTag = (doc.tags || []).some(t => t.toLowerCase() === queryTag);
        if (!hasTag) continue;
      }

      // Filter: Owner (matches owner UUID, or email, or full name)
      if (owner) {
        const ownerProfile = this.profiles.get(doc.owner_id);
        const oQuery = owner.toLowerCase().trim();
        const matchesOwnerId = doc.owner_id.toLowerCase() === oQuery;
        const matchesEmail = ownerProfile && ownerProfile.email.toLowerCase().includes(oQuery);
        const matchesName = ownerProfile && ownerProfile.full_name.toLowerCase().includes(oQuery);
        if (!matchesOwnerId && !matchesEmail && !matchesName) {
          continue;
        }
      }

      // Filter: Date Range
      if (dateFrom && new Date(doc.created_at) < new Date(dateFrom)) {
        continue;
      }
      if (dateTo && new Date(doc.created_at) > new Date(dateTo)) {
        continue;
      }

      const ownerProfile = this.profiles.get(doc.owner_id);
      const categoryObj = doc.category_id ? this.categories.get(doc.category_id) : null;
      const permissionObj = isOwner ? { permission_level: 'owner' } : this.documentPermissions.get(permKey);

      results.push({
        ...doc,
        tags: doc.tags || [],
        owner_name: ownerProfile ? ownerProfile.full_name : 'Unknown Owner',
        owner_email: ownerProfile ? ownerProfile.email : '',
        category_name: categoryObj ? categoryObj.name : 'Uncategorized',
        user_access_level: isOwner ? 'owner' : permissionObj.permission_level
      });
    }

    // Sort by created_at descending
    return results.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  }

  // --- Document Permission Operations ---
  async getPermissionsForDocument(documentId) {
    const results = [];
    for (const [key, perm] of this.documentPermissions.entries()) {
      if (perm.document_id === documentId) {
        const user = this.profiles.get(perm.user_id);
        const granter = this.profiles.get(perm.granted_by);
        results.push({
          id: perm.id,
          document_id: perm.document_id,
          user_id: perm.user_id,
          user_email: user ? user.email : '',
          user_name: user ? user.full_name : '',
          permission_level: perm.permission_level,
          granted_by: perm.granted_by,
          granter_name: granter ? granter.full_name : '',
          created_at: perm.created_at
        });
      }
    }
    return results;
  }

  async getUserPermissionOnDocument(documentId, userId) {
    const doc = this.documents.get(documentId);
    if (!doc || doc.is_deleted) return null;

    if (doc.owner_id === userId) {
      return { permission_level: 'owner', isOwner: true };
    }

    const perm = this.documentPermissions.get(`${documentId}:${userId}`);
    if (perm) {
      return { permission_level: perm.permission_level, isOwner: false };
    }

    return null; // No permission
  }

  async grantPermission({ documentId, userId, permissionLevel, grantedBy }) {
    if (!this.documents.has(documentId)) {
      throw new Error(`Document ${documentId} does not exist`);
    }
    if (!this.profiles.has(userId)) {
      throw new Error(`User ${userId} does not exist`);
    }
    if (!['read', 'edit'].includes(permissionLevel)) {
      throw new Error(`Invalid permission level ${permissionLevel}`);
    }

    const doc = this.documents.get(documentId);
    if (doc.owner_id === userId) {
      throw new Error('Cannot grant permission to the document owner');
    }

    const key = `${documentId}:${userId}`;
    const existing = this.documentPermissions.get(key);
    const record = {
      id: existing ? existing.id : uuidv4(),
      document_id: documentId,
      user_id: userId,
      permission_level: permissionLevel,
      granted_by: grantedBy,
      created_at: existing ? existing.created_at : new Date(),
      updated_at: new Date()
    };
    this.documentPermissions.set(key, record);
    return record;
  }

  async revokePermission(documentId, userId) {
    const key = `${documentId}:${userId}`;
    return this.documentPermissions.delete(key);
  }

  // --- Audit Log Operations (Append-Only Cryptographic Ledger) ---
  addAuditLogSync({
    userId = null,
    userEmail = null,
    action,
    status = 'SUCCESS',
    documentId = null,
    documentTitle = null,
    requestId = null,
    ipAddress = '127.0.0.1',
    userAgent = 'System',
    details = {}
  }) {
    const id = this.auditLogIdCounter++;
    const timestamp = new Date();

    // 1. Sanitize inputs to prevent log injection (strip CRLF / control chars) and scrub credentials
    const cleanAction = sanitizeAction(action);
    const cleanStatus = sanitizeStatus(status);
    const cleanIp = sanitizeString(ipAddress, 45) || '127.0.0.1';
    const cleanUserAgent = sanitizeString(userAgent, 255) || 'Unknown';
    const cleanEmail = userEmail ? sanitizeString(userEmail, 255) : null;
    const cleanTitle = documentTitle ? sanitizeString(documentTitle, 255) : null;
    const cleanRequestId = requestId ? sanitizeString(requestId, 64) : null;
    const cleanDetails = sanitizeAuditDetails(details);

    // 2. Retrieve previous hash from the tail of the ledger
    const prevLog = this.auditLogs.length > 0 ? this.auditLogs[this.auditLogs.length - 1] : null;
    const previousHash = prevLog ? prevLog.current_hash : GENESIS_HASH;

    // 3. Calculate current HMAC-SHA256 hash
    const currentHash = computeAuditHash({
      previousHash,
      id,
      timestamp,
      userId,
      action: cleanAction,
      status: cleanStatus,
      documentId,
      requestId: cleanRequestId,
      details: cleanDetails
    });

    const logEntry = {
      id,
      timestamp,
      created_at: timestamp,
      user_id: userId,
      user_email: cleanEmail,
      action: cleanAction,
      status: cleanStatus,
      document_id: documentId,
      document_title: cleanTitle,
      request_id: cleanRequestId,
      ip_address: cleanIp,
      user_agent: cleanUserAgent,
      details: cleanDetails,
      previous_hash: previousHash,
      prev_hash: previousHash,
      current_hash: currentHash,
      entry_hash: currentHash
    };

    // Immutability rule: Once pushed, cannot be modified or deleted
    this.auditLogs.push(Object.freeze(logEntry));
    return logEntry;
  }

  async addAuditLog(entry) {
    return this.addAuditLogSync(entry);
  }

  // Application-level append-only guard (mirrors PostgreSQL trigger prevent_audit_log_tampering)
  updateAuditLog() {
    throw new Error('SECURITY VIOLATION: audit_logs is an append-only ledger. UPDATE and DELETE operations are strictly prohibited.');
  }

  deleteAuditLog() {
    throw new Error('SECURITY VIOLATION: audit_logs is an append-only ledger. UPDATE and DELETE operations are strictly prohibited.');
  }

  async getAuditLogs(filters = {}) {
    const {
      limit = 50,
      offset = 0,
      action,
      status,
      outcome,
      userId,
      actor,
      documentId,
      document,
      requestId,
      dateFrom,
      dateTo
    } = filters;

    let filtered = [...this.auditLogs];

    // Filter by action substring
    if (action) {
      const actLower = String(action).toLowerCase().trim();
      filtered = filtered.filter(l => l.action.toLowerCase().includes(actLower));
    }

    // Filter by status / outcome (SUCCESS, DENIED, ERROR)
    const targetStatus = outcome || status;
    if (targetStatus) {
      const stUpper = String(targetStatus).toUpperCase().trim();
      filtered = filtered.filter(l => l.status === stUpper);
    }

    // Filter by actor (UUID or Email)
    const targetActor = actor || userId;
    if (targetActor) {
      const actLower = String(targetActor).toLowerCase().trim();
      filtered = filtered.filter(l =>
        (l.user_id && l.user_id.toLowerCase().includes(actLower)) ||
        (l.user_email && l.user_email.toLowerCase().includes(actLower))
      );
    }

    // Filter by target document (UUID or Title)
    const targetDoc = document || documentId;
    if (targetDoc) {
      const docLower = String(targetDoc).toLowerCase().trim();
      filtered = filtered.filter(l =>
        (l.document_id && l.document_id.toLowerCase().includes(docLower)) ||
        (l.document_title && l.document_title.toLowerCase().includes(docLower))
      );
    }

    // Filter by request / correlation ID
    if (requestId) {
      const reqLower = String(requestId).toLowerCase().trim();
      filtered = filtered.filter(l => l.request_id && l.request_id.toLowerCase().includes(reqLower));
    }

    // Filter by date range (UTC)
    if (dateFrom) {
      const dFrom = new Date(dateFrom);
      filtered = filtered.filter(l => new Date(l.timestamp) >= dFrom);
    }
    if (dateTo) {
      const dTo = new Date(dateTo);
      filtered = filtered.filter(l => new Date(l.timestamp) <= dTo);
    }

    // Return in reverse chronological order
    const total = filtered.length;
    const sorted = filtered.sort((a, b) => Number(b.id) - Number(a.id));
    const paginated = sorted.slice(offset, offset + limit);

    return {
      total,
      limit,
      offset,
      logs: paginated
    };
  }

  async getAllAuditLogsForVerification() {
    return [...this.auditLogs];
  }

  // --- Testing Hook: Simulate Tampering to Verify Hash Chain Break ---
  tamperAuditLogForTesting(logId, tamperedPayload) {
    const index = this.auditLogs.findIndex(l => l.id === logId);
    if (index === -1) throw new Error(`Log with id ${logId} not found`);

    if (!this._originalUntamperedLogs) {
      this._originalUntamperedLogs = new Map();
    }
    if (!this._originalUntamperedLogs.has(logId)) {
      this._originalUntamperedLogs.set(logId, { ...this.auditLogs[index] });
    }

    // Force replace the frozen object to simulate out-of-band database hack
    const original = this.auditLogs[index];
    this.auditLogs[index] = {
      ...original,
      ...tamperedPayload
    };
  }

  // --- Testing Hook: Restore Tampered Log to Re-verify Clean Chain ---
  restoreAuditLogForTesting(logId) {
    const index = this.auditLogs.findIndex(l => l.id === logId);
    if (index === -1) throw new Error(`Log with id ${logId} not found`);

    if (this._originalUntamperedLogs && this._originalUntamperedLogs.has(logId)) {
      this.auditLogs[index] = this._originalUntamperedLogs.get(logId);
      this._originalUntamperedLogs.delete(logId);
      return this.auditLogs[index];
    }
    return this.auditLogs[index];
  }
}

// Global Singleton Database Instance
const db = new TrustVaultDatabase();

module.exports = db;
