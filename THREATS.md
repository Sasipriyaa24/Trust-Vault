# TrustVault Enterprise Threat Model & Security Register

## Document Overview
This document constitutes the authoritative Threat Register and Security Verification Matrix for **TrustVault**, an enterprise-grade secure document-sharing platform. Every threat analyzed below documents realistic attack scenarios, attacker capabilities, impact assessments, implemented code-level mitigations, exact source code paths, automated test verifications, and residual risks or consciously accepted operational limitations.

> **Verification Principle**: No mitigation is documented as implemented unless it is evidenced by active code paths and passing automated tests. Controls lacking full end-to-end automation are explicitly categorized as **Open Risks**.

---

## Threat Register

### 1. Insecure Direct Object Reference (IDOR / BOLA) via Document IDs
- **Realistic Attack Scenario**: An adversary authenticated as a standard viewer or external contractor discovers or iterates document UUIDs (e.g., sniffing network traffic, extracting UUIDs from browser history, or sequential enumeration) and sends `GET /api/documents/d1111111-1111-1111-1111-111111111111`. Without object-level authorization, the server would return confidential executive compensation files or proprietary patent filings belonging to another organization or department.
- **Attacker's Role & Prerequisites**: Authenticated user (`viewer` or `document_owner`). Prerequisites: Valid JWT access token and knowledge/guess of victim's document UUID.
- **Impact**: **High** — Breach of document confidentiality; unauthorized disclosure of internal enterprise records.
- **Mitigation Implemented**:
  1. Object-Level Access Control Middleware: `authorizeDocumentAccess({ requiredPermission: 'read' })` intercepts all requests to `/api/documents/:id`. It queries the authoritative document record and validates whether `doc.owner_id === req.user.id` or an active grant exists in `document_permissions` via `db.getUserPermissionOnDocument(doc.id, req.user.id)`.
  2. Database Engine Defense: PostgreSQL Row Level Security (RLS) policy `documents_select_policy` restricts row selection to `owner_id = auth.uid() OR EXISTS (SELECT 1 FROM document_permissions WHERE document_id = documents.id AND user_id = auth.uid())`.
  3. Non-Enumeration Response: Inaccessible or non-existent document IDs return a generic 403 `DOCUMENT_ACCESS_DENIED` or 404 `DOCUMENT_NOT_FOUND` without leaking metadata.
- **Exact Code Paths**:
  - [`server/src/middleware/roles.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/middleware/roles.js#L45-L203)
  - [`server/src/routes/documentRoutes.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/routes/documentRoutes.js#L18-L22)
  - [`server/src/db/migrations/003_row_level_security.sql`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/db/migrations/003_row_level_security.sql#L90-L105)
- **Exact Tests Demonstrating Mitigation**:
  - [`server/tests/security.test.js:88-103`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/security.test.js#L88-L103) (`IDOR Check: Unauthorized user cannot read another users document metadata`)
  - [`server/tests/permissions_system.test.js:44-63`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/permissions_system.test.js#L44-L63) (`1. User A cannot read User B's document metadata (IDOR Defense)`)
  - [`server/tests/document_management.test.js:205-215`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/document_management.test.js#L205-L215) (`should block unauthorized user from reading private metadata (403 IDOR)`)
  - [`server/tests/auth_and_schema.test.js:103-116`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/auth_and_schema.test.js#L103-L116) (`should block an unauthorized user from reading anothers document metadata (IDOR)`)
- **Residual Risk & Consciously Accepted Limitation**: If an attacker compromises a victim's active JWT credentials (e.g., via host compromise), the system evaluates the request as legitimate. Device fingerprinting or mTLS is not implemented.

---

### 2. Authorization Missing from Download or Alternate Endpoints
- **Realistic Attack Scenario**: An adversary realizes that while `GET /api/documents/:id` (metadata endpoint) enforces permissions, an alternate endpoint such as `GET /api/documents/:id/download`, `GET /api/documents/:id/permissions`, or a direct storage endpoint might lack the authorizer middleware, allowing direct exfiltration of document binary streams.
- **Attacker's Role & Prerequisites**: Authenticated user with no read grant on target document.
- **Impact**: **Critical** — Direct exfiltration of sensitive binary files (PDFs, spreadsheets, contracts).
- **Mitigation Implemented**:
  1. Universal Route Protection: All document routes in `documentRoutes.js` and `permissionRoutes.js` require `authenticateToken` globally (`router.use(authenticateToken)`).
  2. Per-Endpoint Authorization: Every distinct action binds `authorizeDocumentAccess`:
     - Download: `authorizeDocumentAccess({ requiredPermission: 'read' })`
     - Metadata Update: `authorizeDocumentAccess({ requiredPermission: 'edit' })`
     - Deletion: `authorizeDocumentAccess({ allowOwnerOnly: true })`
     - Permission Grants/Revocation: `authorizeDocumentAccess({ allowOwnerOnly: true })`
  3. Negative Guardrail Integration Test: Dedicated automated test removes authorization middleware and asserts that security test suites immediately fail.
- **Exact Code Paths**:
  - [`server/src/routes/documentRoutes.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/routes/documentRoutes.js#L24-L44)
  - [`server/src/routes/permissionRoutes.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/routes/permissionRoutes.js#L10-L18)
  - [`server/src/controllers/documentController.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/controllers/documentController.js#L250-L289)
- **Exact Tests Demonstrating Mitigation**:
  - [`server/tests/security.test.js:104-112`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/security.test.js#L104-L112) (`IDOR Check: Unauthorized user cannot download another users document stream`)
  - [`server/tests/permissions_system.test.js:65-94`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/permissions_system.test.js#L65-L94) (`2. User A cannot download, edit or delete User B's document`)
  - [`server/tests/permissions_system.test.js:342-411`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/permissions_system.test.js#L342-L411) (`8. A revoked viewer cannot access the file through another endpoint or previously obtained application link`)
  - [`server/tests/permissions_system.test.js:464-503`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/permissions_system.test.js#L464-L503) (`10. Missing authorization middleware causes security tests to fail`)
  - [`server/tests/document_management.test.js:217-224`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/document_management.test.js#L217-L224) (`should block unauthorized user from downloading document stream (403)`)
- **Residual Risk & Consciously Accepted Limitation**: Developer omission when introducing new future routes. Mitigated by architectural conventions and regression test suites.

---

### 3. Access Surviving Permission Revocation (Stale Cache / Session Tokens)
- **Realistic Attack Scenario**: An employee or external auditor is granted access to review a confidential merger agreement. Once the audit period closes, the owner revokes their permission. The auditor continues downloading the document using their existing JWT or a cached token, because the permission was embedded into the JWT claims or stored in an uninvalidated cache.
- **Attacker's Role & Prerequisites**: Previously authorized collaborator whose permission was recently revoked.
- **Impact**: **High** — Continued unauthorized data access post-offboarding or post-contract termination.
- **Mitigation Implemented**:
  1. Stateless Identity / Stateful Permission Decoupling: Document permissions are **never embedded** in JWT claims. JWTs only attest to actor identity (`sub`, `email`, `role`).
  2. Zero Long-Lived Permission Caching: Every request to read metadata or download bytes executes a live query against `document_permissions` (`db.getUserPermissionOnDocument(doc.id, userId)`).
  3. Synchronous Revocation: `DELETE /api/documents/:id/permissions/:targetUserId` synchronously deletes the record. The subsequent request within the same second evaluates to `null` and fails closed with 403 `DOCUMENT_ACCESS_DENIED`.
- **Exact Code Paths**:
  - [`server/src/middleware/roles.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/middleware/roles.js#L170-L203)
  - [`server/src/controllers/permissionController.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/controllers/permissionController.js#L113-L160)
  - [`server/src/db/migrations/003_row_level_security.sql`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/db/migrations/003_row_level_security.sql#L207-L219)
- **Exact Tests Demonstrating Mitigation**:
  - [`server/tests/permissions_system.test.js:312-340`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/permissions_system.test.js#L312-L340) (`7. An owner can revoke access and the next request is immediately denied`)
  - [`server/tests/permissions_system.test.js:342-411`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/permissions_system.test.js#L342-L411) (`8. A revoked viewer cannot access the file through another endpoint or previously obtained application link`)
  - [`server/tests/security.test.js:201-247`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/security.test.js#L201-L247) (`should grant read access, allow download, and enforce immediate revocation`)
  - [`server/tests/audit_system.test.js:474-504`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/audit_system.test.js#L474-L504) (`should record matching audit event on permission grant and immediate revocation`)
- **Residual Risk & Consciously Accepted Limitation**: If a download stream is actively in-flight across the TCP socket when revocation occurs, bytes already buffered or currently writing over the wire will finish. Mitigated by fast transfer times and `no-store` cache headers.

---

### 4. Public or Leaked Storage URLs (Direct S3 / Supabase Storage Scraping)
- **Realistic Attack Scenario**: Cloud storage buckets are misconfigured as public, or the application issues time-limited pre-signed URLs to clients. An attacker intercepts a pre-signed URL from browser traffic, logs, or shared links, downloading files directly from cloud storage without contacting the application server or triggering an audit event.
- **Attacker's Role & Prerequisites**: Any network eavesdropper, rogue proxy, or user sharing a link.
- **Impact**: **Critical** — Complete bypass of access control, identity verification, and audit logging.
- **Mitigation Implemented**:
  1. Private Storage Bucket: Storage buckets are configured as strictly private with no public read policies.
  2. Zero Pre-Signed / Public URLs: The backend server **never** generates or transmits pre-signed URLs or direct bucket URLs to client applications.
  3. Path Redaction Engine: Internal storage paths are strictly scrubbed from all API responses via `sanitizeDocumentOutput(doc)` (`delete safe.storage_path`).
  4. Backend Proxy Streaming: All downloads stream through `/api/documents/:id/download`. The Node.js server retrieves the stream via service role credentials and pipes it to the client, guaranteeing that every download requires authentication, evaluates permissions, and logs an immutable audit event (`DOCUMENT_DOWNLOAD_ALLOWED`).
- **Exact Code Paths**:
  - [`server/src/controllers/documentController.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/controllers/documentController.js#L35-L40) (`sanitizeDocumentOutput`)
  - [`server/src/controllers/documentController.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/controllers/documentController.js#L250-L289) (`downloadDocument`)
  - [`server/src/services/storageService.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/services/storageService.js#L76-L106) (`getFileStream`)
  - [`client/src/services/api.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/client/src/services/api.js#L89-L111) (`downloadDocumentStream`)
- **Exact Tests Demonstrating Mitigation**:
  - [`server/tests/document_management.test.js:58-60`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/document_management.test.js#L58-L60) (verifies `uploadRes.body.document.storage_path` is undefined)
  - [`server/tests/document_management.test.js:82`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/document_management.test.js#L82) (verifies `metaRes.body.document.storage_path` is undefined)
  - [`server/tests/document_management.test.js:214`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/document_management.test.js#L214) (verifies error payloads omit `storage_path`)
  - [`server/tests/document_management.test.js:268-288`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/document_management.test.js#L268-L288) (verifies client-supplied `storage_path` is ignored)
- **Residual Risk & Consciously Accepted Limitation**: Proxying all downloads through Node.js increases server egress and CPU utilization compared to direct CDN/S3 delivery. Accepted trade-off for zero-trust authorization and zero-drop audit logging.

---

### 5. Search and Metadata Leaking Confidential Information
- **Realistic Attack Scenario**: User A uploads a highly sensitive document entitled `Q3_Mass_Layoffs_Planning.pdf`. User B (an employee without access) uses the global search endpoint `GET /api/documents?search=Layoffs` or filters by tags (`hr`, `layoffs`). If the backend executes full-text search against the database before checking row ownership, User B learns about pending layoffs from result counts, snippets, or matching document titles.
- **Attacker's Role & Prerequisites**: Authenticated user with no grant on target document.
- **Impact**: **Medium-High** — Confidential information leakage through search metadata, tags, and category listings.
- **Mitigation Implemented**:
  1. Access Control Pre-Filtering: In `server/src/db/db.js#L286-L303` (`listDocumentsForUser`), the authorization filter (`isOwner || hasPermission`) executes **before** query keyword matching, category filtering, tag filtering, or date matching. Unpermitted documents are dropped immediately.
  2. Database Engine RLS: PostgreSQL `documents_select_policy` guarantees that `WHERE title ILIKE '%...%'` queries at the SQL level only scan rows where `owner_id = auth.uid()` or an active grant exists.
  3. Document Count Privacy: Search result `total` and arrays only reflect authorized records.
- **Exact Code Paths**:
  - [`server/src/db/db.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/db/db.js#L286-L345)
  - [`server/src/controllers/documentController.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/controllers/documentController.js#L188-L208)
  - [`server/src/db/migrations/003_row_level_security.sql`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/db/migrations/003_row_level_security.sql#L90-L105)
- **Exact Tests Demonstrating Mitigation**:
  - [`server/tests/document_management.test.js:526-533`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/document_management.test.js#L526-L533) (`should isolate search results: Primary Owner cannot discover Alice documents`)
  - [`server/tests/document_management.test.js:535-573`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/document_management.test.js#L535-L573) (validates category, tag, and owner filtering maintain strict isolation)
  - [`server/tests/document_management.test.js:212-215`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/document_management.test.js#L212-L215) (confirms 403 error returns zero title/metadata leaks)
- **Residual Risk & Consciously Accepted Limitation**: Enterprise category names in `public.categories` (e.g. "Financial Reports", "Human Resources") are visible to all authenticated corporate users as general classification taxonomy.

---

### 6. Horizontal Privilege Escalation Between Owners and Viewers
- **Realistic Attack Scenario**: An adversary with a standard `viewer` account or a peer `document_owner` sends a crafted `PATCH /api/documents/:id` to overwrite another user's document title/tags, or sends `DELETE /api/documents/:id` to destroy another user's files, or attempts to grant permissions to a third party.
- **Attacker's Role & Prerequisites**: Authenticated user in the system.
- **Impact**: **High** — Integrity loss, unauthorized modification, or unauthorized deletion of enterprise documents.
- **Mitigation Implemented**:
  1. Role Differentiation:
     - Deletion: Guarded by `allowOwnerOnly: true` (`server/src/middleware/roles.js#L134-L156`). Collaborators with `edit` permission are strictly rejected with 403 `OWNER_ONLY_OPERATION`.
     - Metadata Updates: Requires `requiredPermission: 'edit'`. Viewers with `read` permission are rejected with 403 `INSUFFICIENT_DOCUMENT_PERMISSION`.
     - Permission Grants/Revocation: Strictly restricted to document owner (`allowOwnerOnly: true`).
  2. SQL Ownership Immutability Check: PostgreSQL RLS policy `documents_update_policy` enforces `WITH CHECK (owner_id = documents.owner_id)`, preventing an attacker from transferring document ownership to themselves.
- **Exact Code Paths**:
  - [`server/src/middleware/roles.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/middleware/roles.js#L133-L168, L205-L227)
  - [`server/src/routes/documentRoutes.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/routes/documentRoutes.js#L31-L44)
  - [`server/src/routes/permissionRoutes.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/routes/permissionRoutes.js#L13-L18)
  - [`server/src/db/migrations/003_row_level_security.sql`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/db/migrations/003_row_level_security.sql#L123-L154)
- **Exact Tests Demonstrating Mitigation**:
  - [`server/tests/security.test.js:114-140`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/security.test.js#L114-L140) (`IDOR Check: Non-owner cannot modify document metadata` and `delete another users document`)
  - [`server/tests/permissions_system.test.js:96-146`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/permissions_system.test.js#L96-L146) (`3. User A cannot grant access to User B's document`)
  - [`server/tests/permissions_system.test.js:148-200`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/permissions_system.test.js#L148-L200) (`4. A viewer cannot promote themselves to owner or admin`)
  - [`server/tests/permissions_system.test.js:202-243`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/permissions_system.test.js#L202-L243) (`5. A user with read permission cannot perform edit operations`)
  - [`server/tests/auth_and_schema.test.js:127-180`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/auth_and_schema.test.js#L127-L180) (validates that unauthorized users cannot update, grant, or revoke permissions on another user's document)
- **Residual Risk & Consciously Accepted Limitation**: A document owner possesses full discretion over who they grant `read` or `edit` permissions to. Malicious internal owners intentionally leaking their own files cannot be prevented via access control alone (detectable via audit trail).

---

### 7. Vertical Privilege Escalation to Administrator
- **Realistic Attack Scenario**:
  1. Self-Assignment on Registration: An attacker signs up via `POST /api/auth/register` with payload `{"system_role": "administrator"}`.
  2. Parameter Tampering: An attacker injects `role: "administrator"` into upload or profile update requests.
  3. Blanket Read Bypass: A system administrator attempts to leverage their administrative status to read private whistleblower or payroll files without being granted access by the owner.
- **Attacker's Role & Prerequisites**: Unauthenticated applicant or authenticated non-administrator user.
- **Impact**: **Critical** — Total administrative compromise or loss of executive confidentiality.
- **Mitigation Implemented**:
  1. Server-Side Role Whitelist: `server/src/controllers/authController.js#L42-L44` forces registration roles to `system_role === 'document_owner' ? 'document_owner' : 'viewer'`. Client-supplied `'administrator'` is rejected and downgraded to `viewer`.
  2. PostgreSQL Guard Trigger: `trg_guard_profile_role_escalation` in `server/src/db/migrations/002_triggers_and_guards.sql#L29-L64` executes `BEFORE UPDATE` on `public.profiles`. If `system_role` or `is_active` changes and the caller is not an active administrator, it raises an uncatchable PL/pgSQL exception.
  3. Authoritative Identity Resolution: `server/src/middleware/auth.js#L43-L89` queries `db.getProfileById(userId)` from the database for every request, completely ignoring client-supplied role claims.
  4. Strict Admin Isolation (No Blanket Read Bypass): `server/src/middleware/roles.js#L175-L203` enforces that administrators **cannot** read or download private documents unless granted explicit permission by the owner. When an admin attempts blanket access, 403 is returned and high-priority event `ADMIN_BLANKET_BYPASS_BLOCKED` is recorded in the audit trail.
- **Exact Code Paths**:
  - [`server/src/controllers/authController.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/controllers/authController.js#L42-L44)
  - [`server/src/db/migrations/002_triggers_and_guards.sql`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/db/migrations/002_triggers_and_guards.sql#L29-L64)
  - [`server/src/middleware/auth.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/middleware/auth.js#L43-L89)
  - [`server/src/middleware/roles.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/middleware/roles.js#L175-L203)
- **Exact Tests Demonstrating Mitigation**:
  - [`server/tests/auth_and_schema.test.js:35-84`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/auth_and_schema.test.js#L35-L84) (`1. Role Escalation Prevention`: registration self-assignment downgraded, role management endpoint blocked, spoofed body roles ignored)
  - [`server/tests/auth_and_schema.test.js:185-223`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/auth_and_schema.test.js#L185-L223) (`3. Admin Content Isolation (No Blanket Bypass)`)
  - [`server/tests/security.test.js:146-183`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/security.test.js#L146-L183) (`3. Strict Admin Document Isolation (No Blanket Bypass)`)
  - [`server/tests/permissions_system.test.js:505-574`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/permissions_system.test.js#L505-L574) (`11. Admin can inspect permission metadata and audit events but cannot bypass content authorization`)
- **Residual Risk & Consciously Accepted Limitation**: Administrators retain authority over global user account management (suspending users or reassigning roles). An admin cannot deactivate their own active account (`adminController.js#L151-L157`), but compromised admin credentials represent a significant operational risk.

---

### 8. Permission Changes Racing with Downloads
- **Realistic Attack Scenario**: An adversary realizes their document access is about to be revoked. They trigger dozens of concurrent download requests in parallel threads at the exact millisecond the owner sends `DELETE /api/documents/:id/permissions/:userId`, attempting to exploit a race condition between permission verification and file delivery.
- **Attacker's Role & Prerequisites**: User whose access is actively being revoked.
- **Impact**: **High** — Unauthorized retrieval of documents during the revocation window.
- **Mitigation Implemented**:
  1. Atomic Request-Time Authorization Check: `authorizeDocumentAccess` executes immediately before opening the file stream on every single download request.
  2. Transactional Immutability: In PostgreSQL, `DELETE FROM document_permissions` executes with row-level locking. In the in-process store, Node.js event-loop single-threading ensures synchronous deletion of permission keys.
  3. Zero Stored Authorization State: The download endpoint does not issue pre-authorized download tokens or pre-signed URLs.
- **Exact Code Paths**:
  - [`server/src/routes/documentRoutes.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/routes/documentRoutes.js#L26-L29)
  - [`server/src/middleware/roles.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/middleware/roles.js#L170-L203)
  - [`server/src/controllers/documentController.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/controllers/documentController.js#L250-L289)
- **Exact Tests Demonstrating Mitigation**:
  - [`server/tests/permissions_system.test.js:312-340`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/permissions_system.test.js#L312-L340) (Test 7: Sequential atomic test showing instant denial)
  - [`server/tests/security.test.js:201-247`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/security.test.js#L201-L247) (Step 5 & 6: Immediate revocation test)
- **Residual Risk & Consciously Accepted Limitation**: **[CONSCIOUSLY ACCEPTED LIMITATION]** If an HTTP download stream has already completed authorization and has begun streaming binary chunks across the socket before revocation completes in the database, the active TCP socket will complete transmission of the in-flight file. Mid-stream socket disconnection is not implemented.

---

### 9. Malicious File Types, MIME Spoofing, and Oversized Uploads
- **Realistic Attack Scenario**:
  1. Malware Executable Disguised as PDF: Attacker renames a Windows PE executable (`.exe` starting with `MZ` `4D 5A`) to `invoice.pdf` and uploads it.
  2. Stored XSS via SVG: Attacker uploads an SVG image containing `<script>alert(document.cookie)</script>`.
  3. Storage Exhaustion DoS: Attacker uploads a 500MB zip bomb or multi-gigabyte video file to exhaust disk space and memory buffers.
- **Attacker's Role & Prerequisites**: Authenticated user with `document_owner` or `administrator` role.
- **Impact**: **High-Critical** — Remote code execution on victim endpoints, Stored XSS in browsers, server Denial of Service.
- **Mitigation Implemented**:
  1. Role Enforcement: Viewers are blocked from uploading (`server/src/controllers/documentController.js#L46-L66`).
  2. Strict File Size Limit: Multer enforces a hard 10MB limit (`config.maxFileSizeBytes`), returning 400 `FILE_TOO_LARGE` (`server/src/middleware/upload.js#L159-L174`).
  3. Dangerous Extensions Blacklist: Explicitly prohibits `.exe`, `.bat`, `.cmd`, `.sh`, `.bin`, `.dll`, `.svg`, `.html`, `.js`, `.php`, `.py`, `.ps1` (`server/src/middleware/upload.js#L41-L45`).
  4. Allowed Extensions Whitelist: Only `.pdf`, `.png`, `.jpg`, `.jpeg`, `.docx`, `.xlsx`, `.txt` (`server/src/middleware/upload.js#L48-L50`).
  5. Deep Magic Byte Header Inspection (`verifyMagicBytes`):
     - Blocks Windows `MZ` executable header (`0x4D 0x5A`).
     - Blocks Linux `ELF` header (`0x7F 0x45 0x4C 0x46`).
     - Verifies PDF magic bytes (`%PDF` `0x25 0x50 0x44 0x46`).
     - Verifies PNG (`0x89 0x50 0x4E 0x47...`), JPEG (`0xFF 0xD8 0xFF`), DOCX/XLSX (`PK..` `0x50 0x4B 0x03 0x04`).
     - Scans plain text files for null bytes (`0x00`) to detect masked binary executables.
  6. Audit Denial Logging: Rejection triggers `MALICIOUS_UPLOAD_ATTEMPT_BLOCKED` in audit logs.
- **Exact Code Paths**:
  - [`server/src/middleware/upload.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/middleware/upload.js#L9-L121) (`MAGIC_SIGNATURES`, `verifyMagicBytes`)
  - [`server/src/middleware/upload.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/middleware/upload.js#L152-L245) (`uploadMiddleware`)
  - [`server/src/controllers/documentController.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/controllers/documentController.js#L46-L66)
- **Exact Tests Demonstrating Mitigation**:
  - [`server/tests/security.test.js:253-263`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/security.test.js#L253-L263) (`should block viewers from uploading documents`)
  - [`server/tests/security.test.js:264-280`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/security.test.js#L264-L280) (`should reject dangerous files with executable magic bytes disguised as PDF`)
  - [`server/tests/security.test.js:282-294`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/security.test.js#L282-L294) (`should reject SVG uploads to prevent Stored Cross-Site Scripting (XSS)`)
  - [`server/tests/document_management.test.js:333-351`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/document_management.test.js#L333-L351) (`should reject uploads exceeding 10MB limit with 400 FILE_TOO_LARGE`)
  - [`server/tests/document_management.test.js:357-404`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/document_management.test.js#L357-L404) (executable extensions, SVG XSS, Windows MZ headers, and random non-PDF bytes blocked)
  - [`server/tests/audit_system.test.js:376-394`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/audit_system.test.js#L376-L394) (`should record audit event when malicious upload with fake magic bytes is blocked`)
- **Residual Risk & Consciously Accepted Limitation**: **[RESIDUAL RISK]** Weaponized office macros (VBA inside valid `.docx` or `.xlsx`) or zero-day PDF exploits cannot be identified solely by magic byte inspection. A sandboxed anti-malware scanning pipeline (e.g., ClamAV) is not currently integrated.

---

### 10. Path Traversal and Unsafe Filenames
- **Realistic Attack Scenario**: An attacker submits a document ID containing `../../etc/passwd` or uploads a file named `../../../../etc/shadow` or `..\windows\system32\calc.exe`, hoping to write outside designated vault directories or read server host configuration.
- **Attacker's Role & Prerequisites**: Authenticated user.
- **Impact**: **Critical** — Local File Inclusion (LFI), Arbitrary File Write, or Host System Compromise.
- **Mitigation Implemented**:
  1. Document ID Parameter Guard: `server/src/middleware/roles.js#L57-L83` tests if `documentId` contains `..`, `/`, `\`, `\0`, or exceeds 100 characters. If detected, logs `MALICIOUS_INPUT_DETECTED` and immediately returns 400 `INVALID_DOCUMENT_ID`.
  2. Filename Sanitizer: `server/src/middleware/upload.js#L55-L62` strips path traversal via `path.basename()` and regex-scrubs control and dangerous filesystem characters (`/[\x00-\x1F\x7F<>:"/\\|?*]/g`).
  3. Storage Path Sanitizer: `server/src/services/storageService.js#L32-L41` normalizes paths and throws an exception if `..` is present.
  4. Server-Generated Storage Keys: Storage paths are strictly generated server-side using random UUIDs (`vault/${req.user.id}/${docUuid}${safeExtension}`). Any client-supplied `storage_path` in request bodies is discarded.
  5. Content-Disposition Encoding: File downloads encode the original filename using `encodeURIComponent(doc.original_filename)`.
- **Exact Code Paths**:
  - [`server/src/middleware/roles.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/middleware/roles.js#L57-L83)
  - [`server/src/middleware/upload.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/middleware/upload.js#L55-L62)
  - [`server/src/services/storageService.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/services/storageService.js#L32-L41)
  - [`server/src/controllers/documentController.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/controllers/documentController.js#L98, L257)
- **Exact Tests Demonstrating Mitigation**:
  - [`server/tests/document_management.test.js:250-256`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/document_management.test.js#L250-L256) (`should reject path traversal in document ID parameter (400)`)
  - [`server/tests/audit_system.test.js:361-374`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/audit_system.test.js#L361-L374) (`should record audit event when malicious input or path traversal is detected in document ID`)
  - [`server/tests/permissions_system.test.js:438-462`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/permissions_system.test.js#L438-L462) (`9. A tampered document ID cannot bypass authorization`)
  - [`server/tests/document_management.test.js:268-288`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/document_management.test.js#L268-L288) (`should ignore client-supplied owner_id or storage_path during upload and derive them safely`)
- **Residual Risk & Consciously Accepted Limitation**: Path separators normalized to Unix format (`/`). No known residual risk for supported OS file systems.

---

### 11. SQL Injection and Unsafe Query Construction
- **Realistic Attack Scenario**: An attacker supplies `' OR '1'='1` or `'; DROP TABLE audit_logs; --` in search queries, user emails, or document titles to extract database contents or bypass authentication.
- **Attacker's Role & Prerequisites**: Any caller (unauthenticated or authenticated).
- **Impact**: **Critical** — Total database compromise, loss of confidentiality, integrity, and availability.
- **Mitigation Implemented**:
  1. Parameterized DDL and Migrations: Migration runner `server/src/db/migrate.js` uses `pg.Client` with parameterized queries (`client.query('SELECT version FROM ...')`).
  2. Relational Object Store: In-memory store and Supabase client calls use strict object mapping, type casting, and parameterized PostgREST RPC. String concatenation inside SQL commands is strictly non-existent across the codebase.
  3. Full-Text Search Parameterization: PostgreSQL search indices use parameterized `to_tsvector` and `plainto_tsquery`.
- **Exact Code Paths**:
  - [`server/src/db/migrate.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/db/migrate.js#L40-L48)
  - [`server/src/db/db.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/db/db.js) (throughout)
  - [`server/src/db/migrations/001_initial_schema.sql`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/db/migrations/001_initial_schema.sql#L91-L93)
- **Exact Tests Demonstrating Mitigation**:
  - [`server/tests/document_management.test.js:555-564`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/document_management.test.js#L555-L564) (search filtering with special characters)
  - [`server/tests/auth_and_schema.test.js:35-53`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/auth_and_schema.test.js#L35-L53) (registration input handling)
  - [`server/tests/audit_system.test.js:580-592`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/audit_system.test.js#L580-L592) (handles SQL characters in email/passwords safely)
- **Residual Risk & Consciously Accepted Limitation**: Future direct database queries must consistently enforce parameterization. Static analysis (linting) should guard against raw SQL string interpolation.

---

### 12. Cross-Site Scripting (XSS) from Document Names and Metadata
- **Realistic Attack Scenario**: An adversary uploads a document named `<img src=x onerror=alert(document.cookie)>` or adds malicious HTML into document descriptions or audit notes. When an administrator or collaborator opens the document list or audit inspector, the payload executes in the viewer's browser session.
- **Attacker's Role & Prerequisites**: Authenticated user uploading documents or generating metadata.
- **Impact**: **High** — Session hijacking, credential theft, and unauthorized actions performed in victim context.
- **Mitigation Implemented**:
  1. React JSX Auto-Escaping: All dynamic document metadata (`title`, `description`, `tags`, `actor`, `audit details`) is rendered via React JSX expressions (`{doc.title}`). React auto-encodes all HTML entities by default. The frontend codebase contains **zero** instances of `dangerouslySetInnerHTML`.
  2. HTTP Content Security Policy: Helmet middleware in `server/src/app.js#L17-L35` enforces:
     - `default-src: ["'self'"]`
     - `script-src: ["'self'"]` (disallows inline scripts and external unverified scripts)
     - `object-src: ["'none'"]`
  3. Binary Download Hardening: File download headers in `documentController.js#L256-L263` include `Content-Security-Policy: default-src 'none'`, `X-Content-Type-Options: nosniff`, and `Content-Disposition: attachment`.
  4. SVG Exclusion: Prohibits `.svg` uploads to eliminate SVG-embedded script execution.
- **Exact Code Paths**:
  - [`server/src/app.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/app.js#L16-L35)
  - [`server/src/controllers/documentController.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/controllers/documentController.js#L256-L263)
  - [`server/src/middleware/upload.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/middleware/upload.js#L43, L60)
  - [`client/src/pages/DocumentsView.jsx`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/client/src/pages/DocumentsView.jsx)
  - [`client/src/components/DocumentCard.jsx`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/client/src/components/DocumentCard.jsx)
- **Exact Tests Demonstrating Mitigation**:
  - [`server/tests/security.test.js:282-294`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/security.test.js#L282-L294) (`should reject SVG uploads to prevent Stored Cross-Site Scripting (XSS)`)
  - [`server/tests/document_management.test.js:89-93`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/document_management.test.js#L89-L93) (verifies `nosniff`, `attachment`, and security headers)
  - [`server/tests/document_management.test.js:369-379`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/document_management.test.js#L369-L379) (`should reject SVG files to prevent Stored Cross-Site Scripting (XSS)`)
- **Residual Risk & Consciously Accepted Limitation**: Helmet CSP directives permit `'unsafe-inline'` for `styleSrc` to accommodate Google Fonts and dynamic CSS stylings.

---

### 13. CSRF or Stolen Credentials / Session Tokens
- **Realistic Attack Scenario**: An adversary lures an authenticated user to a malicious website that executes unauthorized state-changing requests against TrustVault via cross-origin requests, or steals a session token stored in the browser.
- **Attacker's Role & Prerequisites**: External malicious website or malicious browser script.
- **Impact**: **High** — Account takeover or unauthorized document deletion/sharing.
- **Mitigation Implemented**:
  1. Bearer Token Authorization Header: Authenticated endpoints require an explicit `Authorization: Bearer <token>` header (`server/src/middleware/auth.js#L10-L27`). Cross-origin browser form submissions or image tags cannot automatically attach custom HTTP headers.
  2. Strict CORS Configuration: `server/src/app.js#L39-L63` restricts allowed origins to explicit trusted client origins (`CLIENT_ORIGIN` and local development ports), blocking unauthorized cross-origin AJAX.
  3. Short Expiry & Account Deactivation Check: JWT tokens expire after 24 hours. Every request verifies that `is_active === true` in the database, immediately terminating compromised sessions upon admin suspension.
- **Exact Code Paths**:
  - [`server/src/app.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/app.js#L39-L63)
  - [`server/src/middleware/auth.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/middleware/auth.js#L10-L27, L63-L80)
  - [`client/src/services/api.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/client/src/services/api.js#L27-L40)
- **Exact Tests Demonstrating Mitigation**:
  - [`server/tests/security.test.js:36-67`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/security.test.js#L36-L67) (`1. Authentication & Fail-Closed Guardrails`: verifies missing headers, malformed signatures, and deactivated accounts fail closed)
- **Residual Risk & Consciously Accepted Limitation**: **[RESIDUAL RISK]** The frontend currently stores the JWT in browser `localStorage` (`client/src/services/api.js#L10`). If an XSS flaw were ever introduced, tokens could be extracted. Migrating to `HttpOnly`, `SameSite=Strict`, `Secure` cookies represents recommended defense-in-depth.

---

### 14. Brute Force and Account Enumeration
- **Realistic Attack Scenario**: An attacker runs dictionary attacks or password credential-stuffing against `/api/auth/login`, analyzing response codes or error messages to enumerate valid corporate email addresses or crack accounts.
- **Attacker's Role & Prerequisites**: Unauthenticated internet actor.
- **Impact**: **High** — Account compromise, discovery of employee directory.
- **Mitigation Implemented**:
  1. Global API Rate Limiting: `express-rate-limit` enforces a maximum of 300 requests per 15 minutes per IP (`server/src/app.js#L77-L88`).
  2. Generic Uniform Login Errors: When an email is non-existent or password does not match, `authController.js#L133-L136` and `L175-L178` return identical HTTP 401 responses: `{ error: 'Invalid email or password.', code: 'INVALID_CREDENTIALS' }`.
  3. Audit Logging: Every failed login generates `USER_LOGIN_FAILED` in the immutable ledger with client IP and request ID.
- **Exact Code Paths**:
  - [`server/src/app.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/app.js#L77-L88)
  - [`server/src/controllers/authController.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/controllers/authController.js#L121-L178)
- **Exact Tests Demonstrating Mitigation**:
  - [`server/tests/audit_system.test.js:222-253`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/audit_system.test.js#L222-L253) (`should record audit event when login fails due to invalid credentials`)
- **Residual Risk & Consciously Accepted Limitation**: **[OPEN RISK / CONSCIOUS LIMITATION]**
  1. The registration endpoint `/api/auth/register` returns 409 `EMAIL_ALREADY_EXISTS` (`authController.js#L48-L51`), which allows user enumeration by attempting registration.
  2. Dedicated per-route rate limiting specifically on `/api/auth/login` (e.g., 5 failed attempts per IP/account per 5 minutes) is recommended to supplement the global 300 requests/15m limit.

---

### 15. Audit Forgery, Deletion, Reordering, or Log Injection
- **Realistic Attack Scenario**: An insider threat or rogue administrator attempts to cover their tracks by:
  1. Modifying or deleting audit log records in the database.
  2. Injecting forged log rows using CRLF characters in user agents or email fields.
  3. Reordering records or replacing the Genesis block.
- **Attacker's Role & Prerequisites**: Rogue administrator or attacker with SQL access.
- **Impact**: **Critical** — Repudiation, loss of forensic evidence, inability to audit data breaches.
- **Mitigation Implemented**:
  1. Anti-Log-Injection Engine: `server/src/utils/auditSanitizer.js#L18-L27` strips CRLF (`\r`, `\n`) and ASCII control characters (`[\x00-\x1F\x7F]`) from all inputs.
  2. Database Immutability Trigger: PostgreSQL trigger `prevent_audit_log_tampering` unconditionally aborts any `UPDATE` or `DELETE` on `public.audit_logs` with a PL/pgSQL security violation exception (`server/src/db/migrations/002_triggers_and_guards.sql#L11-L23`).
  3. Application Immutability: Methods `db.updateAuditLog` and `db.deleteAuditLog` throw runtime security exceptions. No HTTP routes exist for modifying audit records (HTTP PUT/DELETE returns 404).
  4. Cryptographic HMAC-SHA256 Chaining: Each log record is cryptographically linked to its predecessor via:
     $$H_i = \text{HMAC-SHA256}\Big(K_{\text{audit}}, H_{i-1} \,\|\, \text{id}_i \,\|\, \text{ts}_i \,\|\, \text{actor}_i \,\|\, \text{action}_i \,\|\, \text{status}_i \,\|\, \text{docId}_i \,\|\, \text{reqId}_i \,\|\, \text{CanonicalJSON}(\text{details}_i)\Big)$$
  5. Cryptographic Chain Verifier: `verifyAuditChain` validates previous hash pointers, genesis hash (`0`.repeat(64)), and recalculates HMACs, identifying the exact compromised block ID.
- **Exact Code Paths**:
  - [`server/src/utils/auditSanitizer.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/utils/auditSanitizer.js#L1-L111)
  - [`server/src/db/migrations/002_triggers_and_guards.sql`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/db/migrations/002_triggers_and_guards.sql#L11-L23)
  - [`server/src/services/hashChainService.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/services/hashChainService.js#L1-L130)
  - [`server/src/controllers/adminController.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/controllers/adminController.js#L49-L77)
- **Exact Tests Demonstrating Mitigation**:
  - [`server/tests/audit_system.test.js:115-140`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/audit_system.test.js#L115-L140) (`2. Append-Only Immutability & Modification Rejection`: asserts update/delete throws and HTTP mutations return 404)
  - [`server/tests/audit_system.test.js:145-216`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/audit_system.test.js#L145-L216) (`3. Cryptographic Hash Chain & Tamper Detection`: detects altered actions, previous hash link modifications, and genesis block tampering)
  - [`server/tests/audit_system.test.js:526-592`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/audit_system.test.js#L526-L592) (`6. Data Privacy & Anti-Log-Injection Defense`: verifies CRLF sanitization and credential scrubbing)
  - [`server/tests/security.test.js:321-340`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/security.test.js#L321-L340) (validates detection of simulated out-of-band record tampering)
- **Residual Risk & Consciously Accepted Limitation**: As detailed in `AUDIT_SECURITY_ARCHITECTURE.md`, an adversary who compromises the PostgreSQL superuser **and** compromises the application server host (recovering `AUDIT_HMAC_SECRET`) could rewrite historical rows and recalculate the chain. Mitigated by isolating keys outside the DB and anchoring tail checkpoints to immutable WORM storage.

---

### 16. Inconsistent Audit Events After Partial Failures
- **Realistic Attack Scenario**: An upload operation successfully writes binary bytes to cloud storage, but subsequent database insertion fails (e.g. database disconnect, schema constraint failure). If the application terminates without rollback or auditing, an orphaned private file persists in storage unrecorded, or the audit ledger records a success when the file is unavailable.
- **Attacker's Role & Prerequisites**: User uploading files during infrastructure or network instability.
- **Impact**: **Medium-High** — Orphaned storage assets, inconsistent audit evidence, storage leakage.
- **Mitigation Implemented**:
  1. Transactional Rollback: In `server/src/controllers/documentController.js#L146-L182`, if database insertion throws an exception after file upload, `storageService.deleteFile(storagePath)` is invoked immediately to purge the orphaned binary.
  2. Failure Auditing: The catch block records `DOCUMENT_UPLOAD_FAILED` (outcome `ERROR`) with `storageRolledBack: true`, capturing the failure reason, actor ID, and IP address.
- **Exact Code Paths**:
  - [`server/src/controllers/documentController.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/controllers/documentController.js#L146-L182)
- **Exact Tests Demonstrating Mitigation**:
  - [`server/tests/document_management.test.js:578-602`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/document_management.test.js#L578-L602) (`should clean up storage vault when database insertion fails during upload`)
- **Residual Risk & Consciously Accepted Limitation**: If a power loss or host hard crash occurs precisely between storage write and database rollback, an orphaned object could remain until cleaned by an out-of-band reconciliation worker.

---

### 17. Secrets Committed to Git or Exposed to the Browser
- **Realistic Attack Scenario**: A developer accidentally commits `.env`, database passwords, or `SUPABASE_SERVICE_ROLE_KEY` to GitHub, or the frontend build bundle includes private server secrets, enabling public internet users to take over the database.
- **Attacker's Role & Prerequisites**: Public repository observer or visitor inspecting frontend JavaScript bundles.
- **Impact**: **Critical** — Complete compromise of cloud infrastructure, database, and storage.
- **Mitigation Implemented**:
  1. Strict Git Exclusion: Root `.gitignore#L7-L13` ignores `.env`, `server/.env`, `client/.env`, `.env.local`.
  2. Safe Template Files: Only `server/.env.example` is committed, containing generic placeholders (`your-enterprise-audit-hmac-secret...`).
  3. Verified Clean Git History: `git log -S "sb_secret"` confirms zero production secrets were ever committed to git history.
  4. Frontend Bundle Isolation: The Vite client bundle only reads `VITE_API_URL` (`client/src/services/api.js#L3`). The frontend never imports `@supabase/supabase-js`, `SUPABASE_SERVICE_ROLE_KEY`, or `AUDIT_HMAC_SECRET`.
- **Exact Code Paths**:
  - [`.gitignore`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/.gitignore#L7-L13)
  - [`server/.env.example`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/.env.example)
  - [`server/src/config/env.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/config/env.js#L1-L20)
  - [`client/src/services/api.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/client/src/services/api.js#L1-L15)
- **Exact Tests Demonstrating Mitigation**:
  - Codebase inspection and git history verification confirm zero leaked credentials.
- **Residual Risk & Consciously Accepted Limitation**: Pre-commit hooks (e.g. `gitleaks`) should be configured on developer workstations to prevent accidental secret commits.

---

### 18. Insecure Deployment Configuration & Excessive Database Privileges
- **Realistic Attack Scenario**: The production backend runs in development mode, leaking file paths and stack traces in error responses, or the backend connects to PostgreSQL using the `postgres` superuser account which bypasses Row Level Security (`BYPASSRLS`).
- **Attacker's Role & Prerequisites**: External attacker probing errors or exploiting an application injection flaw.
- **Impact**: **High-Critical** — Information disclosure of internal code layout or complete RLS policy bypass.
- **Mitigation Implemented**:
  1. Fail-Closed Production Error Handling: `server/src/app.js#L135-L144` suppresses stack traces and internal errors when `NODE_ENV !== 'development'`.
  2. Forced Row Level Security: All database tables in `003_row_level_security.sql` execute `FORCE ROW LEVEL SECURITY` alongside `ENABLE ROW LEVEL SECURITY`.
  3. Production Blueprint: `render.yaml#L8-L14` forces `NODE_ENV: production` and auto-generates unique cryptographic keys.
- **Exact Code Paths**:
  - [`server/src/app.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/app.js#L135-L144)
  - [`render.yaml`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/render.yaml#L8-L14)
  - [`server/src/db/migrations/003_row_level_security.sql`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/db/migrations/003_row_level_security.sql#L10-L11, L86-L87)
- **Exact Tests Demonstrating Mitigation**:
  - [`server/tests/security.test.js:36-40`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/security.test.js#L36-L40) (verifies standardized fail-closed error bodies)
- **Residual Risk & Consciously Accepted Limitation**: **[OPEN RISK / CONSCIOUS LIMITATION]** In PostgreSQL, the `postgres` superuser has inherent `BYPASSRLS`. For production database operations, a dedicated application user (e.g. `trustvault_app`) lacking superuser status must be provisioned.

---

### 19. Cache Leakage Between Users
- **Realistic Attack Scenario**: User A downloads a confidential document on a shared workstation or through an enterprise forward proxy. User B logs in on the same machine or requests the same URL through the proxy, which serves User A's cached file from the browser disk cache or intermediary cache.
- **Attacker's Role & Prerequisites**: User on a shared workstation or behind an intermediate caching proxy.
- **Impact**: **High** — Breach of document confidentiality across users.
- **Mitigation Implemented**:
  1. Strict Anti-Caching HTTP Headers: `server/src/controllers/documentController.js#L261-L263` injects strict cache control directives on all document download responses:
     - `Cache-Control: private, no-cache, no-store, must-revalidate`
     - `Pragma: no-cache`
     - `Expires: 0`
  2. Client-Side Blob Revocation: `client/src/services/api.js#L109` immediately calls `window.URL.revokeObjectURL(downloadUrl)` after triggering the browser download dialog.
- **Exact Code Paths**:
  - [`server/src/controllers/documentController.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/controllers/documentController.js#L261-L263)
  - [`client/src/services/api.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/client/src/services/api.js#L102-L111)
- **Exact Tests Demonstrating Mitigation**:
  - [`server/tests/document_management.test.js:92`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/document_management.test.js#L92) (`expect(downloadRes.headers['cache-control']).toContain('no-store');`)
- **Residual Risk & Consciously Accepted Limitation**: The physical file saved to the operating system's `Downloads` folder is managed by the user's OS filesystem. Local full-disk encryption (BitLocker / FileVault) is the user organization's responsibility.

---

### 20. Backup, Retention, and Deletion Risks
- **Realistic Attack Scenario**: A document is soft-deleted, but remains in database tables and storage vaults indefinitely. An attacker gaining read access to database backups or historical snapshots extracts documents that users believed were deleted months prior.
- **Attacker's Role & Prerequisites**: Attacker accessing database backup archives or operator auditing old storage objects.
- **Impact**: **Medium-High** — GDPR / regulatory non-compliance; persistence of sensitive data past retention lifecycle.
- **Mitigation Implemented**:
  1. Soft-Delete Architecture: `server/src/controllers/documentController.js#L348-L375` and `db.js#L277-L284` set `is_deleted = true`. All subsequent read and download requests return 404 `DOCUMENT_NOT_FOUND`.
  2. Audit Trail Integrity Preservation: Foreign key constraints in `001_initial_schema.sql` apply `ON DELETE CASCADE` to `document_permissions` and `ON DELETE SET NULL` to `audit_logs`, guaranteeing that historical audit events remain unbroken even when document metadata is purged.
- **Exact Code Paths**:
  - [`server/src/controllers/documentController.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/controllers/documentController.js#L348-L375)
  - [`server/src/db/db.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/db/db.js#L277-L284)
  - [`server/src/db/migrations/001_initial_schema.sql`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/db/migrations/001_initial_schema.sql#L78, L102, L127)
- **Exact Tests Demonstrating Mitigation**:
  - [`server/tests/document_management.test.js:441-473`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/document_management.test.js#L441-L473) (`should allow document owner to delete document (soft delete)`: asserts subsequent listing, GET, and download return 404, and audit log is recorded)
  - [`server/tests/audit_system.test.js:506-521`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/audit_system.test.js#L506-L521) (`should record matching audit event on successful document deletion`)
- **Residual Risk & Consciously Accepted Limitation**: **[OPEN RISK / CONSCIOUS LIMITATION]** While soft-deletion immediately terminates access, physical purge (hard deletion of storage bytes and database rows after a retention window like 30 days) requires a scheduled cron worker. This background hard-purge pipeline is marked as an open risk.

---

### 21. Deactivated Account Session Persistence
- **Realistic Attack Scenario**: An employee is terminated and an administrator deactivates their account via `PATCH /api/admin/users/:id/status` (`is_active: false`). The former employee continues making API requests using their previously issued 24-hour JWT token.
- **Attacker's Role & Prerequisites**: Suspended employee with unexpired JWT token.
- **Impact**: **High** — Continued unauthorized data access post-termination.
- **Mitigation Implemented**:
  1. Live Account Status Verification: Authentication middleware `server/src/middleware/auth.js#L63-L80` resolves `profile.is_active` directly from the database on every request.
  2. Immediate Termination: If `is_active === false`, access is immediately denied with 403 `ACCOUNT_DEACTIVATED` and high-priority event `DEACTIVATED_USER_ACCESS_BLOCKED` is logged.
- **Exact Code Paths**:
  - [`server/src/middleware/auth.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/middleware/auth.js#L63-L80)
  - [`server/src/controllers/adminController.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/controllers/adminController.js#L141-L193)
- **Exact Tests Demonstrating Mitigation**:
  - [`server/tests/security.test.js:51-66`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/security.test.js#L51-L66) (`should immediately block deactivated user accounts from API access`)
- **Residual Risk & Consciously Accepted Limitation**: Negligible.

---

### 22. Client-Injected Ownership & Storage Path Spoofing
- **Realistic Attack Scenario**: An attacker uploads a document while sending `{"owner_id": "<victim_uuid>", "storage_path": "vault/system/trojan.pdf"}` in the request payload to frame another user or overwrite existing vault objects.
- **Attacker's Role & Prerequisites**: Authenticated user.
- **Impact**: **High** — Attribution forgery and storage object collision.
- **Mitigation Implemented**:
  - Safe Server Derivation: `server/src/controllers/documentController.js#L93-L120` strictly derives `owner_id` from `req.user.id` (authenticated token) and generates storage keys using cryptographically random UUIDs (`vault/${req.user.id}/${docUuid}${safeExtension}`).
- **Exact Code Paths**:
  - [`server/src/controllers/documentController.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/controllers/documentController.js#L93-L120)
- **Exact Tests Demonstrating Mitigation**:
  - [`server/tests/document_management.test.js:268-289`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/document_management.test.js#L268-L289) (`should ignore client-supplied owner_id or storage_path during upload and derive them safely`)
- **Residual Risk & Consciously Accepted Limitation**: Negligible.

---

### 23. Sensitive Credential Leakage into Audit Records
- **Realistic Attack Scenario**: An authentication failure or API exception captures the raw request body, writing plain-text passwords, session tokens, or raw file contents into `audit_logs.details`. An auditor inspecting logs is able to harvest user credentials.
- **Attacker's Role & Prerequisites**: Security administrator viewing audit logs or attacker accessing database backups.
- **Impact**: **High** — Credential compromise through audit log review.
- **Mitigation Implemented**:
  - Recursive Scrubbing Engine: `server/src/utils/auditSanitizer.js#L33-L83` traverses all metadata fields. Any key matching `/(password|passwd|pass|token|secret|authorization|auth|bearer|cookie|credential)/i` is replaced with `[REDACTED_SENSITIVE_CREDENTIAL]`, and any binary buffer is replaced with `[REDACTED_BINARY_BUFFER]`.
- **Exact Code Paths**:
  - [`server/src/utils/auditSanitizer.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/utils/auditSanitizer.js#L12, L33-L83)
- **Exact Tests Demonstrating Mitigation**:
  - [`server/tests/audit_system.test.js:536-560`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/audit_system.test.js#L536-L560) (`should automatically scrub passwords, tokens, auth headers, and raw file bytes from metadata`)
- **Residual Risk & Consciously Accepted Limitation**: Negligible.

---

### 24. Distributed Request Correlation Spoofing / Header Injection
- **Realistic Attack Scenario**: An attacker passes an oversized or CRLF-injected `X-Request-ID` header to poison logging pipelines or inject false correlation identifiers into audit ledgers.
- **Attacker's Role & Prerequisites**: Any network caller.
- **Impact**: **Medium** — Log poisoning and distributed tracing corruption.
- **Mitigation Implemented**:
  - Header Validation: `server/src/app.js#L65-L75` validates `X-Request-ID` against regex `^[a-zA-Z0-9_\-]{8,64}$`. If invalid or missing, it discards the header and generates a cryptographically random UUID (`req-${crypto.randomUUID()}`).
- **Exact Code Paths**:
  - [`server/src/app.js`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/src/app.js#L65-L75)
- **Exact Tests Demonstrating Mitigation**:
  - [`server/tests/audit_system.test.js:691-700`](file:///c:/Users/sasip/OneDrive/Desktop/TrustValut/server/tests/audit_system.test.js#L691-L700) (`should filter audit trail by correlation request ID`)
- **Residual Risk & Consciously Accepted Limitation**: Negligible.

---

## Threat to Automated Test Mapping Matrix

| # | Threat Name | Automated Test Suite | Test Case Title | Status |
| :--- | :--- | :--- | :--- | :--- |
| **1** | IDOR via Document IDs | `security.test.js` | `IDOR Check: Unauthorized user cannot read another users document metadata` | PASS |
| | | `permissions_system.test.js` | `1. User A cannot read User B's document metadata (IDOR Defense)` | PASS |
| | | `document_management.test.js` | `should block unauthorized user from reading private metadata (403 IDOR)` | PASS |
| **2** | Missing Download Authorization | `security.test.js` | `IDOR Check: Unauthorized user cannot download another users document stream` | PASS |
| | | `permissions_system.test.js` | `2. User A cannot download, edit or delete User B's document` | PASS |
| | | `permissions_system.test.js` | `8. A revoked viewer cannot access the file through another endpoint` | PASS |
| | | `permissions_system.test.js` | `10. Missing authorization middleware causes security tests to fail` | PASS |
| **3** | Stale Permissions / Post-Revocation | `permissions_system.test.js` | `7. An owner can revoke access and the next request is immediately denied` | PASS |
| | | `security.test.js` | `should grant read access, allow download, and enforce immediate revocation` | PASS |
| **4** | Public / Leaked Storage URLs | `document_management.test.js` | `should allow document owner to upload... (storage_path is undefined)` | PASS |
| | | `document_management.test.js` | `should ignore client-supplied owner_id or storage_path during upload` | PASS |
| **5** | Search / Metadata Leaks | `document_management.test.js` | `should isolate search results: Primary Owner cannot discover Alice documents` | PASS |
| | | `document_management.test.js` | `should filter documents by category / tag / owner` | PASS |
| **6** | Horizontal Privilege Escalation | `security.test.js` | `IDOR Check: Non-owner cannot modify document metadata` | PASS |
| | | `security.test.js` | `IDOR Check: Non-owner cannot delete another users document` | PASS |
| | | `permissions_system.test.js` | `3. User A cannot grant access to User B's document` | PASS |
| | | `permissions_system.test.js` | `5. A user with read permission cannot perform edit operations` | PASS |
| **7** | Vertical Privilege Escalation | `auth_and_schema.test.js` | `1. Role Escalation Prevention (registration downgrade, role endpoint block)`| PASS |
| | | `auth_and_schema.test.js` | `3. Admin Content Isolation (No Blanket Bypass)` | PASS |
| | | `security.test.js` | `3. Strict Admin Document Isolation (No Blanket Bypass)` | PASS |
| | | `permissions_system.test.js` | `11. Admin can inspect permission metadata but cannot bypass content` | PASS |
| **8** | Permission Changes Racing Downloads| `permissions_system.test.js` | `7. An owner can revoke access and the next request is immediately denied` | PASS |
| **9** | Malicious MIME / Oversized Uploads | `security.test.js` | `should reject dangerous files with executable magic bytes disguised as PDF`| PASS |
| | | `security.test.js` | `should reject SVG uploads to prevent Stored Cross-Site Scripting (XSS)` | PASS |
| | | `document_management.test.js` | `should reject uploads exceeding 10MB limit with 400 FILE_TOO_LARGE` | PASS |
| | | `document_management.test.js` | `Invalid File Types & Malware Safeguards (.exe, .sh, SVG, MZ header)` | PASS |
| **10**| Path Traversal / Unsafe Filenames | `document_management.test.js` | `should reject path traversal in document ID parameter (400)` | PASS |
| | | `audit_system.test.js` | `should record audit event when malicious input or path traversal detected` | PASS |
| | | `permissions_system.test.js` | `9. A tampered document ID cannot bypass authorization` | PASS |
| **11**| SQL Injection / Unsafe Queries | `document_management.test.js` | `should search documents across title, description, or tags` | PASS |
| | | `audit_system.test.js` | `should sanitize untrusted input containing CRLF/control characters` | PASS |
| **12**| XSS from Metadata & Names | `security.test.js` | `should reject SVG uploads to prevent Stored Cross-Site Scripting (XSS)` | PASS |
| | | `document_management.test.js` | Download security headers validation (`nosniff`, `attachment`, CSP) | PASS |
| **13**| CSRF / Stolen Session Tokens | `security.test.js` | `1. Authentication & Fail-Closed Guardrails (missing header, invalid JWT)` | PASS |
| **14**| Brute Force / Enumeration | `audit_system.test.js` | `should record audit event when login fails due to invalid credentials` | PASS |
| **15**| Audit Forgery / Deletion / CRLF | `audit_system.test.js` | `2. Append-Only Immutability (updateAuditLog/deleteAuditLog throws exception)`| PASS |
| | | `audit_system.test.js` | `3. Cryptographic Hash Chain & Tamper Detection (action, link, genesis)` | PASS |
| | | `audit_system.test.js` | `6. Data Privacy & Anti-Log-Injection (CRLF stripping, secret scrub)` | PASS |
| | | `security.test.js` | `should DETECT out-of-band tampering when a past audit record is modified` | PASS |
| **16**| Partial Failure Rollback Audit | `document_management.test.js` | `should clean up storage vault when database insertion fails during upload` | PASS |
| **17**| Secrets Committed to Git / Browser | Manual / Git Verification | Git history verified (`git log -S "sb_secret"` clean), `.gitignore` active | VERIFIED |
| **18**| Insecure Deployment & DB Privileges| `security.test.js` | Fail-closed standardized error responses without stack traces | PASS |
| **19**| Cache Leakage Between Users | `document_management.test.js` | Assert `Cache-Control: no-store` on document downloads | PASS |
| **20**| Backup / Retention / Deletion | `document_management.test.js` | `should allow document owner to delete document (soft delete)` | PASS |
| | | `audit_system.test.js` | `should record matching audit event on successful document deletion` | PASS |
| **21**| Deactivated Account Persistence | `security.test.js` | `should immediately block deactivated user accounts from API access` | PASS |
| **22**| Ownership & Storage Path Spoofing | `document_management.test.js` | `should ignore client-supplied owner_id or storage_path during upload` | PASS |
| **23**| Audit Credential Scrubbing | `audit_system.test.js` | `should automatically scrub passwords, tokens, auth headers from metadata` | PASS |
| **24**| Request ID Correlation Injection | `audit_system.test.js` | `should filter audit trail by correlation request ID` | PASS |
