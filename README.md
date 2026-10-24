# 🛡️ TrustVault: Enterprise Secure Document-Sharing Platform
> **Challenge**: Snovasys Fresher Hiring Challenge 2026  
> **Security Weight**: 35% of Total Evaluation Score  
> **Architecture Principle**: Zero-Trust, Least Privilege, Fail-Closed, Cryptographic Verification  

---

## 📋 Table of Contents
1. [Executive Summary & Security Philosophy](#1-executive-summary--security-philosophy)
2. [Defense-in-Depth: PostgreSQL vs Express Protections](#2-defense-in-depth-postgresql-vs-express-protections)
3. [Vulnerability Review: Cross-User Access & Table Policy Analysis](#3-vulnerability-review-cross-user-access--table-policy-analysis)
4. [Version-Controlled SQL Migrations Inventory](#4-version-controlled-sql-migrations-inventory)
5. [Setup Instructions from a Clean Clone](#5-setup-instructions-from-a-clean-clone)
6. [Automated Security & Vulnerability Test Suite](#6-automated-security--vulnerability-test-suite)
7. [Environment Variable Configuration Guide](#7-environment-variable-configuration-guide)
8. [Safe Demo Seeding & Multi-Role Evaluation Switcher](#8-safe-demo-seeding--multi-role-evaluation-switcher)
9. [Supabase Cloud Deployment Guide](#9-supabase-cloud-deployment-guide)

---

## 1. Executive Summary & Security Philosophy

**TrustVault** is a zero-trust enterprise document-sharing repository designed to protect confidential enterprise assets, legal filings, and financial statements. Security accounts for 35% of the evaluation criteria; therefore, TrustVault is built with a **strict defense-in-depth architecture**.

Security is **never** claimed solely on the basis of enabling Row Level Security (RLS) or application guards in isolation. Instead, every operation is validated by two distinct, complementary security layers:
1. **The Application Layer (Express)**: Validates input, inspects binary magic bytes, signs audit logs with out-of-band HMAC secrets, enforces rate limits, acts as a streaming proxy (preventing storage URL leakage), and enforces strict administrator document isolation.
2. **The Database Engine (PostgreSQL & RLS)**: Enforces referential integrity, check constraints, immutable triggers, role escalation guards, and least-privilege row-level filtering.

---

## 2. Defense-in-Depth: PostgreSQL vs Express Protections

| Protection / Guard | Enforced by PostgreSQL Engine | Enforced by Express Gateway | Why Dual Enforcement is Required |
|---|---|---|---|
| **Role Escalation Defense** | **Trigger `guard_profile_role_escalation`** raises exception if non-admin attempts to update `system_role` or `is_active`. | Input sanitization drops client-supplied `system_role` and `role` parameters during registration and profile updates. | If a compromised client or direct SQL call attempts to escalate privileges, the DB trigger blocks it. Express ensures invalid payloads are rejected at the edge. |
| **Audit Ledger Immutability** | **Trigger `prevent_audit_log_tampering`** blocks all `UPDATE` and `DELETE` statements unconditionally. | Application-level audit service is append-only and cryptographically chains every record using `HMAC-SHA256`. | Prevents rogue insider developers from wiping or altering audit records even with raw SQL queries. Express signs hashes with a secret kept out of the DB. |
| **No Blanket Admin Document Bypass** | RLS policy on `documents` **does not** include an admin bypass for SELECT. | `authorizeDocumentAccess` middleware strictly checks document ownership or explicit `document_permissions` entries, rejecting admins with 403. | Guarantees administrators cannot snoop on private documents either through API endpoints or through client-scoped database queries. |
| **Zero-Trust Private File Storage** | Supabase Storage bucket `trustvault-docs` is set to private with zero public read policies. | Downloads stream via `/api/documents/:id/download` proxy with `X-Content-Type-Options: nosniff` and `Content-Disposition: attachment`. | Database cannot stream binary files or set HTTP browser hardening headers. Express acts as the secure streaming gateway. |
| **File Type & Malware Protection** | Check constraint on `file_size_bytes` ensures $0 < \text{size} \le 10\text{MB}$. | **Magic bytes inspection** inspects binary headers (`%PDF-`, PNG, JPEG, DOCX) and **completely bans SVGs** (Stored XSS prevention). | PostgreSQL only sees metadata strings (which can be spoofed). Express inspects the raw binary buffer before saving to disk or storage. |
| **Cross-User Isolation (IDOR Defense)** | RLS policies restrict SELECT/UPDATE/DELETE to `owner_id = auth.uid()` or matching `document_permissions`. | Route controllers query scoped by `req.user.id` and fail closed on missing or unauthorized records (403/404). | RLS provides defense-in-depth if an API developer writes an unscoped query. Express ensures access denials write immediate security audit logs. |
| **Immediate Access Revocation** | Unique constraint `(document_id, user_id)` on `document_permissions`; deletion drops access instantaneously. | Real-time query against database on every single read, download, edit, and delete request with zero distributed stale cache. | Guarantees that when an owner revokes access, the recipient is locked out immediately on their next request. |

---

## 3. Vulnerability Review: Cross-User Access & Table Policy Analysis

A comprehensive security review of every table, foreign key, and policy was conducted to ensure no cross-user data leakage:

### 1. `profiles` Table
- **Primary Key**: `id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE`.
- **Potential Cross-User Vulnerability**: Can User B read or modify User A's profile?
- **Protection**:
  - `profiles_select_policy`: Users can only SELECT their own row (`id = auth.uid()`), while verified administrators can query all profiles for user management.
  - `profiles_update_policy`: Users can only UPDATE their own row (`id = auth.uid()`).
  - **Role Escalation Vector Neutralized**: Even if User A attempts `UPDATE profiles SET system_role = 'administrator'`, PostgreSQL trigger `guard_profile_role_escalation` catches the change and raises a `SECURITY VIOLATION` exception.

### 2. `documents` Table
- **Foreign Keys**: `owner_id REFERENCES profiles(id) ON DELETE RESTRICT`, `category_id REFERENCES categories(id) ON DELETE SET NULL`.
- **Storage Key**: `storage_path VARCHAR(500) UNIQUE` stores a private unguessable key (e.g. `vault/{owner_id}/{uuid}.bin`). **No public URLs are ever stored or exposed.**
- **Potential Cross-User Vulnerability**: Can User B guess User A's document UUID and download or delete it?
- **Protection**:
  - `documents_select_policy`: User can only SELECT documents where `owner_id = auth.uid()` OR where an active grant exists in `document_permissions`.
  - `documents_delete_policy`: Strictly `owner_id = auth.uid()`. Collaborators and administrators cannot delete another user's document.
  - `documents_update_policy`: Collaborators with `edit` permission can only update metadata; `WITH CHECK (owner_id = documents.owner_id)` prevents transferring or hijacking ownership.

### 3. `document_permissions` Table
- **Foreign Keys**: `document_id REFERENCES documents(id) ON DELETE CASCADE`, `user_id REFERENCES profiles(id) ON DELETE CASCADE`.
- **Constraint**: `CONSTRAINT uq_document_user_permission UNIQUE (document_id, user_id)`.
- **Potential Cross-User Vulnerability**: Can User B grant themselves access to User A's document?
- **Protection**:
  - `permissions_insert_policy`: Enforces that `auth.uid()` MUST match the document's `owner_id`. Non-owners cannot grant access.
  - `permissions_delete_policy`: Only the document owner can revoke access.
  - `user_id <> auth.uid()` prevents owners from granting redundant permissions to themselves.

### 4. `audit_logs` Table
- **Immutability Guarantee**: Trigger `trg_audit_logs_immutable` raises an exception on ANY `UPDATE` or `DELETE`.
- **Cryptographic Hash Chaining**: Each record contains `current_hash = HMAC-SHA256(secret, previous_hash + payload)`. Out-of-band database modifications break the hash chain and are detected by `/api/admin/audit-logs/verify`.
- **Access Control**: Ordinary users cannot access audit logs; only active administrators can view global telemetry.

---

## 4. Version-Controlled SQL Migrations Inventory

Migrations are stored in both `server/src/db/migrations/` and `supabase/migrations/`:

| Migration File | Description & Enforced Safeguards |
|---|---|
| `001_initial_schema.sql` | Creates UUID extensions, domain enums, tables (`profiles`, `categories`, `documents`, `document_permissions`, `audit_logs`), check constraints (10MB limit), and performance indexes. |
| `002_triggers_and_guards.sql` | Creates `prevent_audit_log_tampering` trigger, `guard_profile_role_escalation` trigger, and `handle_new_auth_user` trigger for trustworthy auth synchronization. |
| `003_row_level_security.sql` | Enables and forces RLS on all tables with granular SELECT, INSERT, UPDATE, and DELETE policies. Eliminates blanket admin bypass. |
| `004_safe_seed_demo_accounts.sql` | Seeds enterprise classification categories and initializes the genesis anchor block (`id = 1`) for cryptographic audit log hash chaining. |

---

## 5. Setup Instructions from a Clean Clone

Follow these steps to set up and run TrustVault from a fresh clone:

### Prerequisites
- **Node.js**: `v18.0.0` or later (`v22.x` recommended)
- **npm**: `v9.x` or later

### Step 1: Clone and Install Dependencies
```bash
# Clone the repository
git clone https://github.com/YourUsername/TrustVault.git
cd TrustVault

# Install root, backend, and frontend dependencies
npm install --prefix server
npm install --prefix client
```

### Step 2: Configure Environment Variables
Copy `.env.example` in `server/`:
```bash
cp server/.env.example server/.env
```
*(A working development configuration with in-memory secure vault fallback is pre-configured, allowing tests and local evaluation to run out-of-the-box without external cloud dependencies!)*

### Step 3: Run the Automated Security Tests
Run the complete automated security test suite to verify all 28 security invariants:
```bash
npm test
```

### Step 4: Start Backend and Frontend
Open two terminal windows:

**Terminal 1 (Backend API Gateway)**:
```bash
npm run server
# Starts backend at http://localhost:5000 (Health Check: http://localhost:5000/api/health)
```

**Terminal 2 (Frontend Client)**:
```bash
npm run client
# Starts Vite client at http://localhost:5173
```

Open `http://localhost:5173` in your browser.

---

## 6. Automated Security & Vulnerability Test Suite

The test suite runs 28 rigorous automated tests in Jest & Supertest, organized into two dedicated suites:

```bash
npm test
```

### Test Suite Output:
```text
PASS tests/auth_and_schema.test.js
  🔒 TrustVault Schema & Authentication Defense Test Suite
    1. Role Escalation Prevention
      √ should reject or downgrade client attempts to self-assign administrator role during registration (110 ms)
      √ should block non-administrators from accessing the user role management endpoint (56 ms)
      √ should derive user identity strictly from authoritative server data, ignoring client role fields (44 ms)
    2. Unauthorised Cross-User Document Access (IDOR)
      √ should block an unauthorized user from reading anothers document metadata (IDOR) (44 ms)
      √ should block an unauthorized user from downloading anothers document file stream (46 ms)
      √ should block an unauthorized user from updating metadata of anothers document (37 ms)
      √ should block an unauthorized user from granting permissions on anothers document (37 ms)
      √ should block an unauthorized user from revoking permissions on anothers document (74 ms)
    3. Admin Content Isolation (No Blanket Bypass)
      √ should enforce that administrators CANNOT read private document metadata without explicit delegation (49 ms)
      √ should enforce that administrators CANNOT download private document file bytes without explicit delegation (34 ms)
    4. Audit Log Access Isolation & Immutability
      √ should restrict audit trail viewing strictly to administrators (35 ms)
      √ should detect out-of-band tampering in the audit log hash chain (30 ms)

PASS tests/security.test.js
  🛡️ TrustVault Automated Security & Vulnerability Test Suite
    1. Authentication & Fail-Closed Guardrails
      √ should fail-closed and reject requests without Authorization header (34 ms)
      √ should reject malformed or tampered JWT signatures (23 ms)
      √ should immediately block deactivated user accounts from API access (31 ms)
    2. Insecure Direct Object Reference (IDOR) Defense
      √ IDOR Check: Unauthorized user cannot read another users document metadata (50 ms)
      √ IDOR Check: Unauthorized user cannot download another users document stream (51 ms)
      √ IDOR Check: Non-owner cannot modify document metadata (45 ms)
      √ IDOR Check: Non-owner cannot delete another users document (48 ms)
    3. Strict Admin Document Isolation (No Blanket Bypass)
      √ should BLOCK administrators from reading private document metadata without explicit grant (41 ms)
      √ should BLOCK administrators from downloading private document file bytes without explicit grant (30 ms)
    4. Named Permissions & Immediate Access Revocation
      √ should grant read access, allow download, and enforce immediate revocation (86 ms)
    5. Upload Validation & Anti-Malware Safeguards
      √ should block viewers from uploading documents (Role Privilege Enforcement) (18 ms)
      √ should reject dangerous files with executable magic bytes disguised as PDF (23 ms)
      √ should reject SVG uploads to prevent Stored Cross-Site Scripting (XSS) (20 ms)
    6. Cryptographic Audit Chain Integrity & Tamper Detection
      √ should block non-administrators from accessing global audit logs (16 ms)
      √ should verify that an untampered audit ledger passes cryptographic integrity verification (15 ms)
      √ should DETECT out-of-band tampering when a past audit record is modified (33 ms)

Test Suites: 2 passed, 2 total
Tests:       28 passed, 28 total
Snapshots:   0 total
Time:        3.628 s
```

---

## 7. Environment Variable Configuration Guide

In `server/.env`:

```env
# Application Settings
PORT=5000
NODE_ENV=development
CLIENT_ORIGIN=http://localhost:5173

# Direct PostgreSQL Connection URL (Used by migration runner: npm run migrate)
DATABASE_URL=postgres://postgres:[YOUR-PASSWORD]@db.[YOUR-PROJECT-ID].supabase.co:5432/postgres

# Supabase Cloud Project Settings
# CRITICAL: NEVER expose SUPABASE_SERVICE_ROLE_KEY to the frontend client!
SUPABASE_URL=https://your-project-id.supabase.co
SUPABASE_ANON_KEY=your-supabase-anon-public-key
SUPABASE_SERVICE_ROLE_KEY=your-supabase-service-role-secret-key
SUPABASE_JWT_SECRET=your-supabase-jwt-secret-found-in-project-api-settings

# Cryptographic Audit Hash Chaining Secret (Min 32 characters)
AUDIT_HMAC_SECRET=your-enterprise-audit-hmac-secret-at-least-32-chars

# Supabase Storage Private Bucket Name
STORAGE_BUCKET_NAME=trustvault-docs

# Safe Demo Account Seeding Credentials (Used by: npm run seed)
# Passwords are read strictly from environment variables, never hardcoded in repository.
SEED_ADMIN_EMAIL=admin@trustvault.internal
SEED_ADMIN_PASSWORD=AdminSecurePassword2026!
SEED_OWNER_EMAIL=owner@trustvault.internal
SEED_OWNER_PASSWORD=OwnerSecurePassword2026!
SEED_VIEWER_EMAIL=viewer@trustvault.internal
SEED_VIEWER_PASSWORD=ViewerSecurePassword2026!
```

---

## 8. Safe Demo Seeding & Multi-Role Evaluation Switcher

### Safe Seeding CLI
To seed demo accounts without hardcoding passwords into source code:
```bash
npm run seed
```
This reads credentials safely from `SEED_ADMIN_PASSWORD`, `SEED_OWNER_PASSWORD`, and `SEED_VIEWER_PASSWORD` in your `.env`.

### 1-Click Multi-Role Persona Switcher
The web application header includes a persistent **Snovasys Evaluation Ribbon** enabling hiring evaluators to switch roles with a single click:

1. 👑 **Administrator** (`admin@trustvault.internal`):
   - Accesses Admin Security Portal, Global Audit Trail, Hash Chain Verification, and User Governance.
   - Proves administrators **cannot** read or download private documents without explicit delegation.
2. 📁 **Document Owner** (`owner@trustvault.internal`):
   - Uploads files, edits metadata, manages named collaborators, and revokes access.
3. 👥 **Alice (Owner 2)** (`alice@trustvault.internal`):
   - Secondary document owner (demonstrating cross-user IDOR isolation).
4. 👁️ **Viewer** (`viewer@trustvault.internal`):
   - Read-only guest. Can only access documents explicitly shared with them. Uploading is disabled.

---

## 9. Supabase Cloud Deployment Guide

To deploy against a live Supabase production project:

1. Create a Supabase project at [supabase.com](https://supabase.com).
2. Apply the version-controlled SQL migrations:
   ```bash
   DATABASE_URL="postgres://postgres:[PASSWORD]@db.[PROJECT-ID].supabase.co:5432/postgres" npm run migrate
   ```
   *(Or copy the SQL files in `supabase/migrations/` into the Supabase Web SQL Editor in numerical order: `001`, `002`, `003`, `004`)*.
3. In **Storage**, create a new bucket named `trustvault-docs`. Ensure **"Public bucket" is OFF** (unchecked).
4. Run safe seeding:
   ```bash
   npm run seed
   ```
5. Deploy the backend to a Node-compatible service (e.g. Render, Railway, Fly.io) with `.env` configured.
6. Deploy the frontend React app to a modern hosting service (e.g. Vercel, Netlify).

---
*Built for the Snovasys Fresher Hiring Challenge 2026. Security is our first, highest, and non-negotiable priority.*
