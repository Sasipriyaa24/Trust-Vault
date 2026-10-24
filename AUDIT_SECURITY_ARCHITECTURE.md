# TrustVault Enterprise Audit System: Cryptographic Ledger & Security Architecture

TrustVault treats audit logs as a **core security perimeter control and evidentiary artifact**, rather than ordinary application diagnostic logging. Every security-relevant event is recorded in an immutable, append-only, cryptographically verifiable ledger.

---

## 1. Audit Event Data Schema

Every audit record conforms to the following schema:

| Field | Type | Description |
| :--- | :--- | :--- |
| `id` | `BIGINT` / `BIGSERIAL` | Monotonically increasing sequential event sequence number. |
| `timestamp` | `TIMESTAMPTZ` (UTC) | Exact ISO 8601 UTC timestamp of event generation. |
| `user_id` | `UUID` (Foreign Key) | Authoritative actor ID (`null` if unauthenticated/anonymous). |
| `user_email` | `VARCHAR(255)` | Sanitized email of the actor at the time of the event. |
| `action` | `VARCHAR(64)` | Standardized alphanumeric action identifier (e.g., `DOCUMENT_UPLOAD_SUCCESS`, `DOCUMENT_ACCESS_DENIED`). |
| `status` | `ENUM` / `VARCHAR(16)` | Event outcome: `SUCCESS`, `DENIED`, or `ERROR`. |
| `document_id` | `UUID` (Foreign Key) | Target document ID where applicable (`null` for system/auth events). |
| `document_title`| `VARCHAR(255)` | Sanitized title of target document. |
| `request_id` | `VARCHAR(64)` | Distributed correlation ID (`X-Request-ID` or `req-<UUID>`) for end-to-end tracing. |
| `ip_address` | `VARCHAR(45)` | Client IP address (sanitized). |
| `user_agent` | `TEXT` | Sanitized client user-agent string (CRLF and control characters stripped). |
| `details` | `JSONB` | Minimal safe metadata explaining the event. **Secrets and file bytes are strictly scrubbed**. |
| `previous_hash` | `CHAR(64)` | Cryptographic pointer to the immediate predecessor's HMAC hash (`0`.repeat(64) for Genesis block). |
| `current_hash` | `CHAR(64)` | HMAC-SHA256 signature binding predecessor hash, metadata, and correlation ID. |

---

## 2. Event Taxonomy & Coverage

The audit system guarantees **zero-drop surveillance** across the following categories:

```
                                    TrustVault Audit System
                                               │
        ┌───────────────────┬──────────────────┼──────────────────┬──────────────────┐
        ▼                   ▼                  ▼                  ▼                  ▼
 Authentication         Document           Permission          Security         Administrative
     Events            Lifecycle            Control            Denials            Governance
 ─────────────────   ───────────────   ────────────────   ─────────────────   ──────────────────
 USER_LOGIN_SUCCESS  DOCUMENT_UPLOAD   PERMISSION_GRANT   DOCUMENT_ACCESS_    USER_PROFILE_
 USER_LOGIN_FAILED   DOCUMENT_READ     PERMISSION_REVOKE  DENIED (IDOR)       ADMIN_MODIFIED
 USER_REGISTERED     DOCUMENT_DOWNLOAD                    ADMIN_BLANKET_      CATEGORY_CREATED
 DEMO_ROLE_SWITCH    DOCUMENT_UPDATE                      BYPASS_BLOCKED      AUDIT_INTEGRITY_
                     DOCUMENT_DELETE                      MALICIOUS_UPLOAD_   VERIFIED
                     DOCUMENT_UPLOAD_                     BLOCKED
                     FAILED (Rollback)                    MALICIOUS_INPUT_
                                                          DETECTED
```

---

## 3. Cryptographic Hash Chain Architecture

Each block in the audit trail is cryptographically linked to its immediate predecessor using keyed **HMAC-SHA256**:

$$H_0 = 0000000000000000000000000000000000000000000000000000000000000000 \quad (\text{Genesis Hash})$$

$$H_i = \text{HMAC-SHA256}\Big(K_{\text{audit}}, \, H_{i-1} \,\|\, \text{id}_i \,\|\, \text{ts}_i \,\|\, \text{actor}_i \,\|\, \text{action}_i \,\|\, \text{status}_i \,\|\, \text{docId}_i \,\|\, \text{reqId}_i \,\|\, \text{CanonicalJSON}(\text{details}_i)\Big)$$

Where:
- $K_{\text{audit}}$ is the secret key (`AUDIT_HMAC_SECRET`) held out-of-band by the application server or KMS.
- $\text{CanonicalJSON}(\cdot)$ is a deterministic serializer that sorts dictionary keys to eliminate formatting ambiguity.

---

## 4. Threat Model & Why a Hash Chain Alone Does Not Prevent DB Superuser Rewrites

> **Cryptographic Reality: Ordinary database rows are never tamper-proof.**
> A hash chain alone provides **tamper evidence**, not **tamper prevention**, against privileged database operators.

### Why a Privileged Database Operator Can Rewrite the Entire Chain
1. **Unrestricted Storage Privileges**: A Database Administrator (DBA) or an adversary who compromises the PostgreSQL `postgres` superuser account can:
   - Disable triggers: `ALTER TABLE audit_logs DISABLE TRIGGER ALL;`
   - Bypass Row Level Security: `ALTER TABLE audit_logs DISABLE ROW LEVEL SECURITY;`
   - Directly modify arbitrary rows in storage: `UPDATE audit_logs SET action = '...' WHERE id = 42;`
2. **Recomputing History**: If the hash chain is computed via unkeyed SHA-256, or if the DBA compromises the server environment variables or KMS configuration where `AUDIT_HMAC_SECRET` is stored, the DBA can:
   - Alter row $k$.
   - Recompute $H_k = \text{HMAC}(K, H_{k-1} \,\|\, \text{row}_k)$.
   - Sequentially recompute $H_{k+1}, H_{k+2}, \dots, H_n$ up to the current tail.
   - The resulting table will contain a mathematically unbroken, valid hash chain.

### Defense-in-Depth & Operational Controls
To mitigate this inherent limitation, TrustVault implements **defense-in-depth**:

1. **Separation of Duties & Key Isolation**:
   - The database server **never** stores `AUDIT_HMAC_SECRET`. Even with full read access to the database dump, a DBA cannot recompute the HMAC hashes without compromising the application host or cloud KMS.
2. **Database Trigger Guardrails**:
   - PostgreSQL trigger `prevent_audit_log_tampering` executes `BEFORE UPDATE OR DELETE` and raises an uncatchable PL/pgSQL exception for all standard database users.
3. **PostgreSQL Row Level Security (RLS)**:
   - RLS is permanently active on `audit_logs` with zero `UPDATE` or `DELETE` policies.
4. **Out-of-Band Checkpointing (Signed Checkpoints / WORM Storage)**:
   - **Operational Recommendation**: Periodically (e.g., every 5 minutes or every 500 events), the application computes the current tail hash $H_n$, signs it using an asymmetric private key resident in a Hardware Security Module (HSM), and publishes the signed checkpoint to an immutable, Write-Once-Read-Many (WORM) storage destination (such as AWS S3 Object Lock in Compliance Mode or Google Cloud Storage Bucket Lock).
   - Once a checkpoint $H_n$ is committed to WORM storage, no DBA—regardless of privilege—can alter historical records prior to $n$ without causing an immediate mismatch with the externally anchored checkpoint.

---

## 5. Security & Privacy Guarantees

### 1. Zero Secret Leakage (Automated Redaction Engine)
TrustVault's `auditSanitizer` recursively inspects all metadata passed to `details`:
- Any key matching `/(password|passwd|pass|token|secret|authorization|auth|bearer|cookie|credential|key)/i` is replaced with `[REDACTED_SENSITIVE_CREDENTIAL]`.
- Any binary `Buffer` or byte array is replaced with `[REDACTED_BINARY_BUFFER]`.
- Document file contents and private plaintext descriptions are **never** logged.

### 2. Anti-Log-Injection Defense
- Plain text log injection (CRLF injection) occurs when untrusted input contains carriage returns (`\r`) or line feeds (`\n`), allowing an attacker to inject fake log entries into log files or split syslog records.
- TrustVault strips all ASCII control characters (`[\x00-\x1F\x7F]`) and newline sequences from actor emails, user agents, action names, and metadata strings, replacing them with single spaces.

### 3. Distributed Request Correlation
- Every incoming HTTP request is assigned a unique `X-Request-ID` via correlation middleware in `app.js`.
- If a client supplies a valid `X-Request-ID` header matching `^[a-zA-Z0-9_\-]{8,64}$`, it is preserved; otherwise, a cryptographically random UUID (`req-<UUID>`) is generated.
- The `request_id` is propagated to every audit log and returned in response headers, allowing incident responders to correlate HTTP requests directly with database mutations and security denials.

### 4. Transactional Rollback & Partial Failure Auditing
- When a document is uploaded, raw bytes are written to the private vault before metadata is committed to the database.
- If database insertion or verification fails:
  1. The storage object is deleted immediately (transactional rollback).
  2. An audit event `DOCUMENT_UPLOAD_FAILED` (outcome `ERROR`) is recorded with `storageRolledBack: true`.
  3. No orphaned storage files or unlogged errors remain.

---

## 6. Admin Activity Dashboard

The administrator portal (`AdminDashboardView.jsx`) provides multi-attribute surveillance:
- **Filters**:
  - **Actor**: Substring search across actor email or UUID.
  - **Action**: Substring search across action names (e.g., `DENIED`, `UPLOAD`, `LOGIN`).
  - **Outcome**: Exact filtering by status (`SUCCESS`, `DENIED`, `ERROR`).
  - **Target Document**: Substring search across document title or UUID.
  - **Date Range**: UTC date range (`dateFrom` to `dateTo`).
- **Cryptographic Verifier**: One-click verification of the entire HMAC hash chain from the Genesis block to the tail, with instant Breached Block ID identification.
- **Security Demonstration Hook**: Simulated out-of-band tampering button to verify that the cryptographic verifier catches adversarial record edits.
- **Record Inspector**: Modal view displaying previous hash, current hash, correlation ID, and confirming that no sensitive passwords or secrets exist in the metadata.
