-- =============================================================================
-- TrustVault: Enterprise Secure Document-Sharing Platform
-- PostgreSQL Production Schema with Immutable Audit Ledger & Row-Level Security
-- =============================================================================

-- Enable required cryptographic extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- System-wide user roles enum
DO $$ BEGIN
    CREATE TYPE app_system_role AS ENUM ('administrator', 'document_owner', 'viewer');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Document permission levels enum
DO $$ BEGIN
    CREATE TYPE app_permission_level AS ENUM ('read', 'edit');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Audit status enum
DO $$ BEGIN
    CREATE TYPE audit_status_type AS ENUM ('SUCCESS', 'DENIED', 'ERROR');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- -----------------------------------------------------------------------------
-- 1. PROFILES TABLE (Mirrors and extends auth.users)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL UNIQUE,
    full_name VARCHAR(255) NOT NULL,
    system_role app_system_role NOT NULL DEFAULT 'viewer',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_profiles_system_role ON profiles(system_role);
CREATE INDEX IF NOT EXISTS idx_profiles_email ON profiles(email);

-- -----------------------------------------------------------------------------
-- 2. CATEGORIES TABLE
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS categories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed default categories if empty
INSERT INTO categories (name, description) VALUES
    ('Financial Reports', 'Quarterly earnings, audits, balance sheets, tax filings'),
    ('Legal & Compliance', 'NDAs, customer contracts, regulatory agreements, licenses'),
    ('Engineering & Architecture', 'System designs, security specs, API schemas, blueprints'),
    ('Human Resources', 'Offer letters, compensation guidelines, performance reviews'),
    ('General Enterprise', 'Company policies, handbooks, general memos')
ON CONFLICT (name) DO NOTHING;

-- -----------------------------------------------------------------------------
-- 3. DOCUMENTS TABLE
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    category_id UUID REFERENCES categories(id) ON DELETE SET NULL,
    owner_id UUID NOT NULL REFERENCES profiles(id) ON DELETE RESTRICT,
    storage_path VARCHAR(500) NOT NULL UNIQUE,
    original_filename VARCHAR(255) NOT NULL,
    file_size_bytes BIGINT NOT NULL CHECK (file_size_bytes > 0 AND file_size_bytes <= 10485760), -- Max 10MB
    mime_type VARCHAR(100) NOT NULL,
    file_hash_sha256 CHAR(64) NOT NULL,
    tags TEXT[] NOT NULL DEFAULT '{}',
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_documents_owner_id ON documents(owner_id);
CREATE INDEX IF NOT EXISTS idx_documents_category_id ON documents(category_id);
CREATE INDEX IF NOT EXISTS idx_documents_created_at ON documents(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_documents_is_deleted ON documents(is_deleted);
CREATE INDEX IF NOT EXISTS idx_documents_tags ON documents USING gin(tags);

-- -----------------------------------------------------------------------------
-- 4. DOCUMENT_PERMISSIONS TABLE (Named per-document access grants)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS document_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    permission_level app_permission_level NOT NULL,
    granted_by UUID NOT NULL REFERENCES profiles(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_document_user_permission UNIQUE (document_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_doc_perm_document_id ON document_permissions(document_id);
CREATE INDEX IF NOT EXISTS idx_doc_perm_user_id ON document_permissions(user_id);

-- -----------------------------------------------------------------------------
-- 5. AUDIT_LOGS TABLE (Cryptographically chained, append-only security ledger)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id UUID REFERENCES profiles(id) ON DELETE SET NULL,
    user_email VARCHAR(255),
    action VARCHAR(64) NOT NULL,
    status audit_status_type NOT NULL,
    document_id UUID REFERENCES documents(id) ON DELETE SET NULL,
    document_title VARCHAR(255),
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    request_id VARCHAR(64),
    previous_hash CHAR(64) NOT NULL,
    current_hash CHAR(64) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_document_id ON audit_logs(document_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_status ON audit_logs(status);
CREATE INDEX IF NOT EXISTS idx_audit_logs_request_id ON audit_logs(request_id);

-- -----------------------------------------------------------------------------
-- 6. IMMUTABILITY TRIGGER: PREVENT MODIFICATION OR DELETION OF AUDIT RECORDS
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION prevent_audit_log_tampering()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'SECURITY VIOLATION: audit_logs is an append-only ledger. UPDATE and DELETE operations are strictly prohibited.';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DROP TRIGGER IF EXISTS trg_audit_logs_immutable ON audit_logs;
CREATE TRIGGER trg_audit_logs_immutable
BEFORE UPDATE OR DELETE ON audit_logs
FOR EACH ROW
EXECUTE FUNCTION prevent_audit_log_tampering();
