-- =============================================================================
-- Migration 001: Initial Schema Definition
-- TrustVault: Enterprise Secure Document-Sharing Platform
-- =============================================================================

-- 1. Cryptographic and UUID Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 2. Enumerated Domain Types
DO $$ BEGIN
    CREATE TYPE app_system_role AS ENUM ('administrator', 'document_owner', 'viewer');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE app_permission_level AS ENUM ('read', 'edit');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE audit_status_type AS ENUM ('SUCCESS', 'DENIED', 'ERROR');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- -----------------------------------------------------------------------------
-- 3. Table: PROFILES
-- Mirrors and extends Supabase auth.users.
-- Identifiers: UUID foreign key to auth.users.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL UNIQUE,
    full_name VARCHAR(255) NOT NULL,
    system_role app_system_role NOT NULL DEFAULT 'viewer',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexing for profile queries
CREATE INDEX IF NOT EXISTS idx_profiles_system_role ON public.profiles(system_role);
CREATE INDEX IF NOT EXISTS idx_profiles_email ON public.profiles(email);
CREATE INDEX IF NOT EXISTS idx_profiles_is_active ON public.profiles(is_active);

-- -----------------------------------------------------------------------------
-- 4. Table: CATEGORIES
-- Enterprise document classification and taxonomy.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.categories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_categories_name ON public.categories(name);

-- -----------------------------------------------------------------------------
-- 5. Table: DOCUMENTS
-- Document metadata stored separately from file binary content.
-- Storage key: Private bucket storage path, NEVER a public URL.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    category_id UUID REFERENCES public.categories(id) ON DELETE SET NULL,
    owner_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE RESTRICT,
    storage_path VARCHAR(500) NOT NULL UNIQUE, -- Private storage key: vault/{owner_id}/{doc_id}.enc
    original_filename VARCHAR(255) NOT NULL,
    file_size_bytes BIGINT NOT NULL CHECK (file_size_bytes > 0 AND file_size_bytes <= 10485760), -- Max 10MB
    mime_type VARCHAR(100) NOT NULL,
    file_hash_sha256 CHAR(64) NOT NULL, -- SHA-256 binary integrity checksum
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE, -- Soft-delete flag
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- B-Tree indexes for foreign keys and chronological sorting
CREATE INDEX IF NOT EXISTS idx_documents_owner_id ON public.documents(owner_id);
CREATE INDEX IF NOT EXISTS idx_documents_category_id ON public.documents(category_id);
CREATE INDEX IF NOT EXISTS idx_documents_created_at ON public.documents(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_documents_is_deleted ON public.documents(is_deleted);
CREATE INDEX IF NOT EXISTS idx_documents_file_hash ON public.documents(file_hash_sha256);

-- Full-text search index on document title and description
CREATE INDEX IF NOT EXISTS idx_documents_search ON public.documents 
USING gin(to_tsvector('english', title || ' ' || COALESCE(description, '')));

-- -----------------------------------------------------------------------------
-- 6. Table: DOCUMENT_PERMISSIONS
-- Explicit named per-document permission model (read and edit grants).
-- Immediate revocation model: Unique constraint prevents duplicates;
-- deletion or revocation is enforced instantaneously.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.document_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id UUID NOT NULL REFERENCES public.documents(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    permission_level app_permission_level NOT NULL,
    granted_by UUID NOT NULL REFERENCES public.profiles(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_document_user_permission UNIQUE (document_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_doc_perm_document_id ON public.document_permissions(document_id);
CREATE INDEX IF NOT EXISTS idx_doc_perm_user_id ON public.document_permissions(user_id);
CREATE INDEX IF NOT EXISTS idx_doc_perm_granted_by ON public.document_permissions(granted_by);

-- -----------------------------------------------------------------------------
-- 7. Table: AUDIT_LOGS
-- Immutable, cryptographically chained audit ledger.
-- Records successful and denied access attempts and critical state changes.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.audit_logs (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
    user_email VARCHAR(255),
    action VARCHAR(64) NOT NULL,
    status audit_status_type NOT NULL,
    document_id UUID REFERENCES public.documents(id) ON DELETE SET NULL,
    document_title VARCHAR(255),
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    previous_hash CHAR(64) NOT NULL,
    current_hash CHAR(64) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON public.audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON public.audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_document_id ON public.audit_logs(document_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON public.audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_status ON public.audit_logs(status);
