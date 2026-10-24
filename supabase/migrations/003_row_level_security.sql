-- =============================================================================
-- Migration 003: Row Level Security (RLS) Policies
-- TrustVault: Enterprise Secure Document-Sharing Platform
-- Enforces Least Privilege and Cross-User Isolation at the Database Level
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. PROFILES RLS POLICIES
-- -----------------------------------------------------------------------------
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.profiles FORCE ROW LEVEL SECURITY;

-- Users can read their own profile; Administrators can read all profiles
DROP POLICY IF EXISTS "profiles_select_policy" ON public.profiles;
CREATE POLICY "profiles_select_policy"
ON public.profiles
FOR SELECT
TO authenticated
USING (
    id = auth.uid()
    OR EXISTS (
        SELECT 1 FROM public.profiles admin_p
        WHERE admin_p.id = auth.uid()
        AND admin_p.system_role = 'administrator'
        AND admin_p.is_active = TRUE
    )
);

-- Users can update their own personal info (Trigger prevents role/active escalation)
DROP POLICY IF EXISTS "profiles_update_policy" ON public.profiles;
CREATE POLICY "profiles_update_policy"
ON public.profiles
FOR UPDATE
TO authenticated
USING (id = auth.uid())
WITH CHECK (id = auth.uid());

-- Administrators can update any profile (e.g. toggle active status or assign roles)
DROP POLICY IF EXISTS "profiles_admin_update_policy" ON public.profiles;
CREATE POLICY "profiles_admin_update_policy"
ON public.profiles
FOR UPDATE
TO authenticated
USING (
    EXISTS (
        SELECT 1 FROM public.profiles admin_p
        WHERE admin_p.id = auth.uid()
        AND admin_p.system_role = 'administrator'
        AND admin_p.is_active = TRUE
    )
);

-- -----------------------------------------------------------------------------
-- 2. CATEGORIES RLS POLICIES
-- -----------------------------------------------------------------------------
ALTER TABLE public.categories ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.categories FORCE ROW LEVEL SECURITY;

-- All authenticated enterprise users can read category taxonomy
DROP POLICY IF EXISTS "categories_select_policy" ON public.categories;
CREATE POLICY "categories_select_policy"
ON public.categories
FOR SELECT
TO authenticated
USING (TRUE);

-- Only active administrators can insert new categories
DROP POLICY IF EXISTS "categories_insert_policy" ON public.categories;
CREATE POLICY "categories_insert_policy"
ON public.categories
FOR INSERT
TO authenticated
WITH CHECK (
    EXISTS (
        SELECT 1 FROM public.profiles admin_p
        WHERE admin_p.id = auth.uid()
        AND admin_p.system_role = 'administrator'
        AND admin_p.is_active = TRUE
    )
);

-- -----------------------------------------------------------------------------
-- 3. DOCUMENTS RLS POLICIES
-- Strict Isolation: NO BLANKET ADMIN BYPASS FOR READING PRIVATE DOCUMENTS!
-- -----------------------------------------------------------------------------
ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.documents FORCE ROW LEVEL SECURITY;

-- Read policy: User must be owner OR have active grant in document_permissions
DROP POLICY IF EXISTS "documents_select_policy" ON public.documents;
CREATE POLICY "documents_select_policy"
ON public.documents
FOR SELECT
TO authenticated
USING (
    is_deleted = FALSE
    AND (
        owner_id = auth.uid()
        OR EXISTS (
            SELECT 1 FROM public.document_permissions perm
            WHERE perm.document_id = documents.id
            AND perm.user_id = auth.uid()
        )
    )
);

-- Insert policy: User must be document_owner or administrator, setting themselves as owner
DROP POLICY IF EXISTS "documents_insert_policy" ON public.documents;
CREATE POLICY "documents_insert_policy"
ON public.documents
FOR INSERT
TO authenticated
WITH CHECK (
    owner_id = auth.uid()
    AND EXISTS (
        SELECT 1 FROM public.profiles p
        WHERE p.id = auth.uid()
        AND p.system_role IN ('document_owner', 'administrator')
        AND p.is_active = TRUE
    )
);

-- Update policy: Document Owner OR Collaborator with 'edit' permission
DROP POLICY IF EXISTS "documents_update_policy" ON public.documents;
CREATE POLICY "documents_update_policy"
ON public.documents
FOR UPDATE
TO authenticated
USING (
    is_deleted = FALSE
    AND (
        owner_id = auth.uid()
        OR EXISTS (
            SELECT 1 FROM public.document_permissions perm
            WHERE perm.document_id = documents.id
            AND perm.user_id = auth.uid()
            AND perm.permission_level = 'edit'
        )
    )
)
WITH CHECK (
    owner_id = documents.owner_id -- Prevents hijacking ownership via update
);

-- Delete policy: Document Owner ONLY
DROP POLICY IF EXISTS "documents_delete_policy" ON public.documents;
CREATE POLICY "documents_delete_policy"
ON public.documents
FOR DELETE
TO authenticated
USING (
    owner_id = auth.uid()
);

-- -----------------------------------------------------------------------------
-- 4. DOCUMENT_PERMISSIONS RLS POLICIES
-- Owner-Only Delegation Model with Instant Revocation
-- -----------------------------------------------------------------------------
ALTER TABLE public.document_permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.document_permissions FORCE ROW LEVEL SECURITY;

-- Read policy: Document owner can inspect all grants; Grantees can inspect their own grant
DROP POLICY IF EXISTS "permissions_select_policy" ON public.document_permissions;
CREATE POLICY "permissions_select_policy"
ON public.document_permissions
FOR SELECT
TO authenticated
USING (
    user_id = auth.uid()
    OR EXISTS (
        SELECT 1 FROM public.documents doc
        WHERE doc.id = document_permissions.document_id
        AND doc.owner_id = auth.uid()
    )
);

-- Insert policy: Only document owner can grant permissions, cannot grant to self
DROP POLICY IF EXISTS "permissions_insert_policy" ON public.document_permissions;
CREATE POLICY "permissions_insert_policy"
ON public.document_permissions
FOR INSERT
TO authenticated
WITH CHECK (
    granted_by = auth.uid()
    AND user_id <> auth.uid()
    AND EXISTS (
        SELECT 1 FROM public.documents doc
        WHERE doc.id = document_permissions.document_id
        AND doc.owner_id = auth.uid()
    )
);

-- Update policy: Only document owner can change permission level
DROP POLICY IF EXISTS "permissions_update_policy" ON public.document_permissions;
CREATE POLICY "permissions_update_policy"
ON public.document_permissions
FOR UPDATE
TO authenticated
USING (
    EXISTS (
        SELECT 1 FROM public.documents doc
        WHERE doc.id = document_permissions.document_id
        AND doc.owner_id = auth.uid()
    )
);

-- Delete policy: Only document owner can revoke permissions (Enforces Instant Revocation)
DROP POLICY IF EXISTS "permissions_delete_policy" ON public.document_permissions;
CREATE POLICY "permissions_delete_policy"
ON public.document_permissions
FOR DELETE
TO authenticated
USING (
    EXISTS (
        SELECT 1 FROM public.documents doc
        WHERE doc.id = document_permissions.document_id
        AND doc.owner_id = auth.uid()
    )
);

-- -----------------------------------------------------------------------------
-- 5. AUDIT_LOGS RLS POLICIES
-- Append-Only Security Ledger: Only administrators can read. NO ONE can update/delete.
-- -----------------------------------------------------------------------------
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs FORCE ROW LEVEL SECURITY;

-- Read policy: Strict Administrator-Only Access
DROP POLICY IF EXISTS "audit_logs_select_policy" ON public.audit_logs;
CREATE POLICY "audit_logs_select_policy"
ON public.audit_logs
FOR SELECT
TO authenticated
USING (
    EXISTS (
        SELECT 1 FROM public.profiles admin_p
        WHERE admin_p.id = auth.uid()
        AND admin_p.system_role = 'administrator'
        AND admin_p.is_active = TRUE
    )
);

-- Insert policy: Authenticated users can insert audit records for their operations
DROP POLICY IF EXISTS "audit_logs_insert_policy" ON public.audit_logs;
CREATE POLICY "audit_logs_insert_policy"
ON public.audit_logs
FOR INSERT
TO authenticated
WITH CHECK (TRUE);

-- Explicitly NO UPDATE or DELETE policies are created for audit_logs.
-- Combined with trg_audit_logs_immutable, this guarantees tamper resistance.
