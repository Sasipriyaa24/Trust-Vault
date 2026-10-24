-- =============================================================================
-- Migration 002: Triggers and Security Guards
-- TrustVault: Enterprise Secure Document-Sharing Platform
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. AUDIT LOG IMMUTABILITY TRIGGER
-- Enforces that audit_logs is an append-only ledger at the PostgreSQL engine level.
-- Any UPDATE or DELETE statement is unconditionally rejected with an exception.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.prevent_audit_log_tampering()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'SECURITY VIOLATION: audit_logs is an append-only ledger. UPDATE and DELETE operations are strictly prohibited.';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DROP TRIGGER IF EXISTS trg_audit_logs_immutable ON public.audit_logs;
CREATE TRIGGER trg_audit_logs_immutable
BEFORE UPDATE OR DELETE ON public.audit_logs
FOR EACH ROW
EXECUTE FUNCTION public.prevent_audit_log_tampering();

-- -----------------------------------------------------------------------------
-- 2. PROFILE ROLE ESCALATION GUARD TRIGGER
-- Prevents ordinary users from elevating their role to 'administrator' or
-- reactivating a suspended account via direct database / Supabase client calls.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.guard_profile_role_escalation()
RETURNS TRIGGER AS $$
DECLARE
    caller_is_admin BOOLEAN := FALSE;
BEGIN
    -- Check if the calling context is an existing administrator
    IF (auth.uid() IS NOT NULL) THEN
        SELECT (system_role = 'administrator' AND is_active = TRUE)
        INTO caller_is_admin
        FROM public.profiles
        WHERE id = auth.uid();
    END IF;

    -- If the caller is not an administrator, forbid modification of system_role and is_active
    IF NOT caller_is_admin THEN
        IF (OLD.system_role IS DISTINCT FROM NEW.system_role) THEN
            RAISE EXCEPTION 'SECURITY VIOLATION: Privilege escalation prohibited. Ordinary users cannot alter their system_role.';
        END IF;

        IF (OLD.is_active IS DISTINCT FROM NEW.is_active) THEN
            RAISE EXCEPTION 'SECURITY VIOLATION: Account status alteration prohibited. Only administrators can toggle is_active.';
        END IF;
    END IF;

    -- Update timestamp
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DROP TRIGGER IF EXISTS trg_guard_profile_role_escalation ON public.profiles;
CREATE TRIGGER trg_guard_profile_role_escalation
BEFORE UPDATE ON public.profiles
FOR EACH ROW
EXECUTE FUNCTION public.guard_profile_role_escalation();

-- -----------------------------------------------------------------------------
-- 3. AUTOMATIC PROFILE CREATION ON AUTH.USERS INSERTION
-- Guarantees a trustworthy, deterministic link between Supabase Auth and profiles.
-- Default role is ALWAYS constrained to 'viewer' for security, unless provisioned.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.handle_new_auth_user()
RETURNS TRIGGER AS $$
DECLARE
    assigned_role public.app_system_role := 'viewer';
    user_name TEXT := '';
BEGIN
    -- Extract full_name from auth metadata if provided
    IF (NEW.raw_user_meta_data->>'full_name' IS NOT NULL) THEN
        user_name := NEW.raw_user_meta_data->>'full_name';
    ELSE
        user_name := SPLIT_PART(NEW.email, '@', 1);
    END IF;

    -- If client metadata attempted to declare administrator, REJECT it and force 'viewer'
    -- Only 'document_owner' can be self-requested during registration if enabled
    IF (NEW.raw_user_meta_data->>'system_role' = 'document_owner') THEN
        assigned_role := 'document_owner';
    ELSE
        assigned_role := 'viewer';
    END IF;

    INSERT INTO public.profiles (id, email, full_name, system_role, is_active, created_at, updated_at)
    VALUES (
        NEW.id,
        NEW.email,
        user_name,
        assigned_role,
        TRUE,
        NOW(),
        NOW()
    )
    ON CONFLICT (id) DO UPDATE
    SET email = EXCLUDED.email,
        full_name = EXCLUDED.full_name;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Hook into auth.users (Supabase Auth schema)
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
AFTER INSERT ON auth.users
FOR EACH ROW
EXECUTE FUNCTION public.handle_new_auth_user();

-- -----------------------------------------------------------------------------
-- 4. AUTOMATIC TIMESTAMP UPDATER
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.touch_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_touch_documents_updated_at ON public.documents;
CREATE TRIGGER trg_touch_documents_updated_at
BEFORE UPDATE ON public.documents
FOR EACH ROW
EXECUTE FUNCTION public.touch_updated_at();

DROP TRIGGER IF EXISTS trg_touch_permissions_updated_at ON public.document_permissions;
CREATE TRIGGER trg_touch_permissions_updated_at
BEFORE UPDATE ON public.document_permissions
FOR EACH ROW
EXECUTE FUNCTION public.touch_updated_at();
