-- =============================================================================
-- Migration 004: Safe Seed Data for Categories and Initial Audit Genesis
-- TrustVault: Enterprise Secure Document-Sharing Platform
-- Note: Does NOT hardcode plain-text production user passwords.
-- User accounts are created via Supabase Auth API or server/src/db/seed.js.
-- =============================================================================

-- 1. Seed Enterprise Classification Categories
INSERT INTO public.categories (id, name, description) VALUES
    ('c1111111-1111-1111-1111-111111111111', 'Financial Reports', 'Quarterly earnings, audits, balance sheets, tax filings'),
    ('c2222222-2222-2222-2222-222222222222', 'Legal & Compliance', 'NDAs, customer contracts, regulatory agreements, licenses'),
    ('c3333333-3333-3333-3333-333333333333', 'Engineering & Architecture', 'System designs, security specs, API schemas, blueprints'),
    ('c4444444-4444-4444-4444-444444444444', 'Human Resources', 'Offer letters, compensation guidelines, performance reviews'),
    ('c5555555-5555-5555-5555-555555555555', 'General Enterprise', 'Company policies, handbooks, general memos')
ON CONFLICT (name) DO NOTHING;

-- 2. Seed Genesis Audit Log Record (Blockchain-lite Anchor)
-- Only inserted if the audit log table is currently empty
INSERT INTO public.audit_logs (
    id,
    timestamp,
    user_id,
    user_email,
    action,
    status,
    document_id,
    document_title,
    ip_address,
    user_agent,
    details,
    previous_hash,
    current_hash
)
SELECT
    1,
    NOW(),
    NULL,
    'system@trustvault.internal',
    'SYSTEM_GENESIS_INITIALIZATION',
    'SUCCESS',
    NULL,
    NULL,
    '127.0.0.1',
    'TrustVault Cryptographic Kernel',
    '{"message": "Genesis state anchored. Cryptographic hash chain initialized."}'::jsonb,
    '0000000000000000000000000000000000000000000000000000000000000000',
    -- Computed HMAC-SHA256 seed anchor
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
WHERE NOT EXISTS (SELECT 1 FROM public.audit_logs WHERE id = 1);
