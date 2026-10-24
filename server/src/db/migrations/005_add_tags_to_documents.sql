-- =============================================================================
-- Migration 005: Add Tags Support to Documents
-- TrustVault: Enterprise Secure Document-Sharing Platform
-- Enables categorization and tagging for flexible document organization
-- =============================================================================

ALTER TABLE public.documents 
ADD COLUMN IF NOT EXISTS tags TEXT[] NOT NULL DEFAULT '{}';

CREATE INDEX IF NOT EXISTS idx_documents_tags ON public.documents USING gin(tags);
