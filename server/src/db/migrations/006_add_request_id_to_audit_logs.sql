-- =============================================================================
-- Migration 006: Add Request Correlation ID to Audit Logs
-- TrustVault: Enterprise Secure Document-Sharing Platform
-- Enables end-to-end distributed tracing and request correlation in security audits
-- =============================================================================

ALTER TABLE public.audit_logs 
ADD COLUMN IF NOT EXISTS request_id VARCHAR(64);

CREATE INDEX IF NOT EXISTS idx_audit_logs_request_id ON public.audit_logs(request_id);
