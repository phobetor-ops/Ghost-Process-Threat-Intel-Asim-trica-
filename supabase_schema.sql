-- ============================================================================
-- Ghost Process: Threat Intelligence State & Cache Schema (Supabase / Postgres)
-- ============================================================================

-- Enable pgcrypto for UUID generation if not already active
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS public.threat_intel_cache (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    threat_hash TEXT NOT NULL UNIQUE,
    cve_id TEXT NULL,
    source_feed TEXT NOT NULL,
    title TEXT NOT NULL,
    source_url TEXT NOT NULL,
    published_at TIMESTAMPTZ NULL,
    severity_flag TEXT NOT NULL CHECK (severity_flag IN ('EMERGENCY', 'ROUTINE')),
    markdown_report TEXT NOT NULL,
    pending_notification BOOLEAN NOT NULL DEFAULT TRUE,
    notified_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE public.threat_intel_cache IS
    'Deduplication state cache and routing queue for the Ghost Process Threat Intel pipeline.';

-- Fast lookup index for deduplicating CVEs across multiple feeds (NVD, Exploit-DB, etc.)
CREATE UNIQUE INDEX IF NOT EXISTS idx_threat_intel_cache_cve_id_unique
    ON public.threat_intel_cache (cve_id)
    WHERE cve_id IS NOT NULL;

-- Partial index for the Daily Digest query (pending_notification = TRUE)
CREATE INDEX IF NOT EXISTS idx_threat_intel_cache_pending_digest
    ON public.threat_intel_cache (created_at ASC)
    WHERE pending_notification = TRUE;

-- Enable Row Level Security (RLS)
ALTER TABLE public.threat_intel_cache ENABLE ROW LEVEL SECURITY;

-- Allow pipeline access via Supabase API keys (anon / service_role)
DROP POLICY IF EXISTS "service_role_full_access" ON public.threat_intel_cache;
DROP POLICY IF EXISTS "ghost_process_pipeline_access" ON public.threat_intel_cache;
CREATE POLICY "ghost_process_pipeline_access"
    ON public.threat_intel_cache
    FOR ALL
    TO anon, authenticated, service_role
    USING (true)
    WITH CHECK (true);

GRANT ALL ON TABLE public.threat_intel_cache TO anon, authenticated, service_role;
