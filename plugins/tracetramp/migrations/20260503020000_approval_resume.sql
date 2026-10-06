-- Migration: Add request storage and result caching for approval resume
-- Allows re-execution of approved HITL requests

-- Add columns to approval_queue for request payload and result caching
ALTER TABLE approval_queue ADD COLUMN IF NOT EXISTS request_payload JSONB;
ALTER TABLE approval_queue ADD COLUMN IF NOT EXISTS result_payload JSONB;
ALTER TABLE approval_queue ADD COLUMN IF NOT EXISTS result_ready BOOLEAN DEFAULT FALSE;
ALTER TABLE approval_queue ADD COLUMN IF NOT EXISTS result_trace_id VARCHAR(36);

-- Index for fast lookup of approved but not-yet-executed requests
CREATE INDEX IF NOT EXISTS idx_approval_queue_approved_pending 
ON approval_queue(status, result_ready) 
WHERE status = 'approved' AND result_ready = FALSE;

-- Index for quarantine view
CREATE INDEX IF NOT EXISTS idx_approval_queue_quarantine 
ON approval_queue(status, created_at DESC) 
WHERE status = 'quarantined';
