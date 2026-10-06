-- TraceTramp ↔ WitnessCtl integration: correlate captures and async handoff rows by trace id.

ALTER TABLE witness_captures
    ADD COLUMN IF NOT EXISTS tracetramp_trace_id TEXT,
    ADD COLUMN IF NOT EXISTS tracetramp_request_id TEXT;

CREATE INDEX IF NOT EXISTS idx_witness_captures_tt_trace
    ON witness_captures (tracetramp_trace_id)
    WHERE tracetramp_trace_id IS NOT NULL AND tracetramp_trace_id <> '';

CREATE TABLE IF NOT EXISTS witness_tracetramp_handoffs (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    trace_id    TEXT NOT NULL,
    request_id  TEXT NOT NULL,
    tenant_id   TEXT NOT NULL,
    payload     JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_witness_tt_handoffs_trace
    ON witness_tracetramp_handoffs (trace_id);

CREATE INDEX IF NOT EXISTS idx_witness_tt_handoffs_created
    ON witness_tracetramp_handoffs (created_at DESC);
