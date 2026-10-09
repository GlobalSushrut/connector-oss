-- AgentPassport — Initial Schema
-- All tables prefixed ap_ for namespace isolation.
-- Append-only audit log. No UPDATE or DELETE on ap_audit_log.

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ─────────────────────────────────────────────────────────────────
-- 1. ORGANISATIONS  (multi-tenant root)
-- ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ap_organisations (
    id              UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            TEXT        NOT NULL,
    slug            TEXT        NOT NULL UNIQUE,
    connector_org_id TEXT,                         -- linked ConnectorOS org
    settings        JSONB       NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─────────────────────────────────────────────────────────────────
-- 2. AGENTS  (every registered AI agent)
-- ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ap_agents (
    id                  UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id              UUID        NOT NULL REFERENCES ap_organisations(id) ON DELETE CASCADE,
    did                 TEXT        NOT NULL UNIQUE,   -- did:connector:agent:<uuid>
    name                TEXT        NOT NULL,
    version             TEXT        NOT NULL DEFAULT '1.0',
    description         TEXT,
    agent_card          JSONB       NOT NULL DEFAULT '{}',  -- A2A agent card
    connector_pid       TEXT,                               -- ConnectorOS process ID
    status              TEXT        NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending','active','suspended','quarantined','revoked')),
    trust_score         NUMERIC(5,4) NOT NULL DEFAULT 1.0
                            CHECK (trust_score >= 0 AND trust_score <= 1),
    total_interactions  BIGINT      NOT NULL DEFAULT 0,
    violation_count     INT         NOT NULL DEFAULT 0,
    incident_count      INT         NOT NULL DEFAULT 0,
    public_key_ed25519  TEXT,                               -- hex-encoded Ed25519 pubkey
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    activated_at        TIMESTAMPTZ,
    last_seen_at        TIMESTAMPTZ,
    revoked_at          TIMESTAMPTZ,
    revocation_reason   TEXT,
    revoked_by          TEXT,
    audit_cid           TEXT,                               -- latest CID chain entry
    metadata            JSONB       NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_agents_org     ON ap_agents(org_id);
CREATE INDEX IF NOT EXISTS idx_agents_status  ON ap_agents(status);
CREATE INDEX IF NOT EXISTS idx_agents_did     ON ap_agents(did);
CREATE INDEX IF NOT EXISTS idx_agents_score   ON ap_agents(trust_score DESC);

-- ─────────────────────────────────────────────────────────────────
-- 3. SPONSORS  (human liability chain — one active per agent)
-- ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ap_sponsors (
    id                  UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id            UUID        NOT NULL REFERENCES ap_agents(id) ON DELETE CASCADE,
    org_id              UUID        NOT NULL REFERENCES ap_organisations(id),
    user_did            TEXT        NOT NULL,   -- did:connector:user:<email>
    user_email          TEXT        NOT NULL,
    display_name        TEXT        NOT NULL,
    legal_entity        TEXT        NOT NULL,
    jurisdiction        TEXT,                  -- ISO 3166 country code
    tax_id_hash         TEXT,                  -- SHA-256(tax_id) — never store raw
    liability_sig       TEXT        NOT NULL,  -- Ed25519(agent_did‖user_did‖timestamp)
    approval_token      TEXT,                  -- single-use, expires in 48h
    approval_token_exp  TIMESTAMPTZ,
    status              TEXT        NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending','active','revoked')),
    verified_at         TIMESTAMPTZ,
    expires_at          TIMESTAMPTZ,
    revoked_at          TIMESTAMPTZ,
    revocation_reason   TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sponsors_agent  ON ap_sponsors(agent_id);
CREATE INDEX IF NOT EXISTS idx_sponsors_email  ON ap_sponsors(user_email);
CREATE UNIQUE INDEX IF NOT EXISTS idx_sponsors_active
    ON ap_sponsors(agent_id) WHERE status = 'active';

-- ─────────────────────────────────────────────────────────────────
-- 4. VERIFIABLE CREDENTIALS  (W3C VC)
-- ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ap_credentials (
    id                  UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id            UUID        NOT NULL REFERENCES ap_agents(id) ON DELETE CASCADE,
    org_id              UUID        NOT NULL REFERENCES ap_organisations(id),
    credential_type     TEXT        NOT NULL
                            CHECK (credential_type IN (
                                'CapabilityCredential',
                                'ComplianceCredential',
                                'ProvenanceCredential',
                                'IdentityCredential',
                                'CustomCredential'
                            )),
    issuer_did          TEXT        NOT NULL,
    issuer_name         TEXT        NOT NULL,
    subject             JSONB       NOT NULL,   -- credential-specific payload
    proof_type          TEXT        NOT NULL DEFAULT 'Ed25519Signature2020',
    proof_sig           TEXT        NOT NULL,   -- Ed25519 over canonical JSON
    vc_json             JSONB       NOT NULL,   -- full W3C VC document
    issued_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMPTZ,
    revoked_at          TIMESTAMPTZ,
    revocation_reason   TEXT,
    revoked_by          TEXT
);

CREATE INDEX IF NOT EXISTS idx_creds_agent   ON ap_credentials(agent_id);
CREATE INDEX IF NOT EXISTS idx_creds_type    ON ap_credentials(credential_type);
CREATE INDEX IF NOT EXISTS idx_creds_issuer  ON ap_credentials(issuer_did);
CREATE INDEX IF NOT EXISTS idx_creds_active  ON ap_credentials(agent_id)
    WHERE revoked_at IS NULL;

-- ─────────────────────────────────────────────────────────────────
-- 5. REPUTATION EVENTS  (immutable — append only)
-- ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ap_reputation_events (
    id              UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id        UUID        NOT NULL REFERENCES ap_agents(id) ON DELETE CASCADE,
    agent_did       TEXT        NOT NULL,
    org_id          UUID        NOT NULL REFERENCES ap_organisations(id),
    event_type      TEXT        NOT NULL
                        CHECK (event_type IN (
                            'interaction_batch',
                            'minor_violation',
                            'moderate_violation',
                            'severe_violation',
                            'budget_breach',
                            'security_incident',
                            'sponsor_revocation',
                            'compliance_credential',
                            'federation_reference',
                            'sponsor_renewal',
                            'admin_override'
                        )),
    delta           NUMERIC(6,4) NOT NULL,       -- signed: negative = harm
    score_before    NUMERIC(5,4) NOT NULL,
    score_after     NUMERIC(5,4) NOT NULL,
    reason          TEXT,
    evidence_cid    TEXT,
    source_org_id   UUID,                        -- originating org (federation)
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rep_agent   ON ap_reputation_events(agent_id);
CREATE INDEX IF NOT EXISTS idx_rep_did     ON ap_reputation_events(agent_did);
CREATE INDEX IF NOT EXISTS idx_rep_type    ON ap_reputation_events(event_type);
CREATE INDEX IF NOT EXISTS idx_rep_time    ON ap_reputation_events(occurred_at DESC);

-- ─────────────────────────────────────────────────────────────────
-- 6. INCIDENTS
-- ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ap_incidents (
    id                  UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id            UUID        NOT NULL REFERENCES ap_agents(id) ON DELETE CASCADE,
    org_id              UUID        NOT NULL REFERENCES ap_organisations(id),
    incident_type       TEXT        NOT NULL,   -- policy_violation|unauthorized_access|budget_breach|security|etc
    severity            TEXT        NOT NULL DEFAULT 'medium'
                            CHECK (severity IN ('low','medium','high','critical')),
    title               TEXT        NOT NULL,
    description         TEXT        NOT NULL,
    evidence_cid        TEXT,
    auto_action         TEXT,                   -- quarantined|reputation_decremented|revoked|none
    reputation_delta    NUMERIC(6,4),
    sponsor_notified_at TIMESTAMPTZ,
    sponsor_response    TEXT,
    resolved_at         TIMESTAMPTZ,
    resolved_by         TEXT,
    resolution_note     TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_incidents_agent    ON ap_incidents(agent_id);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON ap_incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_open     ON ap_incidents(agent_id)
    WHERE resolved_at IS NULL;

-- ─────────────────────────────────────────────────────────────────
-- 7. CERTIFICATE REVOCATION LIST  (public-queryable)
-- ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ap_crl (
    id              UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    did             TEXT        NOT NULL UNIQUE,
    entity_type     TEXT        NOT NULL DEFAULT 'agent'
                        CHECK (entity_type IN ('agent','credential','sponsor')),
    revoked_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reason          TEXT,
    revoked_by      TEXT        NOT NULL,
    crl_seq         BIGSERIAL,                   -- monotonic sequence for CRL freshness
    published_hash  TEXT                         -- SHA-256 of CRL at publication time
);

CREATE INDEX IF NOT EXISTS idx_crl_did  ON ap_crl(did);
CREATE INDEX IF NOT EXISTS idx_crl_seq  ON ap_crl(crl_seq DESC);

-- ─────────────────────────────────────────────────────────────────
-- 8. VERIFICATION LOG  (immutable — append only)
-- ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ap_verification_log (
    id                      UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_did               TEXT        NOT NULL,
    verifier_id             TEXT,                -- org slug, IP, or anonymous
    verifier_ip             INET,
    required_credentials    JSONB,
    min_trust_score         NUMERIC(5,4),
    require_active_sponsor  BOOL        NOT NULL DEFAULT FALSE,
    max_violations          INT,
    result                  BOOL        NOT NULL,
    failure_reason          TEXT,
    trust_score_at_verify   NUMERIC(5,4),
    proof_sig               TEXT        NOT NULL,  -- signed by AgentPassport instance
    verified_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_verlog_did    ON ap_verification_log(agent_did);
CREATE INDEX IF NOT EXISTS idx_verlog_result ON ap_verification_log(result);
CREATE INDEX IF NOT EXISTS idx_verlog_time   ON ap_verification_log(verified_at DESC);

-- ─────────────────────────────────────────────────────────────────
-- 9. FEDERATION PEERS
-- ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ap_federation_peers (
    id              UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id          UUID        NOT NULL REFERENCES ap_organisations(id),
    peer_name       TEXT        NOT NULL,
    peer_url        TEXT        NOT NULL,
    peer_public_key TEXT,                        -- Ed25519 pubkey for verifying their exports
    trust_scope     JSONB       NOT NULL DEFAULT '{}',  -- capability/score filters
    min_trust_score NUMERIC(5,4) NOT NULL DEFAULT 0.7,
    auto_trust      BOOL        NOT NULL DEFAULT FALSE,
    status          TEXT        NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending','active','suspended')),
    last_sync_at    TIMESTAMPTZ,
    agent_count     INT         NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_fed_peers_org ON ap_federation_peers(org_id);

-- ─────────────────────────────────────────────────────────────────
-- 10. FEDERATED AGENTS  (imported from peers)
-- ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ap_federated_agents (
    id              UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id          UUID        NOT NULL REFERENCES ap_organisations(id),
    peer_id         UUID        NOT NULL REFERENCES ap_federation_peers(id) ON DELETE CASCADE,
    remote_did      TEXT        NOT NULL,
    remote_name     TEXT        NOT NULL,
    remote_passport JSONB       NOT NULL,   -- snapshot at import time
    local_trust_override NUMERIC(5,4),     -- org can override imported score
    status          TEXT        NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active','suspended','revoked')),
    imported_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_refresh_at TIMESTAMPTZ,
    UNIQUE (org_id, remote_did)
);

-- ─────────────────────────────────────────────────────────────────
-- 11. AUDIT LOG  (immutable, append-only — never UPDATE/DELETE)
-- ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ap_audit_log (
    id              UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id          UUID        REFERENCES ap_organisations(id),
    entity_type     TEXT        NOT NULL,  -- agent|sponsor|credential|incident|federation|system
    entity_id       TEXT        NOT NULL,
    action          TEXT        NOT NULL,  -- registered|activated|revoked|credential_issued|verified|etc
    actor_did       TEXT,                  -- who performed the action (user DID or system)
    actor_ip        INET,
    payload         JSONB       NOT NULL DEFAULT '{}',
    prev_cid        TEXT,                  -- CID of previous audit entry for this entity
    this_cid        TEXT,                  -- CID of this entry (SHA-256 of content)
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_entity  ON ap_audit_log(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_audit_actor   ON ap_audit_log(actor_did);
CREATE INDEX IF NOT EXISTS idx_audit_org     ON ap_audit_log(org_id);
CREATE INDEX IF NOT EXISTS idx_audit_time    ON ap_audit_log(occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_cid     ON ap_audit_log(this_cid);

-- ─────────────────────────────────────────────────────────────────
-- 12. SYSTEM KEYS  (AgentPassport signing keypair — one per instance)
-- ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ap_system_keys (
    id              UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    key_id          TEXT        NOT NULL UNIQUE,   -- kid used in proofs
    public_key      TEXT        NOT NULL,           -- hex Ed25519
    private_key_enc TEXT        NOT NULL,           -- AES-256-GCM encrypted with AP_KEY_ENC_KEY
    algorithm       TEXT        NOT NULL DEFAULT 'Ed25519',
    active          BOOL        NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rotated_at      TIMESTAMPTZ
);
