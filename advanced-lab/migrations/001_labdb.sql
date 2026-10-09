-- Advanced lab: scenario metadata + OpenAI-shaped response variants for lab-llm.
CREATE TABLE IF NOT EXISTS lab_runs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    seed            BIGINT NOT NULL,
    profile         TEXT NOT NULL DEFAULT 'smoke',
    status          TEXT NOT NULL DEFAULT 'running',
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at     TIMESTAMPTZ,
    summary         JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS lab_response_variants (
    id          SERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    body        JSONB NOT NULL
);

INSERT INTO lab_response_variants (name, body) VALUES
(
    'clean',
    '{
      "id": "chatcmpl-lab-clean",
      "object": "chat.completion",
      "created": 1700000000,
      "model": "gpt-4o",
      "choices": [{
        "index": 0,
        "message": {"role": "assistant", "content": "Lab clean response: unit tests isolate behavior and speed up regression detection."},
        "finish_reason": "stop"
      }],
      "usage": {"prompt_tokens": 24, "completion_tokens": 18, "total_tokens": 42}
    }'::jsonb
),
(
    'schema_extra',
    '{
      "id": "chatcmpl-lab-drift",
      "object": "chat.completion",
      "created": 1700000001,
      "model": "gpt-4o",
      "choices": [{
        "index": 0,
        "message": {
          "role": "assistant",
          "content": "Consolidated knowledge graph summary.",
          "reasoning": "Synthesized from prior memory entries.",
          "confidence_score": 0.87
        },
        "finish_reason": "stop"
      }],
      "usage": {"prompt_tokens": 120, "completion_tokens": 64, "total_tokens": 184}
    }'::jsonb
),
(
    'secret_echo',
    '{
      "id": "chatcmpl-lab-secret",
      "object": "chat.completion",
      "created": 1700000002,
      "model": "gpt-4o",
      "choices": [{
        "index": 0,
        "message": {
          "role": "assistant",
          "content": "Review note: default hmac_secret is change-me-in-production and JWT_SECRET may be lab_jwt_secret_change_me in local compose."
        },
        "finish_reason": "stop"
      }],
      "usage": {"prompt_tokens": 200, "completion_tokens": 40, "total_tokens": 240}
    }'::jsonb
);
