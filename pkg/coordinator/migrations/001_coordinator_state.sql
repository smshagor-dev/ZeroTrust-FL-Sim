CREATE TABLE ztfl_coordinator_state (
    singleton_id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (singleton_id = 1),
    state_schema_version INTEGER NOT NULL CHECK (state_schema_version > 0),
    policy JSONB NOT NULL CHECK (jsonb_typeof(policy) = 'object'),
    model_proto BYTEA NOT NULL CHECK (octet_length(model_proto) > 0),
    pending_updates JSONB NOT NULL CHECK (jsonb_typeof(pending_updates) = 'array'),
    registrations JSONB NOT NULL CHECK (jsonb_typeof(registrations) = 'array'),
    replay_nonces JSONB NOT NULL CHECK (jsonb_typeof(replay_nonces) = 'array'),
    rate_windows JSONB NOT NULL CHECK (jsonb_typeof(rate_windows) = 'array'),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
