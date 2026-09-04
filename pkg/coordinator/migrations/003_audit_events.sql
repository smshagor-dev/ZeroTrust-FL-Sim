CREATE TABLE IF NOT EXISTS ztfl_audit_events (
    sequence BIGINT PRIMARY KEY CHECK (sequence > 0),
    event_id TEXT NOT NULL UNIQUE CHECK (char_length(event_id) BETWEEN 7 AND 64),
    occurred_at TIMESTAMPTZ NOT NULL,
    event_type TEXT NOT NULL CHECK (char_length(event_type) BETWEEN 1 AND 128),
    event_payload JSONB NOT NULL,
    previous_hash BYTEA NULL,
    event_hash BYTEA NOT NULL UNIQUE,
    CHECK (previous_hash IS NULL OR octet_length(previous_hash) = 32),
    CHECK (octet_length(event_hash) = 32)
);

CREATE INDEX IF NOT EXISTS ztfl_audit_events_occurred_at_idx
    ON ztfl_audit_events (occurred_at, sequence);

CREATE INDEX IF NOT EXISTS ztfl_audit_events_type_idx
    ON ztfl_audit_events (event_type, sequence);
