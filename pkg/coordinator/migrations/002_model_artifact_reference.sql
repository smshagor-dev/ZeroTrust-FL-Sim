ALTER TABLE ztfl_coordinator_state
    ADD COLUMN model_artifact_bucket TEXT,
    ADD COLUMN model_artifact_key TEXT,
    ADD COLUMN model_artifact_sha256 BYTEA,
    ADD COLUMN model_artifact_size_bytes BIGINT;

ALTER TABLE ztfl_coordinator_state
    ADD CONSTRAINT ztfl_model_artifact_reference_complete CHECK (
        (
            model_artifact_bucket IS NULL
            AND model_artifact_key IS NULL
            AND model_artifact_sha256 IS NULL
            AND model_artifact_size_bytes IS NULL
        )
        OR
        (
            length(model_artifact_bucket) > 0
            AND length(model_artifact_key) > 0
            AND octet_length(model_artifact_sha256) = 32
            AND model_artifact_size_bytes > 0
        )
    );
