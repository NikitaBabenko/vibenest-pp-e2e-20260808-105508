-- PostgreSQL migration reference corresponding to the disposable SQLite projection.
-- Adapt it through the persistent application's ORM/migration system before multi-instance use.
CREATE TABLE project_payment_webhook_event (
    id uuid PRIMARY KEY,
    sequence bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
    destination_key text NOT NULL,
    provider_event_id text NOT NULL,
    event_type text NOT NULL,
    occurred_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    received_instance_id uuid NOT NULL,
    body_sha256 char(64) NOT NULL,
    normalized_payload jsonb NOT NULL,
    attempt_count integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_attempt_at timestamptz NULL,
    lease_id uuid NULL,
    lease_expires_at timestamptz NULL,
    processed_at timestamptz NULL,
    dead_lettered_at timestamptz NULL,
    last_error_code text NULL,
    ignored_as_stale boolean NOT NULL DEFAULT false,
    arrived_out_of_order boolean NOT NULL DEFAULT false,
    CONSTRAINT uq_project_payment_webhook_event
        UNIQUE (destination_key, provider_event_id)
);

CREATE INDEX ix_project_payment_webhook_event_due
    ON project_payment_webhook_event (next_attempt_at, sequence)
    WHERE processed_at IS NULL AND dead_lettered_at IS NULL;

CREATE INDEX ix_project_payment_webhook_event_expired_lease
    ON project_payment_webhook_event (lease_expires_at)
    WHERE processed_at IS NULL AND lease_expires_at IS NOT NULL;

CREATE TABLE project_payment_entitlement (
    id uuid PRIMARY KEY,
    subject_key text NOT NULL,
    grant_key text NOT NULL,
    source_key text NOT NULL,
    quantity integer NOT NULL CHECK (quantity > 0),
    status text NOT NULL,
    effective_from timestamptz NOT NULL,
    effective_until timestamptz NULL,
    period_starts_at timestamptz NULL,
    period_ends_at timestamptz NULL,
    source_price_key text NOT NULL,
    source_event_id text NOT NULL,
    last_occurred_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_project_payment_entitlement UNIQUE (subject_key, grant_key, source_key),
    CONSTRAINT ck_project_payment_entitlement_status
        CHECK (status IN ('active', 'scheduled_cancel', 'revoked', 'expired'))
);

CREATE INDEX ix_project_payment_entitlement_active
    ON project_payment_entitlement (subject_key, grant_key, effective_until)
    WHERE status IN ('active', 'scheduled_cancel');

CREATE TABLE project_payment_evidence (
    name text PRIMARY KEY
);

CREATE TABLE project_payment_ordering_clock (
    ordering_key text PRIMARY KEY,
    occurred_at timestamptz NOT NULL
);

-- Bounded support projections for catalog mappings, transactions, subscriptions,
-- declines, and refunds. Each value is derived only from a verified normalized event.
CREATE TABLE project_payment_projection (
    namespace text NOT NULL,
    projection_key text NOT NULL,
    value_json jsonb NOT NULL,
    PRIMARY KEY (namespace, projection_key)
);

-- The application must apply the conditional entitlement upsert and mark the
-- corresponding inbox row processed in one transaction. Recurring sources fence first
-- on the signed billing-period bounds and then on last_occurred_at; terminal events may
-- revoke immediately but an older event can never reactivate a terminal source.
