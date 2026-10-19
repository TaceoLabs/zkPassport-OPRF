CREATE TABLE passport_registrations (
    -- I = OPRF(p_blind, k_reg), uncompressed Baby Jubjub point (x, y)
    salted_identifier      BYTEA       PRIMARY KEY CHECK (octet_length(salted_identifier) = 64),
    -- current commitment, Baby Jubjub Fq (= BN254 Fr)
    commitment      BYTEA       NOT NULL    CHECK (octet_length(commitment) = 32),
    registered_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- every commitment ever stored for an identifier, including the current one; append-only
CREATE TABLE commitment_history (
    salted_identifier   BYTEA       NOT NULL REFERENCES passport_registrations (salted_identifier) ON DELETE CASCADE,
    commitment          BYTEA       NOT NULL CHECK (octet_length(commitment) = 32),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- a commitment can be used at most once per identifier
    PRIMARY KEY (salted_identifier, commitment)
);
