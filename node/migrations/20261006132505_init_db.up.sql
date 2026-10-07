CREATE TABLE passport_registrations (
    -- I = OPRF(p_blind, k_reg), compressed Baby Jubjub point
    identifier      BYTEA       PRIMARY KEY CHECK (octet_length(identifier) = 32),
    -- current commitment, BN254 Fr
    commitment      BYTEA       NOT NULL    CHECK (octet_length(commitment) = 32),
    registered_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
