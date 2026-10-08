CREATE TABLE passport_registrations (
    -- I = OPRF(p_blind, k_reg), uncompressed Baby Jubjub point (x, y)
    salted_identifier      BYTEA       PRIMARY KEY CHECK (octet_length(salted_identifier) = 64),
    -- current commitment, Baby Jubjub Fq (= BN254 Fr)
    commitment      BYTEA       NOT NULL    CHECK (octet_length(commitment) = 32),
    registered_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE FUNCTION set_updated_at() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER passport_registrations_set_updated_at
    BEFORE UPDATE ON passport_registrations
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
