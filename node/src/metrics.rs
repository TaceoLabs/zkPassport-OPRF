//! Metrics definitions for the zkPassport OPRF service.
//!
//! This module defines all metrics keys used by the service and
//! provides a helper [`describe_metrics`] to set metadata for
//! each metric using the `metrics` crate.

macro_rules! oprf_metrics_key_zkpassport {
    ($key:expr) => {
        taceo_oprf::service::oprf_metrics_key!("zkpassport", $key)
    };
}

/// Describe all metrics used by the service.
///
/// This calls the `describe_*` functions from the `metrics` crate to set metadata on the different metrics.
pub fn describe_metrics() {
    taceo_oprf::service::metrics::describe_metrics();
    auth_module::describe_metrics();
    api::describe_metrics();
    oracle::describe_metrics();
}

pub(crate) mod auth_module {
    const METRICS_ID_AUTHENTICATION_COUNTER: &str = oprf_metrics_key_zkpassport!("auth");
    const METRICS_ATTRID_AUTH_MODULE: &str = "auth_module";
    const METRICS_ATTR_FACE_MATCH_MODULE: &str = "face_match";
    const METRICS_ATTR_REGISTER_MODULE: &str = "register";
    const METRICS_ATTR_NULLIFIER_MODULE: &str = "nullifier";

    pub(super) fn describe_metrics() {
        metrics::describe_counter!(
            METRICS_ID_AUTHENTICATION_COUNTER,
            metrics::Unit::Count,
            "Number of times the authentication modules were hit."
        );
    }

    pub(crate) fn inc_face_match() {
        metrics::counter!(METRICS_ID_AUTHENTICATION_COUNTER, METRICS_ATTRID_AUTH_MODULE => METRICS_ATTR_FACE_MATCH_MODULE).increment(1);
    }

    pub(crate) fn inc_register() {
        metrics::counter!(METRICS_ID_AUTHENTICATION_COUNTER, METRICS_ATTRID_AUTH_MODULE => METRICS_ATTR_REGISTER_MODULE).increment(1);
    }

    pub(crate) fn inc_nullifier() {
        metrics::counter!(METRICS_ID_AUTHENTICATION_COUNTER, METRICS_ATTRID_AUTH_MODULE => METRICS_ATTR_NULLIFIER_MODULE).increment(1);
    }
}

pub(crate) mod api {
    /// Metrics key for counting newly stored identifiers.
    const METRICS_ID_REGISTRATIONS: &str = oprf_metrics_key_zkpassport!("registrations");
    /// Metrics key for counting commitments that were rotated.
    const METRICS_ID_ROTATIONS: &str = oprf_metrics_key_zkpassport!("rotations");

    pub(super) fn describe_metrics() {
        metrics::describe_counter!(
            METRICS_ID_REGISTRATIONS,
            metrics::Unit::Count,
            "Number of newly registered identifiers."
        );
        metrics::describe_counter!(
            METRICS_ID_ROTATIONS,
            metrics::Unit::Count,
            "Number of rotated commitments."
        );
    }

    pub(crate) fn inc_registrations() {
        metrics::counter!(METRICS_ID_REGISTRATIONS).increment(1);
    }

    pub(crate) fn inc_rotations() {
        metrics::counter!(METRICS_ID_ROTATIONS).increment(1);
    }
}

pub(crate) mod oracle {
    use std::time::Duration;

    /// Metrics key for the duration of requests to the oracle, including retries.
    const METRICS_ID_ORACLE_DURATION: &str = oprf_metrics_key_zkpassport!("oracle.duration");
    /// Metrics key for counting retries of requests to the oracle.
    const METRICS_ID_ORACLE_RETRIES: &str = oprf_metrics_key_zkpassport!("oracle.retries");
    const METRICS_ATTRID_ENDPOINT: &str = "endpoint";
    const METRICS_ATTR_FACE_MATCH_ENDPOINT: &str = "face_match";
    const METRICS_ATTR_IDENTIFY_ENDPOINT: &str = "identify";
    const METRICS_ATTR_REGISTER_ENDPOINT: &str = "register";
    const METRICS_ATTR_QUERY_ENDPOINT: &str = "query";
    const METRICS_ATTR_ROTATE_ENDPOINT: &str = "rotate";

    pub(super) fn describe_metrics() {
        metrics::describe_histogram!(
            METRICS_ID_ORACLE_DURATION,
            metrics::Unit::Milliseconds,
            "Duration of requests to the proof-verifier oracle including retries, labelled by endpoint"
        );
        metrics::describe_counter!(
            METRICS_ID_ORACLE_RETRIES,
            metrics::Unit::Count,
            "Number of retries of requests to the proof-verifier oracle"
        );
    }

    pub(crate) fn record_face_match_duration(duration: Duration) {
        metrics::histogram!(METRICS_ID_ORACLE_DURATION, METRICS_ATTRID_ENDPOINT => METRICS_ATTR_FACE_MATCH_ENDPOINT).record(duration.as_secs_f64() * 1000.0);
    }

    pub(crate) fn record_identify_duration(duration: Duration) {
        metrics::histogram!(METRICS_ID_ORACLE_DURATION, METRICS_ATTRID_ENDPOINT => METRICS_ATTR_IDENTIFY_ENDPOINT).record(duration.as_secs_f64() * 1000.0);
    }

    pub(crate) fn record_register_duration(duration: Duration) {
        metrics::histogram!(METRICS_ID_ORACLE_DURATION, METRICS_ATTRID_ENDPOINT => METRICS_ATTR_REGISTER_ENDPOINT).record(duration.as_secs_f64() * 1000.0);
    }

    pub(crate) fn record_query_duration(duration: Duration) {
        metrics::histogram!(METRICS_ID_ORACLE_DURATION, METRICS_ATTRID_ENDPOINT => METRICS_ATTR_QUERY_ENDPOINT).record(duration.as_secs_f64() * 1000.0);
    }

    pub(crate) fn record_rotate_duration(duration: Duration) {
        metrics::histogram!(METRICS_ID_ORACLE_DURATION, METRICS_ATTRID_ENDPOINT => METRICS_ATTR_ROTATE_ENDPOINT).record(duration.as_secs_f64() * 1000.0);
    }

    pub(crate) fn inc_retries() {
        metrics::counter!(METRICS_ID_ORACLE_RETRIES).increment(1);
    }
}
