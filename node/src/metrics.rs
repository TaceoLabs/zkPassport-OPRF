//! Metrics definitions for the zkPassport OPRF service.
//!
//! This module defines all metrics keys used by the service and
//! provides a helper [`describe_metrics`] to set metadata for
//! each metric using the `metrics` crate.

/// Internal helper for the library.
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
    oracle::describe_metrics();
}

pub(crate) mod oracle {

    /// Metrics placeholder
    const METRICS_ID_ORACLE_HEALTH: &str = oprf_metrics_key_zkpassport!("oracle.health");

    pub(crate) fn describe_metrics() {
        metrics::describe_gauge!(
            METRICS_ID_ORACLE_HEALTH,
            metrics::Unit::Count,
            "Gauge that is either 0 or 1, indicting whether the oracle is healthy"
        );
    }

    pub(crate) fn healthy() {
        metrics::gauge!(METRICS_ID_ORACLE_HEALTH).set(1.0);
    }

    pub(crate) fn sick() {
        metrics::gauge!(METRICS_ID_ORACLE_HEALTH).set(0.0);
    }
}
