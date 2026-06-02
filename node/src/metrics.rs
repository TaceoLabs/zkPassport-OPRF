//! Metrics definitions for the zkPassport OPRF service.
//!
//! This module defines all metrics keys used by the service and
//! provides a helper [`describe_metrics`] to set metadata for
//! each metric using the `metrics` crate.

/// Describe all metrics used by the service.
///
/// This calls the `describe_*` functions from the `metrics` crate to set metadata on the different metrics.
pub fn describe_metrics() {
    taceo_oprf::service::metrics::describe_metrics();
    oracle::describe_metrics();
}

pub(crate) mod oracle {

    /// Metrics placeholder
    const METRICS_ID_ORACLE_HEALTH: &str = "taceo.zkpassport.nullifier.oprf.health";

    pub(crate) fn describe_metrics() {
        metrics::describe_counter!(
            METRICS_ID_ORACLE_HEALTH,
            metrics::Unit::Count,
            "Placeholder metric for oracle health"
        );
    }
}
