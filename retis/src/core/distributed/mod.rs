pub(crate) mod aggregator;
pub(crate) mod client;
pub(crate) mod duckdb;
pub(crate) mod flow_id;
pub(crate) mod node_id;
pub(crate) mod ntp;
pub(crate) mod protocol;

#[cfg(test)]
mod tests;

pub(crate) use aggregator::{AggregatorConfig, EventSink, LoggingEventSink, TraceAggregator};
pub(crate) use client::{DistributedCollector, DistributedCollectorConfig};
pub(crate) use duckdb::{DuckDbConfig, DuckDbEventSink};
pub(crate) use node_id::NodeIdentity;
pub(crate) use ntp::{NtpMonitor, NtpSyncStatus};
