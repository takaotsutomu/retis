pub(crate) mod aggregator;
pub(crate) mod client;
pub(crate) mod duckdb;
pub(crate) mod node_id;
pub(crate) mod ntp;
pub(crate) mod protocol;

pub(crate) use aggregator::{AggregatorConfig, EventSink, LoggingEventSink, TraceAggregator};
pub(crate) use client::{DistributedCollector, DistributedCollectorConfig};
pub(crate) use duckdb::{DuckDbConfig, DuckDbEventSink};
pub(crate) use node_id::NodeIdentity;
pub(crate) use ntp::{NtpMonitor, NtpSyncStatus};
