//! DuckDB event sink.
//!
//! Uses a single-writer Appender pattern for simplicity.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use log::{debug, info, warn};

use retis_pnet::ethernet::EthernetPacket;

use super::aggregator::{EventSink, SessionInfo};
use super::flow_id::FlowId;
use super::mapping_store::MappingStore;
use super::probe::{classify_probe, ProbeDirection};
use super::protocol::{BatchStatus, EventBatch, WireDistributedMetadata};
use crate::events::{Event, OvsAction, OvsEvent};

fn opt_to_value(opt: &Option<String>) -> duckdb::types::Value {
    match opt {
        Some(s) => duckdb::types::Value::Text(s.clone()),
        None => duckdb::types::Value::Null,
    }
}

#[derive(Debug, Clone)]
pub(crate) struct DuckDbConfig {
    /// Path to the DuckDB database file. Default: `./retis.duckdb`
    pub db_path: PathBuf,
}

impl Default for DuckDbConfig {
    fn default() -> Self {
        Self {
            db_path: PathBuf::from("./retis.duckdb"),
        }
    }
}

impl DuckDbConfig {
    pub fn new(db_path: impl AsRef<Path>) -> Self {
        Self {
            db_path: db_path.as_ref().to_path_buf(),
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct DuckDbStats {
    pub events_received: u64,
    pub events_inserted: u64,
    pub events_failed: u64,
    pub batches_received: u64,
}

#[derive(Debug, Clone)]
struct EventRow {
    node_id: String,
    epoch_ns: i64,
    ntp_offset_ns: i64,
    sync_status: u8,
    session_id: u64,
    node_name: String,
    hostname: String,
    tracking_id: Option<String>,
    correlation_id: Option<String>,
    flow_id: Option<String>,
    event_type: Option<String>,
    probe_point: Option<String>,
    next_hop_node_id: Option<String>,
    event_json: String,
}

impl EventRow {
    fn from_wire_event(
        distributed: &WireDistributedMetadata,
        event_json: &str,
        session: &SessionInfo,
        mapping: &Arc<MappingStore>,
    ) -> Result<Self> {
        let event: Event = serde_json::from_str(event_json).context("parsing event JSON")?;

        let tracking_id = event
            .skb_tracking
            .as_ref()
            .map(|t| format!("{:x}", t.tracking_id()));

        let correlation_id = event
            .skb_tracking
            .as_ref()
            .and_then(|t| t.correlation_id())
            .map(|h| format!("{:016x}", h));

        let flow_id = event
            .packet
            .as_ref()
            .and_then(|p| FlowId::from_bytes(&p.data.0))
            .map(|f| f.to_string());

        let (event_type, probe_point) = event
            .kernel
            .as_ref()
            .map(|k| (Some(k.probe_type.clone()), Some(k.symbol.clone())))
            .unwrap_or((None, None));

        let node_uuid = uuid::Uuid::from_bytes(distributed.node_id);
        let node_id = node_uuid.to_string();

        // Resolve next-hop node via OVS output port action.
        let next_hop_node_id = event
            .ovs
            .as_ref()
            .and_then(|ovs| match ovs {
                OvsEvent::Action { action_execute } => match &action_execute.action {
                    Some(OvsAction::Output { output }) => Some(output.port),
                    _ => None,
                },
                _ => None,
            })
            .and_then(|port| mapping.resolve_ovs_port(node_uuid, port))
            .map(|id| id.to_string());

        // Fallback: resolve via destination MAC from raw packet bytes.
        // Only for TX probes: at TX points (dev_queue_xmit, etc.), the
        // Ethernet dst MAC is the next L2 hop's MAC. At RX points, the
        // dst MAC is the receiving node's own MAC (self-edge, not useful).
        let is_tx_probe = probe_point
            .as_ref()
            .map(|p| classify_probe(p) == ProbeDirection::Tx)
            .unwrap_or(false);

        let next_hop_node_id = if is_tx_probe {
            next_hop_node_id.or_else(|| {
                let packet = event.packet.as_ref()?;
                let eth = EthernetPacket::new(&packet.data.0)?;
                let dst_mac = eth.get_destination();
                // Skip broadcast/multicast and zero MACs. Zero MACs come
                // from synthesized Ethernet headers (skb->mac_header was
                // invalid).
                if dst_mac.is_zero() || dst_mac.is_multicast() {
                    return None;
                }
                // MacAddr::Display produces the same colon-separated
                // lowercase hex format as `ip -j link show` output.
                mapping
                    .resolve_mac(&dst_mac.to_string())
                    .map(|id| id.to_string())
            })
        } else {
            next_hop_node_id
        };

        Ok(Self {
            node_id,
            epoch_ns: distributed.epoch_ns,
            ntp_offset_ns: distributed.ntp_offset_ns,
            sync_status: distributed.sync_status,
            session_id: session.session_id,
            node_name: session.node_name.clone(),
            hostname: session.hostname.clone(),
            tracking_id,
            correlation_id,
            flow_id,
            event_type,
            probe_point,
            next_hop_node_id,
            event_json: event_json.to_string(),
        })
    }
}

pub(crate) struct DuckDbEventSink {
    connection: duckdb::Connection,
    mapping: Arc<MappingStore>,
    stats: DuckDbStats,
    pending: Vec<EventRow>,
    batch_size: usize,
}

impl DuckDbEventSink {
    /// Creates the database file and schema if they don't exist.
    ///
    /// `mapping` is shared with the aggregator's `ConnectionHandler`s, which
    /// update it as node mapping snapshots arrive. The sink reads it during
    /// `process_batch` to resolve OVS tunnel next-hop node IDs.
    pub fn new(config: DuckDbConfig, mapping: Arc<MappingStore>) -> Result<Self> {
        info!("Opening DuckDB database at {:?}", config.db_path);

        let connection =
            duckdb::Connection::open(&config.db_path).context("opening DuckDB database")?;

        Self::create_schema(&connection)?;

        Ok(Self {
            connection,
            mapping,
            stats: DuckDbStats::default(),
            pending: Vec::with_capacity(10_000),
            batch_size: 10_000,
        })
    }

    fn create_schema(conn: &duckdb::Connection) -> Result<()> {
        // UUIDs as VARCHAR for direct string equality in query filters.
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS retis_events (
                event_id VARCHAR DEFAULT (uuid()::VARCHAR),
                node_id VARCHAR NOT NULL,
                epoch_ns BIGINT NOT NULL,
                ntp_offset_ns BIGINT NOT NULL,
                sync_status TINYINT NOT NULL,
                session_id UBIGINT NOT NULL,
                node_name VARCHAR NOT NULL,
                hostname VARCHAR NOT NULL,
                tracking_id VARCHAR,
                correlation_id VARCHAR,
                flow_id VARCHAR,
                event_type VARCHAR,
                probe_point VARCHAR,
                next_hop_node_id VARCHAR,
                event_json VARCHAR NOT NULL,
                received_at TIMESTAMP DEFAULT current_timestamp
            );

            CREATE INDEX IF NOT EXISTS idx_tracking ON retis_events(tracking_id);
            CREATE INDEX IF NOT EXISTS idx_correlation ON retis_events(correlation_id);
            CREATE INDEX IF NOT EXISTS idx_epoch ON retis_events(epoch_ns);
            CREATE INDEX IF NOT EXISTS idx_node ON retis_events(node_id);
            "#,
        )
        .context("creating DuckDB schema")?;

        debug!("DuckDB schema created/verified");
        Ok(())
    }

    /// Flush pending rows to the database using an Appender.
    ///
    /// Always clears `self.pending` regardless of success or failure.
    /// On error, the events are lost rather than retried, because the
    /// Appender does not guarantee atomicity for non-constraint errors:
    /// a partial flush could persist some rows, and retrying the full
    /// batch would produce duplicates (event_id is auto-generated).
    /// Data loss is acceptable for an ephemeral debugging tool.
    fn flush_pending(&mut self) -> Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }

        let rows = std::mem::take(&mut self.pending);
        let count = rows.len();

        let result = (|| -> Result<()> {
            let mut appender = self
                .connection
                .appender("retis_events")
                .context("creating appender")?;

            for row in &rows {
                appender
                    .append_row([
                        duckdb::types::Value::Null, // event_id (auto-generated)
                        duckdb::types::Value::Text(row.node_id.clone()),
                        duckdb::types::Value::BigInt(row.epoch_ns),
                        duckdb::types::Value::BigInt(row.ntp_offset_ns),
                        duckdb::types::Value::TinyInt(row.sync_status as i8),
                        duckdb::types::Value::UBigInt(row.session_id),
                        duckdb::types::Value::Text(row.node_name.clone()),
                        duckdb::types::Value::Text(row.hostname.clone()),
                        opt_to_value(&row.tracking_id),
                        opt_to_value(&row.correlation_id),
                        opt_to_value(&row.flow_id),
                        opt_to_value(&row.event_type),
                        opt_to_value(&row.probe_point),
                        opt_to_value(&row.next_hop_node_id),
                        duckdb::types::Value::Text(row.event_json.clone()),
                        duckdb::types::Value::Null, // received_at (auto-generated)
                    ])
                    .context("appending row")?;
            }

            // Explicitly flush to catch errors (drop swallows them).
            appender.flush().context("flushing appender")?;
            Ok(())
        })();

        if result.is_ok() {
            self.stats.events_inserted += count as u64;
            debug!("Flushed {} events to DuckDB", count);
        } else {
            self.stats.events_failed += count as u64;
        }

        result
    }
}

impl EventSink for DuckDbEventSink {
    fn process_batch(&mut self, session: &SessionInfo, batch: &EventBatch) -> Result<BatchStatus> {
        self.stats.events_received += batch.events.len() as u64;
        self.stats.batches_received += 1;

        for wire_event in &batch.events {
            match EventRow::from_wire_event(
                &wire_event.distributed,
                &wire_event.event_json,
                session,
                &self.mapping,
            ) {
                Ok(row) => self.pending.push(row),
                Err(e) => {
                    debug!("EventRow conversion failed: {}", e);
                    self.stats.events_failed += 1;
                }
            }
        }

        if self.pending.len() >= self.batch_size {
            if let Err(e) = self.flush_pending() {
                warn!("Failed to flush events to DuckDB: {}", e);
            }
        }

        Ok(BatchStatus::Accepted)
    }

    fn flush(&mut self) -> Result<()> {
        self.flush_pending()
    }
}

impl Drop for DuckDbEventSink {
    fn drop(&mut self) {
        if let Err(e) = self.flush_pending() {
            warn!("Failed to flush events on shutdown: {}", e);
        }

        info!(
            "DuckDB sink stopped: received={}, inserted={}, failed={}",
            self.stats.events_received, self.stats.events_inserted, self.stats.events_failed,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::distributed::mapping_store::MappingStore;
    use std::time::Instant;
    use tempfile::TempDir;

    fn create_test_sink() -> (DuckDbEventSink, TempDir) {
        let temp_dir = TempDir::new().expect("create temp dir");
        let db_path = temp_dir.path().join("test.duckdb");
        let config = DuckDbConfig::new(&db_path);
        let sink =
            DuckDbEventSink::new(config, Arc::new(MappingStore::new())).expect("create sink");
        (sink, temp_dir)
    }

    fn create_test_session() -> SessionInfo {
        SessionInfo {
            session_id: 1,
            node_id: [0u8; 16],
            node_name: "test-node".to_string(),
            hostname: "localhost".to_string(),
            retis_version: "1.0.0".to_string(),
            connected_at: Instant::now(),
            last_heartbeat: Instant::now(),
            events_received: 0,
            batches_received: 0,
        }
    }

    #[test]
    fn creates_database_and_schema() {
        let (sink, _temp_dir) = create_test_sink();

        let count: i64 = sink
            .connection
            .query_row("SELECT COUNT(*) FROM retis_events", [], |row| row.get(0))
            .expect("query should succeed");

        assert_eq!(count, 0);
    }

    #[test]
    fn inserts_events_on_flush() {
        let (mut sink, _temp_dir) = create_test_sink();
        let session = create_test_session();

        let batch = EventBatch {
            batch_id: 1,
            events: vec![
                super::super::protocol::WireEvent {
                    distributed: WireDistributedMetadata {
                        node_id: [1u8; 16],
                        epoch_ns: 1000,
                        ntp_offset_ns: 0,
                        sync_status: 0,
                    },
                    event_json: "{}".to_string(),
                },
                super::super::protocol::WireEvent {
                    distributed: WireDistributedMetadata {
                        node_id: [1u8; 16],
                        epoch_ns: 2000,
                        ntp_offset_ns: 0,
                        sync_status: 0,
                    },
                    event_json: "{}".to_string(),
                },
            ],
        };

        let result = sink.process_batch(&session, &batch).expect("process batch");
        assert!(matches!(result, BatchStatus::Accepted));

        let count: i64 = sink
            .connection
            .query_row("SELECT COUNT(*) FROM retis_events", [], |row| row.get(0))
            .expect("query");
        assert_eq!(count, 0);

        sink.flush().expect("flush");

        let count: i64 = sink
            .connection
            .query_row("SELECT COUNT(*) FROM retis_events", [], |row| row.get(0))
            .expect("query");
        assert_eq!(count, 2);

        // Stats reflect the processed batch.
        assert_eq!(sink.stats.events_received, 2);
        assert_eq!(sink.stats.events_inserted, 2);
        assert_eq!(sink.stats.batches_received, 1);
    }

    #[test]
    fn auto_flushes_at_batch_size() {
        let (mut sink, _temp_dir) = create_test_sink();
        let session = create_test_session();

        sink.batch_size = 5;

        for i in 0..3 {
            let batch = EventBatch {
                batch_id: i,
                events: vec![
                    super::super::protocol::WireEvent {
                        distributed: WireDistributedMetadata {
                            node_id: [1u8; 16],
                            epoch_ns: i as i64 * 1000,
                            ntp_offset_ns: 0,
                            sync_status: 0,
                        },
                        event_json: "{}".to_string(),
                    },
                    super::super::protocol::WireEvent {
                        distributed: WireDistributedMetadata {
                            node_id: [1u8; 16],
                            epoch_ns: i as i64 * 1000 + 1,
                            ntp_offset_ns: 0,
                            sync_status: 0,
                        },
                        event_json: "{}".to_string(),
                    },
                ],
            };
            sink.process_batch(&session, &batch).expect("process");
        }

        // Third batch (6 events total) should have triggered flush of first 5.
        let count: i64 = sink
            .connection
            .query_row("SELECT COUNT(*) FROM retis_events", [], |row| row.get(0))
            .expect("query");
        assert!(count >= 5, "Expected at least 5 flushed, got {}", count);
    }
}
