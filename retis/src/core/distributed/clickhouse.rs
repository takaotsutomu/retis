//! ClickHouse event sink for distributed tracing.
//!
//! Stores events received from collectors into ClickHouse using the HTTP interface.
//! Uses a multi-writer thread pattern for high throughput (1-2M events/sec).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use crossbeam_channel::{self, Receiver, RecvTimeoutError, Sender, TrySendError};
use log::{debug, error, info, warn};

use super::aggregator::{
    BackpressureChange, EventSink, ProcessResult, SessionInfo, SharedBackpressure,
};
use super::protocol::{BatchStatus, EventBatch, PauseReason, WireDistributedMetadata};
use crate::events::Event;

// =============================================================================
// Configuration
// =============================================================================

#[derive(Debug, Clone)]
pub(crate) struct ClickHouseConfig {
    pub url: String,
    pub database: String,
    pub table: String,
    pub user: Option<String>,
    pub writer_count: usize,
    pub channel_size: usize,
    pub writer_batch_size: usize,
    pub flush_interval_ms: u64,
    pub auto_create_tables: bool,
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
}

impl Default for ClickHouseConfig {
    fn default() -> Self {
        Self {
            url: "http://localhost:8123".to_string(),
            database: "retis".to_string(),
            table: "retis_events".to_string(),
            user: None,
            writer_count: 4,
            channel_size: 2000,
            writer_batch_size: 50_000,
            flush_interval_ms: 100,
            auto_create_tables: true,
            connect_timeout: Duration::from_secs(10),
            io_timeout: Duration::from_secs(30),
        }
    }
}

// =============================================================================
// Statistics
// =============================================================================

pub(crate) struct ClickHouseStats {
    pub events_received: AtomicU64,
    pub events_inserted: AtomicU64,
    pub events_dropped: AtomicU64,
    pub events_failed: AtomicU64,
    pub batches_sent: AtomicU64,
    pub insert_errors: AtomicU64,
}

impl ClickHouseStats {
    fn new() -> Self {
        Self {
            events_received: AtomicU64::new(0),
            events_inserted: AtomicU64::new(0),
            events_dropped: AtomicU64::new(0),
            events_failed: AtomicU64::new(0),
            batches_sent: AtomicU64::new(0),
            insert_errors: AtomicU64::new(0),
        }
    }
}

// =============================================================================
// EventRow
// =============================================================================

#[derive(Debug, Clone)]
struct EventRow {
    node_id: String,
    epoch_ns: i64,
    ntp_offset_ns: i64,
    ntp_uncertainty_ns: u64,
    sync_status: u8,
    session_id: u64,
    node_name: String,
    hostname: String,
    tracking_id: String,
    flow_id: String,
    event_type: String,
    probe_point: String,
    event_json: String,
}

impl EventRow {
    fn from_wire_event(
        distributed: &WireDistributedMetadata,
        event_json: &str,
        session: &SessionInfo,
    ) -> Result<Self> {
        let event: Event = serde_json::from_str(event_json).context("parsing event JSON")?;

        let tracking_id = event
            .skb_tracking
            .as_ref()
            .map(|t| format!("{:x}", t.tracking_id()))
            .unwrap_or_default();

        let (event_type, probe_point) = event
            .kernel
            .as_ref()
            .map(|k| (k.probe_type.clone(), k.symbol.clone()))
            .unwrap_or_default();

        let node_id = uuid::Uuid::from_bytes(distributed.node_id).to_string();

        Ok(Self {
            node_id,
            epoch_ns: distributed.epoch_ns,
            ntp_offset_ns: distributed.ntp_offset_ns,
            ntp_uncertainty_ns: distributed.ntp_uncertainty_ns,
            sync_status: distributed.sync_status,
            session_id: session.session_id,
            node_name: session.node_name.clone(),
            hostname: session.hostname.clone(),
            tracking_id,
            flow_id: String::new(), // TODO: Extract from packet section in M3
            event_type,
            probe_point,
            event_json: event_json.to_string(),
        })
    }

    fn to_tsv(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.node_id,
            self.epoch_ns,
            self.ntp_offset_ns,
            self.ntp_uncertainty_ns,
            self.sync_status,
            self.session_id,
            escape_tsv(&self.node_name),
            escape_tsv(&self.hostname),
            escape_tsv(&self.tracking_id),
            escape_tsv(&self.flow_id),
            escape_tsv(&self.event_type),
            escape_tsv(&self.probe_point),
            escape_tsv(&self.event_json),
        )
    }
}

/// Escape special characters for ClickHouse TabSeparated format.
fn escape_tsv(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

// =============================================================================
// Writer Commands
// =============================================================================

enum WriterCommand {
    Events(Vec<EventRow>),
    Shutdown,
}

// =============================================================================
// ClickHouseWriter
// =============================================================================

struct ClickHouseWriter {
    id: usize,
    config: ClickHouseConfig,
    receiver: Receiver<WriterCommand>,
    agent: ureq::Agent,
    auth_header: Option<(String, String)>,
    pending: Vec<EventRow>,
    stats: Arc<ClickHouseStats>,
    connected: bool,
    next_retry: Instant,
    retry_delay: Duration,
}

impl ClickHouseWriter {
    fn new(
        id: usize,
        config: ClickHouseConfig,
        receiver: Receiver<WriterCommand>,
        password: Option<&str>,
        stats: Arc<ClickHouseStats>,
    ) -> Self {
        let agent = ureq::Agent::new_with_config(
            ureq::config::Config::builder()
                .timeout_connect(Some(config.connect_timeout))
                .timeout_recv_response(Some(config.io_timeout))
                .build(),
        );

        let auth_header = config.user.as_ref().map(|user| {
            let key = password.unwrap_or("");
            (user.clone(), key.to_string())
        });

        Self {
            id,
            config,
            receiver,
            agent,
            auth_header,
            pending: Vec::with_capacity(50_000),
            stats,
            connected: false,
            next_retry: Instant::now(),
            retry_delay: Duration::from_secs(1),
        }
    }

    fn run(mut self) {
        let flush_interval = Duration::from_millis(self.config.flush_interval_ms);

        debug!("ClickHouse writer {} started", self.id);

        loop {
            match self.receiver.recv_timeout(flush_interval) {
                Ok(WriterCommand::Events(rows)) => {
                    self.pending.extend(rows);
                    if self.pending.len() >= self.config.writer_batch_size {
                        self.insert_batch();
                    }
                }
                Ok(WriterCommand::Shutdown) => {
                    debug!("Writer {} received shutdown", self.id);
                    break;
                }
                Err(RecvTimeoutError::Timeout) => {
                    if !self.pending.is_empty() {
                        self.insert_batch();
                    }
                }
                Err(RecvTimeoutError::Disconnected) => {
                    debug!("Writer {} channel disconnected", self.id);
                    break;
                }
            }
        }

        if !self.pending.is_empty() {
            self.insert_batch();
        }

        debug!(
            "ClickHouse writer {} stopped, {} events still pending",
            self.id,
            self.pending.len()
        );
    }

    fn insert_batch(&mut self) {
        if self.pending.is_empty() {
            return;
        }

        if !self.connected && Instant::now() < self.next_retry {
            return;
        }

        let rows = std::mem::take(&mut self.pending);
        let count = rows.len();

        match self.do_insert(&rows) {
            Ok(()) => {
                self.stats
                    .events_inserted
                    .fetch_add(count as u64, Ordering::Relaxed);
                self.stats.batches_sent.fetch_add(1, Ordering::Relaxed);
                self.connected = true;
                self.retry_delay = Duration::from_secs(1);
                debug!("Writer {} inserted {} events", self.id, count);
            }
            Err(e) => {
                warn!("Writer {} insert failed: {}", self.id, e);
                self.stats.insert_errors.fetch_add(1, Ordering::Relaxed);
                self.stats
                    .events_failed
                    .fetch_add(count as u64, Ordering::Relaxed);
                self.connected = false;
                self.next_retry = Instant::now() + self.retry_delay;
                self.retry_delay = std::cmp::min(self.retry_delay * 2, Duration::from_secs(60));
            }
        }
    }

    fn do_insert(&self, rows: &[EventRow]) -> Result<()> {
        let columns = "node_id, epoch_ns, ntp_offset_ns, ntp_uncertainty_ns, sync_status, \
                       session_id, node_name, hostname, tracking_id, flow_id, \
                       event_type, probe_point, event_json";

        let query = format!(
            "INSERT INTO {}.{} ({}) FORMAT TabSeparated",
            self.config.database, self.config.table, columns
        );

        let url = format!("{}/?query={}", self.config.url, urlencoding::encode(&query));

        let body: String = rows
            .iter()
            .map(|r| r.to_tsv())
            .collect::<Vec<_>>()
            .join("\n");

        let mut request = self.agent.post(&url);

        if let Some((user, password)) = &self.auth_header {
            request = request.header("X-ClickHouse-User", user);
            request = request.header("X-ClickHouse-Key", password);
        }

        let mut response = request.send(&body).context("sending to ClickHouse")?;

        if response.status().as_u16() != 200 {
            let err_body = response.body_mut().read_to_string().unwrap_or_default();
            bail!("ClickHouse returned {}: {}", response.status(), err_body);
        }

        Ok(())
    }
}

// =============================================================================
// ClickHouseEventSink
// =============================================================================

pub(crate) struct ClickHouseEventSink {
    config: ClickHouseConfig,
    sender: Sender<WriterCommand>,
    writer_handles: Vec<JoinHandle<()>>,
    stats: Arc<ClickHouseStats>,
    backpressure: Arc<SharedBackpressure>,
}

impl ClickHouseEventSink {
    pub fn new(
        config: ClickHouseConfig,
        password: Option<&str>,
        backpressure: Arc<SharedBackpressure>,
    ) -> Result<Self> {
        Self::verify_connectivity(&config)?;

        let stats = Arc::new(ClickHouseStats::new());
        let (sender, receiver) = crossbeam_channel::bounded(config.channel_size);

        if config.auto_create_tables {
            Self::create_tables(&config, password)?;
        }

        let mut writer_handles = Vec::with_capacity(config.writer_count);
        for i in 0..config.writer_count {
            let writer = ClickHouseWriter::new(
                i,
                config.clone(),
                receiver.clone(),
                password,
                Arc::clone(&stats),
            );

            let handle = thread::Builder::new()
                .name(format!("clickhouse-writer-{}", i))
                .spawn(move || writer.run())
                .context("spawning writer thread")?;

            writer_handles.push(handle);
        }

        info!(
            "ClickHouse sink initialized: {} writers, channel size {}",
            config.writer_count, config.channel_size
        );

        Ok(Self {
            config,
            sender,
            writer_handles,
            stats,
            backpressure,
        })
    }

    fn create_tables(config: &ClickHouseConfig, password: Option<&str>) -> Result<()> {
        let agent = ureq::Agent::new_with_config(
            ureq::config::Config::builder()
                .timeout_connect(Some(config.connect_timeout))
                .timeout_recv_response(Some(config.io_timeout))
                .build(),
        );

        let execute = |query: &str| -> Result<()> {
            let mut request = agent.post(&config.url);

            if let Some(user) = &config.user {
                request = request.header("X-ClickHouse-User", user);
            }
            if let Some(pw) = password {
                request = request.header("X-ClickHouse-Key", pw);
            }

            let mut response = request.send(query).context("executing query")?;

            if response.status().as_u16() != 200 {
                let body = response.body_mut().read_to_string().unwrap_or_default();
                bail!("ClickHouse error: {}", body);
            }

            Ok(())
        };

        execute(&format!(
            "CREATE DATABASE IF NOT EXISTS {}",
            config.database
        ))?;

        let schema = format!(
            r#"
CREATE TABLE IF NOT EXISTS {database}.{table} (
    event_id UUID DEFAULT generateUUIDv4(),
    node_id UUID,
    epoch_ns Int64,
    ntp_offset_ns Int64,
    ntp_uncertainty_ns UInt64,
    sync_status Enum8('Synchronized' = 0, 'Degraded' = 1, 'Unsynchronized' = 2),
    session_id UInt64,
    node_name String,
    hostname String,
    tracking_id String,
    flow_id String,
    event_type String,
    probe_point String,
    event_json String,
    received_at DateTime64(9) DEFAULT now64(9)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(fromUnixTimestamp64Nano(epoch_ns))
ORDER BY (epoch_ns, node_id, tracking_id)
TTL toDateTime(fromUnixTimestamp64Nano(epoch_ns)) + INTERVAL 7 DAY
SETTINGS index_granularity = 8192
"#,
            database = config.database,
            table = config.table
        );
        execute(&schema)?;

        info!("ClickHouse tables initialized");
        Ok(())
    }

    /// Verify that ClickHouse is reachable.
    ///
    /// This provides early failure on startup if ClickHouse is misconfigured
    /// or unreachable, rather than silently failing when events arrive.
    fn verify_connectivity(config: &ClickHouseConfig) -> Result<()> {
        let agent = ureq::Agent::new_with_config(
            ureq::config::Config::builder()
                .timeout_connect(Some(config.connect_timeout))
                .timeout_recv_response(Some(config.io_timeout))
                .build(),
        );

        let ping_url = format!("{}/ping", config.url);
        let response = agent
            .get(&ping_url)
            .call()
            .context("connecting to ClickHouse")?;

        if response.status().as_u16() != 200 {
            bail!("ClickHouse ping failed with status {}", response.status());
        }

        debug!("ClickHouse connectivity verified at {}", config.url);
        Ok(())
    }

    fn channel_fill_ratio(&self) -> f64 {
        self.sender.len() as f64 / self.config.channel_size as f64
    }
}

impl EventSink for ClickHouseEventSink {
    fn process_batch(
        &mut self,
        session: &SessionInfo,
        batch: &EventBatch,
    ) -> Result<ProcessResult> {
        self.stats
            .events_received
            .fetch_add(batch.event_count as u64, Ordering::Relaxed);

        let mut rows = Vec::with_capacity(batch.events.len());
        for wire_event in &batch.events {
            match EventRow::from_wire_event(
                &wire_event.distributed,
                &wire_event.event_json,
                session,
            ) {
                Ok(row) => rows.push(row),
                Err(e) => {
                    debug!("Failed to parse event: {}", e);
                    self.stats.events_failed.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        if rows.is_empty() {
            return Ok(ProcessResult {
                status: BatchStatus::Accepted,
                backpressure_changed: None,
            });
        }

        // Hysteresis: Pause at >80%, Resume at <50%
        let fill_ratio = self.channel_fill_ratio();
        let backpressure_changed = if fill_ratio > 0.8 {
            if self
                .backpressure
                .set_paused(PauseReason::StorageBackpressure)
            {
                warn!(
                    "ClickHouse channel {}% full, pausing collectors",
                    (fill_ratio * 100.0) as u32
                );
                Some(BackpressureChange::NowPaused)
            } else {
                None
            }
        } else if fill_ratio < 0.5 && self.backpressure.is_paused() {
            if self.backpressure.set_resumed() {
                info!(
                    "ClickHouse channel {}% full, resuming collectors",
                    (fill_ratio * 100.0) as u32
                );
                Some(BackpressureChange::NowResumed)
            } else {
                None
            }
        } else {
            None
        };

        let status = match self.sender.try_send(WriterCommand::Events(rows)) {
            Ok(()) => BatchStatus::Accepted,
            Err(TrySendError::Full(WriterCommand::Events(dropped))) => {
                let count = dropped.len();
                self.stats
                    .events_dropped
                    .fetch_add(count as u64, Ordering::Relaxed);
                warn!("ClickHouse channel full, dropped {} events", count);
                BatchStatus::PartialFailure
            }
            Err(TrySendError::Full(_)) => BatchStatus::Accepted,
            Err(TrySendError::Disconnected(_)) => {
                bail!("ClickHouse writer threads died")
            }
        };

        Ok(ProcessResult {
            status,
            backpressure_changed,
        })
    }

    fn flush(&mut self) -> Result<()> {
        let start = Instant::now();
        let timeout = Duration::from_secs(5);

        while !self.sender.is_empty() && start.elapsed() < timeout {
            thread::sleep(Duration::from_millis(10));
        }

        if !self.sender.is_empty() {
            warn!(
                "ClickHouse flush timeout, {} batches still in channel",
                self.sender.len()
            );
        }

        Ok(())
    }
}

impl Drop for ClickHouseEventSink {
    fn drop(&mut self) {
        for _ in 0..self.writer_handles.len() {
            let _ = self.sender.send(WriterCommand::Shutdown);
        }

        for handle in self.writer_handles.drain(..) {
            if let Err(e) = handle.join() {
                error!("Writer thread panicked: {:?}", e);
            }
        }

        let stats = &self.stats;
        info!(
            "ClickHouse sink stopped: received={}, inserted={}, dropped={}, failed={}",
            stats.events_received.load(Ordering::Relaxed),
            stats.events_inserted.load(Ordering::Relaxed),
            stats.events_dropped.load(Ordering::Relaxed),
            stats.events_failed.load(Ordering::Relaxed),
        );
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_tsv_special_chars() {
        assert_eq!(escape_tsv("hello"), "hello");
        assert_eq!(escape_tsv("a\tb\nc\rd\\e"), "a\\tb\\nc\\rd\\\\e");
        assert_eq!(escape_tsv("{\n\"k\":\"v\"\n}"), "{\\n\"k\":\"v\"\\n}");
    }
}
