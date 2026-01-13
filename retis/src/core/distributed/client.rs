//! Distributed collector client for sending events to an aggregator.
//!
//! Implements a channel-based architecture where the main thread sends events
//! through a bounded channel to a dedicated worker thread that owns the TCP
//! connection. This ensures the main event loop never blocks on network I/O.
//!
//! ```text
//! Main Thread                              Worker Thread
//!      │                                        │
//!      │  process_one(&Event)                   │
//!      │    • serialize → WireEvent             │
//!      │    • sender.try_send()  ──────────────►│ recv_timeout()
//!      │                                        │   • batch events
//!      │  (never blocks on network I/O)         │   • send when ready
//!      │                                        │
//!      │  shutdown()                            │
//!      │    • sender.send(Shutdown)  ──────────►│ drain + flush + shutdown msg
//!      │    • thread.join()  ◄──────────────────│ exit
//! ```

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use log::{debug, error, info, warn};

use super::protocol::*;
use crate::core::distributed::NodeIdentity;
use crate::events::Event;

const CHANNEL_SIZE: usize = 1000;
const INITIAL_RECONNECT_DELAY: Duration = Duration::from_millis(100);
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(30);
const RECONNECT_BACKOFF_MULTIPLIER: u32 = 2;

#[derive(Debug, Clone)]
pub struct DistributedCollectorConfig {
    pub aggregator_addr: String,
    pub batch_size: usize,
    pub flush_interval_ms: u64,
    /// Maximum events to buffer in worker when disconnected.
    pub buffer_size: usize,
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
}

impl Default for DistributedCollectorConfig {
    fn default() -> Self {
        Self {
            aggregator_addr: format!("127.0.0.1:{}", DEFAULT_PORT),
            batch_size: DEFAULT_BATCH_SIZE,
            flush_interval_ms: DEFAULT_FLUSH_INTERVAL_MS,
            buffer_size: DEFAULT_BUFFER_SIZE,
            connect_timeout: Duration::from_secs(10),
            io_timeout: Duration::from_secs(30),
        }
    }
}

enum CollectorCommand {
    Event(WireEvent),
    Shutdown,
}

struct SharedStats {
    events_captured: AtomicU64,
    events_sent: AtomicU64,
    events_dropped: AtomicU64,
    batches_sent: AtomicU64,
    bytes_sent: AtomicU64,
}

impl SharedStats {
    fn new() -> Self {
        Self {
            events_captured: AtomicU64::new(0),
            events_sent: AtomicU64::new(0),
            events_dropped: AtomicU64::new(0),
            batches_sent: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
        }
    }

    fn snapshot(&self) -> CollectorStats {
        CollectorStats {
            events_captured: self.events_captured.load(Ordering::Relaxed),
            events_sent: self.events_sent.load(Ordering::Relaxed),
            events_dropped: self.events_dropped.load(Ordering::Relaxed),
            batches_sent: self.batches_sent.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Default)]
pub struct CollectorStats {
    pub events_captured: u64,
    pub events_sent: u64,
    pub events_dropped: u64,
    pub batches_sent: u64,
    pub bytes_sent: u64,
}

struct CollectorWorker {
    config: DistributedCollectorConfig,
    identity: NodeIdentity,
    stats: Arc<SharedStats>,
    receiver: mpsc::Receiver<CollectorCommand>,

    stream: Option<TcpStream>,
    session_id: Option<u64>,
    sequence: u64,

    pending_events: Vec<WireEvent>,
    last_flush: Instant,

    buffer: VecDeque<WireEvent>,

    next_reconnect_delay: Duration,
    last_connect_attempt: Option<Instant>,
}

impl CollectorWorker {
    fn new(
        config: DistributedCollectorConfig,
        identity: NodeIdentity,
        stats: Arc<SharedStats>,
        receiver: mpsc::Receiver<CollectorCommand>,
    ) -> Self {
        Self {
            config,
            identity,
            stats,
            receiver,
            stream: None,
            session_id: None,
            sequence: 0,
            pending_events: Vec::new(),
            last_flush: Instant::now(),
            buffer: VecDeque::new(),
            next_reconnect_delay: INITIAL_RECONNECT_DELAY,
            last_connect_attempt: None,
        }
    }

    fn run(mut self) {
        let flush_interval = Duration::from_millis(self.config.flush_interval_ms);

        loop {
            match self.receiver.recv_timeout(flush_interval) {
                Ok(CollectorCommand::Event(event)) => {
                    self.handle_event(event);
                }
                Ok(CollectorCommand::Shutdown) => {
                    self.handle_shutdown();
                    break;
                }
                Err(RecvTimeoutError::Timeout) => {
                    if let Err(e) = self.flush() {
                        debug!("Periodic flush failed: {}", e);
                    }
                }
                Err(RecvTimeoutError::Disconnected) => {
                    warn!("Channel disconnected, shutting down worker");
                    self.handle_shutdown();
                    break;
                }
            }
        }
    }

    fn handle_event(&mut self, event: WireEvent) {
        self.pending_events.push(event);

        let batch_ready = self.pending_events.len() >= self.config.batch_size
            || self.last_flush.elapsed().as_millis() >= self.config.flush_interval_ms as u128;

        if batch_ready {
            if let Err(e) = self.flush() {
                warn!("Failed to flush batch: {}", e);
            }
        }
    }

    fn handle_shutdown(&mut self) {
        // Drain local buffer first (older events)
        while let Some(event) = self.buffer.pop_front() {
            self.pending_events.push(event);
        }

        // Then drain channel (newer events)
        while let Ok(cmd) = self.receiver.try_recv() {
            if let CollectorCommand::Event(event) = cmd {
                self.pending_events.push(event);
            }
        }

        if let Err(e) = self.flush() {
            warn!("Failed to flush during shutdown: {}", e);
        }

        self.send_shutdown_message();

        let stats = self.stats.snapshot();
        info!(
            "Distributed collector shutdown: {} events sent, {} dropped",
            stats.events_sent, stats.events_dropped
        );
    }

    fn send_shutdown_message(&mut self) {
        if self.stream.is_none() {
            return;
        }

        let stats = self.stats.snapshot();
        let shutdown = Shutdown {
            reason: ShutdownReason::Shutdown,
            total_events_sent: stats.events_sent,
            total_batches_sent: stats.batches_sent,
        };

        if let Err(e) = self.send_message(Payload::Shutdown(shutdown)) {
            debug!("Failed to send shutdown message: {}", e);
        }

        self.stream = None;
    }

    fn flush(&mut self) -> Result<()> {
        if self.pending_events.is_empty() {
            return Ok(());
        }

        if self.stream.is_none() {
            if !self.should_attempt_reconnect() {
                let events: Vec<_> = self.pending_events.drain(..).collect();
                for event in events {
                    self.buffer_event(event);
                }
                return Ok(());
            }

            if let Err(e) = self.connect() {
                let events: Vec<_> = self.pending_events.drain(..).collect();
                for event in events {
                    self.buffer_event(event);
                }
                return Err(e);
            }

            if !self.buffer.is_empty() {
                let mut combined =
                    Vec::with_capacity(self.buffer.len() + self.pending_events.len());
                combined.extend(self.buffer.drain(..));
                combined.append(&mut self.pending_events);
                self.pending_events = combined;
            }
        }

        // Chunk to stay within MAX_MESSAGE_SIZE (matters after reconnect
        // when the buffer may hold up to DEFAULT_BUFFER_SIZE events).
        let events = std::mem::take(&mut self.pending_events);
        let mut iter = events.into_iter();
        loop {
            let chunk: Vec<WireEvent> = iter.by_ref().take(self.config.batch_size).collect();
            if chunk.is_empty() {
                break;
            }

            let event_count = chunk.len() as u32;
            let batch = EventBatch {
                batch_id: self.stats.batches_sent.load(Ordering::Relaxed) + 1,
                event_count,
                events: chunk,
            };
            let batch_id = batch.batch_id;

            if let Err(e) = self.send_message(Payload::EventBatch(batch)) {
                warn!("Failed to send batch: {}", e);
                self.stats
                    .events_dropped
                    .fetch_add(event_count as u64, Ordering::Relaxed);
                self.handle_disconnect();
                for event in iter {
                    self.buffer_event(event);
                }
                return Err(e);
            }

            match self.recv_message() {
                Ok(response) => match response.payload {
                    Payload::BatchAck(ack) => {
                        if ack.batch_id != batch_id {
                            warn!(
                                "BatchAck mismatch: expected {}, got {}",
                                batch_id, ack.batch_id
                            );
                        }
                        match ack.status {
                            BatchStatus::Accepted => {
                                debug!("Batch {} accepted ({} events)", batch_id, event_count);
                                self.stats
                                    .events_sent
                                    .fetch_add(event_count as u64, Ordering::Relaxed);
                                self.stats.batches_sent.fetch_add(1, Ordering::Relaxed);
                            }
                            BatchStatus::Rejected(reason) => {
                                error!("Batch {} rejected: {}", batch_id, reason);
                            }
                        }
                    }
                    _ => {
                        warn!("Unexpected response: {:?}", response.payload);
                    }
                },
                Err(e) => {
                    warn!("Failed to receive BatchAck: {}", e);
                    self.handle_disconnect();
                    for event in iter {
                        self.buffer_event(event);
                    }
                    return Err(e);
                }
            }
        }

        self.last_flush = Instant::now();
        Ok(())
    }

    fn buffer_event(&mut self, event: WireEvent) {
        if self.buffer.len() >= self.config.buffer_size {
            self.buffer.pop_front();
            self.stats.events_dropped.fetch_add(1, Ordering::Relaxed);
        }
        self.buffer.push_back(event);
    }

    fn should_attempt_reconnect(&self) -> bool {
        match self.last_connect_attempt {
            None => true,
            Some(last) => last.elapsed() >= self.next_reconnect_delay,
        }
    }

    fn reset_reconnect_backoff(&mut self) {
        self.next_reconnect_delay = INITIAL_RECONNECT_DELAY;
    }

    fn increase_reconnect_backoff(&mut self) {
        self.next_reconnect_delay = std::cmp::min(
            self.next_reconnect_delay * RECONNECT_BACKOFF_MULTIPLIER,
            MAX_RECONNECT_DELAY,
        );
    }

    fn connect(&mut self) -> Result<()> {
        self.last_connect_attempt = Some(Instant::now());

        info!(
            "Connecting to aggregator at {}",
            self.config.aggregator_addr
        );

        let stream = match TcpStream::connect_timeout(
            &self
                .config
                .aggregator_addr
                .parse()
                .context("parsing aggregator address")?,
            self.config.connect_timeout,
        ) {
            Ok(s) => s,
            Err(e) => {
                self.increase_reconnect_backoff();
                warn!(
                    "Connection failed, will retry in {:?}: {}",
                    self.next_reconnect_delay, e
                );
                return Err(e.into());
            }
        };

        stream.set_read_timeout(Some(self.config.io_timeout))?;
        stream.set_write_timeout(Some(self.config.io_timeout))?;
        stream.set_nodelay(true)?;

        self.stream = Some(stream);
        self.sequence = 0;

        self.register()?;
        self.reset_reconnect_backoff();

        info!(
            "Connected to aggregator (session_id: {})",
            self.session_id
                .expect("session_id should be set after register")
        );

        Ok(())
    }

    fn register(&mut self) -> Result<()> {
        let register = Register {
            node_id: self.identity.as_bytes(),
            node_name: self.identity.display_name().to_string(),
            hostname: self.identity.hostname().to_string(),
            retis_version: option_env!("RELEASE_VERSION")
                .unwrap_or("unspec")
                .to_string(),
            kernel_version: nix::sys::utsname::uname()
                .map(|u| u.release().to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".to_string()),
            capabilities: vec![],
        };

        self.send_message(Payload::Register(register))?;

        let response = self.recv_message()?;
        match response.payload {
            Payload::RegisterAck(ack) => {
                if !ack.accepted {
                    bail!(
                        "Registration rejected: {}",
                        ack.reject_reason.unwrap_or_else(|| "unknown".to_string())
                    );
                }
                self.session_id = Some(ack.session_id);

                if let Some(recommended) = ack.recommended_batch_size {
                    if recommended as usize != self.config.batch_size {
                        debug!(
                            "Updating batch_size from {} to {} (aggregator recommendation)",
                            self.config.batch_size, recommended
                        );
                        self.config.batch_size = recommended as usize;
                    }
                }

                Ok(())
            }
            _ => bail!("Expected RegisterAck, got {:?}", response.payload),
        }
    }

    fn send_message(&mut self, payload: Payload) -> Result<()> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Not connected"))?;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as i64;

        let msg = Message::new(self.sequence, timestamp, payload);
        self.sequence += 1;

        let encoded = bincode::encode_to_vec(&msg, bincode::config::standard())
            .context("encoding message")?;

        let len = encoded.len() as u32;
        stream.write_all(&len.to_le_bytes())?;
        stream.write_all(&encoded)?;
        stream.flush()?;

        Ok(())
    }

    fn recv_message(&mut self) -> Result<Message> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Not connected"))?;

        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf)?;
        let len = u32::from_le_bytes(len_buf) as usize;

        if len > MAX_MESSAGE_SIZE {
            bail!("Message too large: {} bytes", len);
        }

        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf)?;

        let (msg, _): (Message, _) = bincode::decode_from_slice(&buf, bincode::config::standard())
            .context("decoding message")?;

        Ok(msg)
    }

    fn handle_disconnect(&mut self) {
        warn!("Disconnected from aggregator");
        self.stream = None;
        self.session_id = None;
        self.increase_reconnect_backoff();
    }
}

/// Distributed collector that sends events to an aggregator via a worker thread.
pub struct DistributedCollector {
    stats: Arc<SharedStats>,
    sender: SyncSender<CollectorCommand>,
    thread: Option<JoinHandle<()>>,
}

impl DistributedCollector {
    pub fn start(config: DistributedCollectorConfig, identity: NodeIdentity) -> Self {
        let stats = Arc::new(SharedStats::new());
        let (sender, receiver) = mpsc::sync_channel(CHANNEL_SIZE);

        let worker = CollectorWorker::new(config, identity, Arc::clone(&stats), receiver);

        let thread = thread::Builder::new()
            .name("distributed-collector".into())
            .spawn(move || worker.run())
            .expect("failed to spawn distributed collector thread");

        Self {
            stats,
            sender,
            thread: Some(thread),
        }
    }

    pub fn process_one(&mut self, event: &Event) -> Result<()> {
        self.stats.events_captured.fetch_add(1, Ordering::Relaxed);

        let distributed = match &event.distributed {
            Some(meta) => WireDistributedMetadata::from_metadata(meta),
            None => {
                warn!("Event missing distributed metadata, skipping");
                return Ok(());
            }
        };

        let event_json = serde_json::to_string(event).context("serializing event")?;

        let wire_event = WireEvent {
            distributed,
            event_json,
        };

        match self.sender.try_send(CollectorCommand::Event(wire_event)) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => {
                self.stats.events_dropped.fetch_add(1, Ordering::Relaxed);
                debug!("Channel full, dropping event");
                Ok(())
            }
            Err(TrySendError::Disconnected(_)) => {
                bail!("Worker thread disconnected")
            }
        }
    }

    pub fn shutdown(&mut self) -> Result<()> {
        if self.sender.send(CollectorCommand::Shutdown).is_err() {
            debug!("Worker already terminated");
        }

        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| anyhow::anyhow!("Worker thread panicked"))?;
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn stats(&self) -> CollectorStats {
        self.stats.snapshot()
    }
}

impl Drop for DistributedCollector {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}
