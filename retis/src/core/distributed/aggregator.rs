//! Trace aggregator server for distributed tracing.
//!
//! The aggregator receives events from distributed collectors over TCP,
//! processes them through an `EventSink`, and tracks session state.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use log::{debug, error, info, warn};

use super::protocol::*;

/// Configuration for the trace aggregator.
#[derive(Debug, Clone)]
pub(crate) struct AggregatorConfig {
    /// Address to listen on (default: "0.0.0.0:9415").
    pub listen_addr: String,
    /// Maximum concurrent connections (default: 100).
    pub max_connections: usize,
    /// Maximum message size in bytes (default: 16 MB).
    pub max_message_size: usize,
    /// I/O timeout for read/write operations (default: 30s).
    pub io_timeout: Duration,
}

impl Default for AggregatorConfig {
    fn default() -> Self {
        Self {
            listen_addr: format!("0.0.0.0:{}", DEFAULT_PORT),
            max_connections: 100,
            max_message_size: MAX_MESSAGE_SIZE,
            io_timeout: Duration::from_secs(30),
        }
    }
}

struct AggregatorStats {
    events_received: AtomicU64,
    batches_received: AtomicU64,
    connections_accepted: AtomicU64,
    active_connections: AtomicU64,
}

impl AggregatorStats {
    fn new() -> Self {
        Self {
            events_received: AtomicU64::new(0),
            batches_received: AtomicU64::new(0),
            connections_accepted: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
        }
    }

    fn snapshot(&self) -> AggregatorStatsSnapshot {
        AggregatorStatsSnapshot {
            events_received: self.events_received.load(Ordering::Relaxed),
            batches_received: self.batches_received.load(Ordering::Relaxed),
            connections_accepted: self.connections_accepted.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
pub(crate) struct AggregatorStatsSnapshot {
    pub events_received: u64,
    pub batches_received: u64,
    pub connections_accepted: u64,
    pub active_connections: u64,
}

/// Trait for handling received events.
///
/// Implementations can store events to ClickHouse, files, or other backends.
pub(crate) trait EventSink: Send {
    /// Process a batch of events. Returns the status to send back to the collector.
    fn process_batch(&mut self, session: &SessionInfo, batch: &EventBatch) -> Result<BatchStatus>;

    /// Flush any buffered data to storage.
    fn flush(&mut self) -> Result<()>;
}

/// Event sink that logs received events (for debugging/testing).
pub(crate) struct LoggingEventSink {
    events_processed: u64,
}

impl LoggingEventSink {
    pub fn new() -> Self {
        Self {
            events_processed: 0,
        }
    }
}

impl EventSink for LoggingEventSink {
    fn process_batch(&mut self, session: &SessionInfo, batch: &EventBatch) -> Result<BatchStatus> {
        debug!(
            "Received batch {} from {} ({} events)",
            batch.batch_id, session.node_name, batch.event_count
        );
        self.events_processed += batch.event_count as u64;
        Ok(BatchStatus::Accepted)
    }

    fn flush(&mut self) -> Result<()> {
        debug!(
            "LoggingEventSink: {} total events processed",
            self.events_processed
        );
        Ok(())
    }
}

/// Information about a connected collector session.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct SessionInfo {
    pub session_id: u64,
    pub node_id: [u8; 16],
    pub node_name: String,
    pub hostname: String,
    pub retis_version: String,
    pub connected_at: Instant,
    pub last_heartbeat: Instant,
    pub events_received: u64,
    pub batches_received: u64,
}

/// Handles a single collector connection in a dedicated thread.
struct ConnectionHandler {
    stream: TcpStream,
    session_id: u64,
    config: AggregatorConfig,
    sessions: Arc<RwLock<HashMap<u64, SessionInfo>>>,
    stats: Arc<AggregatorStats>,
    event_sink: Arc<Mutex<Box<dyn EventSink>>>,
    sequence: u64,
    registered: bool,
}

impl ConnectionHandler {
    fn new(
        stream: TcpStream,
        session_id: u64,
        config: AggregatorConfig,
        sessions: Arc<RwLock<HashMap<u64, SessionInfo>>>,
        stats: Arc<AggregatorStats>,
        event_sink: Arc<Mutex<Box<dyn EventSink>>>,
    ) -> Self {
        Self {
            stream,
            session_id,
            config,
            sessions,
            stats,
            event_sink,
            sequence: 0,
            registered: false,
        }
    }

    fn run(mut self) {
        if let Err(e) = self.stream.set_read_timeout(Some(self.config.io_timeout)) {
            warn!("Failed to set read timeout: {}", e);
        }
        if let Err(e) = self.stream.set_write_timeout(Some(self.config.io_timeout)) {
            warn!("Failed to set write timeout: {}", e);
        }
        if let Err(e) = self.stream.set_nodelay(true) {
            warn!("Failed to set TCP_NODELAY: {}", e);
        }

        loop {
            let msg = match self.recv_message() {
                Ok(msg) => msg,
                Err(e) => {
                    let err_str = e.to_string();
                    if err_str.contains("connection reset")
                        || err_str.contains("broken pipe")
                        || err_str.contains("end of file")
                        || err_str.contains("os error 104")
                    {
                        debug!("Session {} disconnected", self.session_id);
                    } else {
                        warn!("Session {} recv error: {}", self.session_id, e);
                    }
                    break;
                }
            };

            if msg.version != PROTOCOL_VERSION {
                warn!(
                    "Session {} protocol version mismatch: got {}, expected {}",
                    self.session_id, msg.version, PROTOCOL_VERSION
                );
                break;
            }

            let result = match msg.payload {
                Payload::Register(register) => self.handle_register(register),
                Payload::EventBatch(batch) => self.handle_event_batch(batch),
                Payload::Heartbeat(heartbeat) => self.handle_heartbeat(heartbeat),
                Payload::Shutdown(shutdown) => {
                    info!(
                        "Session {} shutdown: reason={:?}, events_sent={}, batches_sent={}",
                        self.session_id,
                        shutdown.reason,
                        shutdown.total_events_sent,
                        shutdown.total_batches_sent
                    );
                    break;
                }
                _ => {
                    warn!("Session {} unexpected message type", self.session_id);
                    continue;
                }
            };

            if let Err(e) = result {
                error!("Session {} handler error: {}", self.session_id, e);
                break;
            }
        }
    }

    fn handle_register(&mut self, register: Register) -> Result<()> {
        // Reject duplicate registration (defensive against buggy collectors).
        if self.registered {
            warn!("Session {} already registered", self.session_id);
            let ack = RegisterAck {
                accepted: false,
                reject_reason: Some("already registered".to_string()),
                session_id: self.session_id,
                aggregator_version: env!("CARGO_PKG_VERSION").to_string(),
                recommended_batch_size: None,
            };
            return self.send_message(Payload::RegisterAck(ack));
        }

        let session = SessionInfo {
            session_id: self.session_id,
            node_id: register.node_id,
            node_name: register.node_name.clone(),
            hostname: register.hostname.clone(),
            retis_version: register.retis_version.clone(),
            connected_at: Instant::now(),
            last_heartbeat: Instant::now(),
            events_received: 0,
            batches_received: 0,
        };

        self.sessions
            .write()
            .expect("sessions lock should not be poisoned")
            .insert(self.session_id, session);

        self.registered = true;

        info!(
            "Registered collector: {} (session {}, host: {}, retis: {})",
            register.node_name, self.session_id, register.hostname, register.retis_version
        );

        let ack = RegisterAck {
            accepted: true,
            reject_reason: None,
            session_id: self.session_id,
            aggregator_version: env!("CARGO_PKG_VERSION").to_string(),
            recommended_batch_size: None,
        };
        self.send_message(Payload::RegisterAck(ack))
    }

    fn handle_event_batch(&mut self, batch: EventBatch) -> Result<()> {
        // Reject batches from unregistered connections.
        if !self.registered {
            warn!(
                "Session {} not registered, rejecting batch",
                self.session_id
            );
            let ack = BatchAck {
                batch_id: batch.batch_id,
                status: BatchStatus::Rejected("not registered".to_string()),
                events_processed: 0,
                events_failed: batch.event_count,
            };
            return self.send_message(Payload::BatchAck(ack));
        }

        let session_info = self
            .sessions
            .read()
            .expect("sessions lock should not be poisoned")
            .get(&self.session_id)
            .cloned()
            .context("session not found")?;

        let status = self
            .event_sink
            .lock()
            .expect("event_sink lock should not be poisoned")
            .process_batch(&session_info, &batch)
            .context("processing batch")?;

        self.stats
            .events_received
            .fetch_add(batch.event_count as u64, Ordering::Relaxed);
        self.stats.batches_received.fetch_add(1, Ordering::Relaxed);

        if let Ok(mut sessions) = self.sessions.write() {
            if let Some(session) = sessions.get_mut(&self.session_id) {
                session.events_received += batch.event_count as u64;
                session.batches_received += 1;
            }
        }

        let events_processed = match &status {
            BatchStatus::Accepted => batch.event_count,
            BatchStatus::Rejected(_) => 0,
        };
        let events_failed = batch.event_count - events_processed;

        let ack = BatchAck {
            batch_id: batch.batch_id,
            status,
            events_processed,
            events_failed,
        };
        self.send_message(Payload::BatchAck(ack))
    }

    fn handle_heartbeat(&mut self, heartbeat: Heartbeat) -> Result<()> {
        debug!(
            "Session {} heartbeat: ntp_sync={}, offset={}ns, captured={}, dropped={}",
            self.session_id,
            heartbeat.ntp_synchronized,
            heartbeat.ntp_offset_ns,
            heartbeat.events_captured,
            heartbeat.events_dropped
        );

        if let Ok(mut sessions) = self.sessions.write() {
            if let Some(session) = sessions.get_mut(&self.session_id) {
                session.last_heartbeat = Instant::now();
            }
        }

        Ok(())
    }

    fn send_message(&mut self, payload: Payload) -> Result<()> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as i64;

        let msg = Message::new(self.sequence, timestamp, payload);
        self.sequence += 1;

        let encoded = bincode::encode_to_vec(&msg, bincode::config::standard())
            .context("encoding message")?;

        if encoded.len() > self.config.max_message_size {
            bail!("Message too large: {} bytes", encoded.len());
        }

        let len = encoded.len() as u32;
        self.stream
            .write_all(&len.to_le_bytes())
            .context("writing message length")?;
        self.stream
            .write_all(&encoded)
            .context("writing message body")?;
        self.stream.flush().context("flushing stream")?;

        Ok(())
    }

    fn recv_message(&mut self) -> Result<Message> {
        let mut len_buf = [0u8; 4];
        self.stream
            .read_exact(&mut len_buf)
            .context("reading message length")?;
        let len = u32::from_le_bytes(len_buf) as usize;

        if len > self.config.max_message_size {
            bail!("Message too large: {} bytes", len);
        }

        let mut buf = vec![0u8; len];
        self.stream
            .read_exact(&mut buf)
            .context("reading message body")?;

        let (msg, _): (Message, _) = bincode::decode_from_slice(&buf, bincode::config::standard())
            .context("decoding message")?;

        Ok(msg)
    }
}

impl Drop for ConnectionHandler {
    fn drop(&mut self) {
        if let Ok(mut sessions) = self.sessions.write() {
            if sessions.remove(&self.session_id).is_some() {
                info!("Session {} removed", self.session_id);
            }
        }
        self.stats
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);
    }
}

/// TCP server that receives events from distributed collectors.
pub(crate) struct TraceAggregator {
    config: AggregatorConfig,
    listener: TcpListener,
    sessions: Arc<RwLock<HashMap<u64, SessionInfo>>>,
    stats: Arc<AggregatorStats>,
    next_session_id: AtomicU64,
    running: Arc<AtomicBool>,
    event_sink: Arc<Mutex<Box<dyn EventSink>>>,
    handler_threads: Vec<JoinHandle<()>>,
}

impl TraceAggregator {
    /// Creates a new aggregator bound to the configured address.
    pub fn new(config: AggregatorConfig, event_sink: Box<dyn EventSink>) -> Result<Self> {
        let listener = TcpListener::bind(&config.listen_addr)
            .with_context(|| format!("binding to {}", config.listen_addr))?;

        listener
            .set_nonblocking(true)
            .context("setting listener to non-blocking")?;

        info!("Aggregator listening on {}", config.listen_addr);

        Ok(Self {
            config,
            listener,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(AggregatorStats::new()),
            next_session_id: AtomicU64::new(1),
            running: Arc::new(AtomicBool::new(false)),
            event_sink: Arc::new(Mutex::new(event_sink)),
            handler_threads: Vec::new(),
        })
    }

    /// Runs the aggregator accept loop. Blocks until `shutdown()` is called.
    pub fn run(&mut self) -> Result<()> {
        self.running.store(true, Ordering::SeqCst);

        info!("Aggregator started");

        while self.running.load(Ordering::SeqCst) {
            match self.listener.accept() {
                Ok((stream, addr)) => {
                    let active = self.stats.active_connections.load(Ordering::Relaxed);
                    if active >= self.config.max_connections as u64 {
                        warn!(
                            "Connection limit reached ({}/{}), rejecting {}",
                            active, self.config.max_connections, addr
                        );
                        continue;
                    }

                    let session_id = self.next_session_id.fetch_add(1, Ordering::Relaxed);

                    info!("Accepted connection from {} (session {})", addr, session_id);

                    self.stats
                        .connections_accepted
                        .fetch_add(1, Ordering::Relaxed);
                    self.stats
                        .active_connections
                        .fetch_add(1, Ordering::Relaxed);

                    let handler = ConnectionHandler::new(
                        stream,
                        session_id,
                        self.config.clone(),
                        Arc::clone(&self.sessions),
                        Arc::clone(&self.stats),
                        Arc::clone(&self.event_sink),
                    );

                    let thread = thread::Builder::new()
                        .name(format!("aggregator-session-{}", session_id))
                        .spawn(move || handler.run())
                        .expect("failed to spawn connection handler thread");

                    self.handler_threads.push(thread);
                    self.handler_threads.retain(|t| !t.is_finished());
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(e) => {
                    error!("Accept error: {}", e);
                }
            }
        }

        info!("Aggregator stopping...");

        for thread in self.handler_threads.drain(..) {
            if let Err(e) = thread.join() {
                warn!("Handler thread panicked: {:?}", e);
            }
        }

        if let Ok(mut sink) = self.event_sink.lock() {
            if let Err(e) = sink.flush() {
                error!("Failed to flush event sink: {}", e);
            }
        }

        let stats = self.stats.snapshot();
        info!(
            "Aggregator stopped: {} events received, {} batches, {} connections",
            stats.events_received, stats.batches_received, stats.connections_accepted
        );

        Ok(())
    }

    /// Signals the aggregator to stop accepting new connections.
    pub fn shutdown(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Returns a snapshot of the current statistics.
    #[allow(dead_code)]
    pub fn stats(&self) -> AggregatorStatsSnapshot {
        self.stats.snapshot()
    }

    /// Returns the number of active sessions.
    #[allow(dead_code)]
    pub fn active_sessions(&self) -> usize {
        self.sessions
            .read()
            .expect("sessions lock should not be poisoned")
            .len()
    }
}
