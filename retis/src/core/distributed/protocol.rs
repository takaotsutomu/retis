//! Wire protocol types for distributed tracing.
//!
//! This module defines the message types used for communication between
//! collectors and the aggregator.

use bincode::{Decode, Encode};

pub const PROTOCOL_VERSION: u8 = 1;
pub const DEFAULT_PORT: u16 = 9415;
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024; // 16 MiB
pub const DEFAULT_BATCH_SIZE: usize = 1000;
pub const DEFAULT_FLUSH_INTERVAL_MS: u64 = 100;

// Default local buffer size for events buffered while disconnected.
pub const DEFAULT_BUFFER_SIZE: usize = 100_000;

#[derive(Encode, Decode, Debug, Clone)]
pub struct Message {
    pub version: u8,
    /// Sequence number (per-connection, resets on reconnect)
    pub sequence: u64,
    /// Timestamp when message was created (epoch ns)
    pub timestamp: i64,
    pub payload: Payload,
}

impl Message {
    pub fn new(sequence: u64, timestamp: i64, payload: Payload) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            sequence,
            timestamp,
            payload,
        }
    }
}

#[derive(Encode, Decode, Debug, Clone)]
pub enum Payload {
    // Collector -> Aggregator
    Register(Register),
    EventBatch(EventBatch),
    Heartbeat(Heartbeat),
    Shutdown(Shutdown),

    // Aggregator -> Collector
    RegisterAck(RegisterAck),
    BatchAck(BatchAck),
}

/// Registration message sent after TCP connection is established.
#[derive(Encode, Decode, Debug, Clone)]
pub struct Register {
    pub node_id: [u8; 16],
    /// Human-readable node name
    pub node_name: String,
    pub hostname: String,
    pub retis_version: String,
    pub kernel_version: String,
    pub capabilities: Vec<String>,
}

/// Bulk delivery of captured events.
#[derive(Encode, Decode, Debug, Clone)]
pub struct EventBatch {
    pub batch_id: u64,
    pub event_count: u32,
    pub events: Vec<WireEvent>,
}

/// Keepalive message with status information.
#[derive(Encode, Decode, Debug, Clone)]
pub struct Heartbeat {
    pub ntp_synchronized: bool,
    pub ntp_offset_ns: i64,
    /// Events captured since last heartbeat.
    pub events_captured: u64,
    pub events_dropped: u64,
}

/// Clean shutdown notification.
#[derive(Encode, Decode, Debug, Clone)]
pub struct Shutdown {
    pub reason: ShutdownReason,
    pub total_events_sent: u64,
    pub total_batches_sent: u64,
}

#[derive(Encode, Decode, Debug, Clone)]
pub enum ShutdownReason {
    /// User initiated normal shutdown
    Shutdown,
    /// Collector is restarting
    Restart,
    Error(String),
}

/// Response to Register message.
#[derive(Encode, Decode, Debug, Clone)]
pub struct RegisterAck {
    pub accepted: bool,
    pub reject_reason: Option<String>,
    /// Aggregator's assigned session ID for this connection
    pub session_id: u64,
    pub aggregator_version: String,
    pub recommended_batch_size: Option<u32>,
}

/// Acknowledgment of received EventBatch.
#[derive(Encode, Decode, Debug, Clone)]
pub struct BatchAck {
    pub batch_id: u64,
    pub status: BatchStatus,
    pub events_processed: u32,
    pub events_failed: u32,
}

/// Status of batch processing.
#[derive(Encode, Decode, Debug, Clone)]
pub enum BatchStatus {
    /// All events accepted
    Accepted,
    /// Batch rejected entirely
    Rejected(String),
}

/// Wire format for a single event.
///
/// The event itself is JSON-encoded for compatibility with existing
/// retis Event serialization.
#[derive(Encode, Decode, Debug, Clone)]
pub struct WireEvent {
    /// Distributed metadata (bincode-native for efficiency)
    pub distributed: WireDistributedMetadata,
    /// The retis event, JSON-encoded
    pub event_json: String,
}

/// Distributed metadata in wire format.
///
/// This mirrors DistributedMetadata but uses primitive types
/// for efficient bincode serialization.
#[derive(Encode, Decode, Debug, Clone)]
pub struct WireDistributedMetadata {
    pub node_id: [u8; 16],
    pub epoch_ns: i64,
    pub ntp_offset_ns: i64,
    /// 0=Synchronized, 1=Degraded, 2=Unsynchronized
    pub sync_status: u8,
}

impl WireDistributedMetadata {
    pub fn from_metadata(meta: &crate::events::DistributedMetadata) -> Self {
        Self {
            node_id: meta.node_id,
            epoch_ns: meta.epoch_ns,
            ntp_offset_ns: meta.ntp_offset_ns,
            sync_status: match meta.sync_status {
                crate::events::SyncStatus::Synchronized => 0,
                crate::events::SyncStatus::Degraded => 1,
                crate::events::SyncStatus::Unsynchronized => 2,
            },
        }
    }
}
