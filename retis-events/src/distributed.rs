//! Distributed tracing metadata for events.

use crate::event_type;

/// Clock synchronization status.
#[event_type]
#[derive(Copy, Default, Eq)]
pub enum SyncStatus {
    /// Clock is synchronized with NTP server.
    Synchronized = 0,
    /// Synchronized but with high offset.
    Degraded = 1,
    #[default]
    Unsynchronized = 2,
}

impl SyncStatus {
    pub fn is_reliable(&self) -> bool {
        matches!(self, SyncStatus::Synchronized | SyncStatus::Degraded)
    }
}

/// Distributed tracing metadata attached to events.
///
/// When retis runs in distributed mode (`--distributed`), each event
/// is enriched with this metadata to enable cross-node correlation.
#[event_type]
#[derive(Default)]
pub struct DistributedMetadata {
    /// Node identifier as UUID bytes.
    pub node_id: [u8; 16],
    /// Epoch timestamp in nanoseconds.
    pub epoch_ns: i64,
    /// NTP offset at capture time, in nanoseconds.
    /// Positive means local clock is ahead of NTP.
    pub ntp_offset_ns: i64,
    pub sync_status: SyncStatus,
}

impl DistributedMetadata {
    pub fn new(
        node_id: [u8; 16],
        epoch_ns: i64,
        ntp_offset_ns: i64,
        sync_status: SyncStatus,
    ) -> Self {
        Self {
            node_id,
            epoch_ns,
            ntp_offset_ns,
            sync_status,
        }
    }

    /// Get the node ID as a UUID string.
    pub fn node_id_string(&self) -> String {
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.node_id[0], self.node_id[1], self.node_id[2], self.node_id[3],
            self.node_id[4], self.node_id[5],
            self.node_id[6], self.node_id[7],
            self.node_id[8], self.node_id[9],
            self.node_id[10], self.node_id[11], self.node_id[12], self.node_id[13], self.node_id[14], self.node_id[15],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_status_is_reliable() {
        assert!(SyncStatus::Synchronized.is_reliable());
        assert!(SyncStatus::Degraded.is_reliable());
        assert!(!SyncStatus::Unsynchronized.is_reliable());
    }

    #[test]
    fn node_id_string() {
        let meta = DistributedMetadata {
            node_id: [
                0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
                0xde, 0xf0,
            ],
            ..Default::default()
        };

        assert_eq!(
            meta.node_id_string(),
            "12345678-9abc-def0-1234-56789abcdef0"
        );
    }

    #[test]
    fn metadata_new() {
        let node_id = [1u8; 16];
        let meta = DistributedMetadata::new(
            node_id,
            1_234_567_890_000_000_000,
            -1_000_000,
            SyncStatus::Synchronized,
        );

        assert_eq!(meta.node_id, node_id);
        assert_eq!(meta.epoch_ns, 1_234_567_890_000_000_000);
        assert_eq!(meta.ntp_offset_ns, -1_000_000);
        assert_eq!(meta.sync_status, SyncStatus::Synchronized);
    }
}
