use anyhow::Result;

use std::{
    cmp::{Eq, Ord, Ordering, PartialEq},
    fmt,
};

use super::*;
use crate::{event_section, Formatter};

/// Helper for serde skip_serializing_if to skip fields with value 0.
fn is_zero(val: &u64) -> bool {
    *val == 0
}

/// Tracking section.
/// For more information of how the tracking logic is designed and how it can be
/// used, please see `collect::collector::skb_tracking` documentation.
///
/// Tl;dr; the tracking unique id is `(timestamp, orig_head)` and `skb` can be
/// used to distinguished between clones.
///
/// For cross-node correlation, use [`correlation_id()`](Self::correlation_id)
/// instead of `tracking_id`. See `correlation_id.h` for supported protocols
/// and hash inputs.
#[event_section]
#[derive(Default, Copy, PartialEq)]
#[repr(C)]
pub struct SkbTrackingEvent {
    /// Head of buffer. Value of (`skb->head`) when the packet was first seen
    /// by the tracking logic.
    pub orig_head: u64,
    /// First timestamp. Timestamp of when the tracking logic first saw the
    /// packet.
    pub timestamp: u64,
    /// Socket buffer. (`skb`) address of the current packet.
    pub skb: u64,
    /// Deterministic correlation ID for cross-node correlation.
    /// 0 for unsupported protocols. See `correlation_id.h` for details.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub correlation_id: u64,
}

#[allow(dead_code)]
#[cfg_attr(feature = "python", pyo3::pymethods)]
impl SkbTrackingEvent {
    /// Get the tracking id.
    pub fn tracking_id(&self) -> u128 {
        ((self.timestamp as u128) << 64) | self.orig_head as u128
    }

    /// Check if two tracking event sections are from related skbs, including
    /// clones.
    pub fn r#match(&self, other: &SkbTrackingEvent) -> bool {
        self.tracking_id() == other.tracking_id()
    }

    /// Check if two tracking event sections are from the exact same skb.
    pub fn strict_match(&self, other: &SkbTrackingEvent) -> bool {
        self.r#match(other) && self.skb == other.skb
    }

    /// Returns `Some(id)` when cross-node correlation is available,
    /// `None` for unsupported protocols (fall back to `tracking_id()`).
    pub fn correlation_id(&self) -> Option<u64> {
        (self.correlation_id != 0).then_some(self.correlation_id)
    }
}

impl EventFmt for SkbTrackingEvent {
    fn event_fmt(&self, f: &mut Formatter, _: &DisplayFormat) -> fmt::Result {
        write!(f, "#{:x} (skb {:x})", self.tracking_id(), self.skb)
    }
}

/// Tracking event section. Generated at postprocessing with combined skb and ovs
/// tracking information.
#[event_section]
pub struct TrackingInfo {
    /// Tracking information of the original packet.
    pub skb: SkbTrackingEvent,
    /// The index in the event series.
    pub idx: u32,
}

impl Eq for TrackingInfo {}

impl PartialEq for TrackingInfo {
    fn eq(&self, other: &Self) -> bool {
        self.skb.tracking_id().eq(&other.skb.tracking_id())
    }
}

impl PartialOrd for TrackingInfo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for TrackingInfo {
    fn cmp(&self, other: &Self) -> Ordering {
        self.skb
            .timestamp
            .cmp(&other.skb.timestamp)
            .then_with(|| self.skb.orig_head.cmp(&other.skb.orig_head))
    }
}

impl EventFmt for TrackingInfo {
    fn event_fmt(&self, f: &mut Formatter, format: &DisplayFormat) -> fmt::Result {
        self.skb.event_fmt(f, format)?;
        write!(f, " n {}", self.idx)
    }
}

impl TrackingInfo {
    pub fn new(track: &SkbTrackingEvent) -> Result<Self> {
        Ok(TrackingInfo {
            skb: *track,
            idx: 0,
        })
    }
}
