//! Journey data structures for cross-node packet correlation.
//!
//! A "journey" represents the path of a packet (or flow) across multiple nodes
//! in a distributed system. Each journey consists of ordered "hops" where the
//! packet was observed, along with timing information and causality validation.
//!
//! The [`Journey`] struct assumes hops are ordered by timestamp. Ordering is
//! enforced by [`JourneyBuilder`](super::journey_builder) when constructing
//! journeys, not by this data structure.

use std::collections::HashSet;
use std::fmt;

use uuid::Uuid;

/// A single observation point in a packet's journey.
///
/// Each hop represents one event where a packet was captured at a specific
/// probe point on a specific node. Hops are ordered by timestamp within a
/// journey.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct JourneyHop {
    pub event_id: Uuid,
    pub node_id: Uuid,
    pub node_name: String,
    /// Wall-clock timestamp in nanoseconds since Unix epoch
    pub epoch_ns: i64,
    /// Probe point where the event was captured (e.g., "kprobe:tcp_sendmsg")
    pub probe_point: String,
    /// Type of event (e.g., "kprobe", "tracepoint")
    pub event_type: String,
    /// Flow ID (5-tuple) as observed at this hop. May differ across hops due to NAT.
    pub flow_id: String,
}

impl fmt::Display for JourneyHop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}@{} ({}ns)",
            self.probe_point, self.node_name, self.epoch_ns
        )
    }
}

/// A detected causality violation between two hops.
///
/// A causality violation occurs when hop B appears to happen before hop A
/// according to timestamps, but logically hop A should precede hop B. This
/// can happen due to:
/// - NTP clock skew
/// - Events on the same node with reversed timestamps (clock adjustment)
/// - Network delays shorter than timestamp precision
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CausalityViolation {
    /// Index of the hop that should logically come first
    pub earlier_hop_idx: usize,
    /// Index of the hop that should logically come second
    pub later_hop_idx: usize,
    /// Time difference in nanoseconds (negative means hop ordering doesn't
    /// match timestamp ordering)
    pub time_diff_ns: i64,
}

impl fmt::Display for CausalityViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "hop {} -> {} ({:+}ns)",
            self.earlier_hop_idx, self.later_hop_idx, self.time_diff_ns
        )
    }
}

/// A complete packet journey across multiple nodes.
///
/// Represents the path of a packet as it traverses the network. Contains all
/// observed hops in chronological order, along with computed statistics and
/// any detected causality violations.
///
/// # Invariants
///
/// - Hops should be ordered by `epoch_ns` (ascending). This is enforced by
///   [`JourneyBuilder`](super::journey_builder), not by this struct.
/// - Causality violations are populated by a separate validator.
#[derive(Debug, Clone)]
pub(crate) struct Journey {
    pub journey_id: Uuid,
    /// The key used to group events into this journey.
    /// - For single-node journeys: the tracking_id (SKB tracking hash)
    /// - For cross-node journeys: the correlation_id (packet content hash)
    pub journey_key: String,
    /// Ordered list of hops in the journey (should be sorted by epoch_ns)
    pub hops: Vec<JourneyHop>,
    pub start_time_ns: i64,
    pub end_time_ns: i64,
    /// Total end-to-end latency in nanoseconds.
    ///
    /// This is `None` for single-hop journeys because latency measures the time
    /// between entry and exit observations - a single observation point has no
    /// journey to measure.
    pub total_latency_ns: Option<i64>,
    /// Detected causality violations between hops (populated by CausalityValidator)
    pub causality_violations: Vec<CausalityViolation>,
}

impl Journey {
    /// Creates a new journey with an empty hop list.
    ///
    /// The journey starts with placeholder timestamps that will be updated
    /// when hops are added and [`recompute_timing`](Self::recompute_timing) is called.
    pub fn new(journey_key: String) -> Self {
        Self {
            journey_id: Uuid::new_v4(),
            journey_key,
            hops: Vec::new(),
            start_time_ns: 0,
            end_time_ns: 0,
            total_latency_ns: None,
            causality_violations: Vec::new(),
        }
    }

    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }

    pub fn is_multi_hop(&self) -> bool {
        self.hops.len() > 1
    }

    pub fn node_ids(&self) -> HashSet<Uuid> {
        self.hops.iter().map(|h| h.node_id).collect()
    }

    pub fn is_cross_node(&self) -> bool {
        self.node_ids().len() > 1
    }

    /// Recomputes timing statistics from the current hops.
    ///
    /// This should be called after modifying the hops list. Updates:
    /// - `start_time_ns` / `end_time_ns` from first/last hop
    /// - `total_latency_ns` (end - start, or `None` for single hop)
    pub fn recompute_timing(&mut self) {
        if self.hops.is_empty() {
            self.start_time_ns = 0;
            self.end_time_ns = 0;
            self.total_latency_ns = None;
            return;
        }

        self.start_time_ns = self.hops.first().expect("hops is non-empty").epoch_ns;
        self.end_time_ns = self.hops.last().expect("hops is non-empty").epoch_ns;

        self.total_latency_ns = if self.hops.len() > 1 {
            Some(self.end_time_ns.saturating_sub(self.start_time_ns))
        } else {
            None
        };
    }
}

impl fmt::Display for Journey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Journey {} ({} hops, {})",
            self.journey_id,
            self.hops.len(),
            if self.is_cross_node() {
                "cross-node"
            } else {
                "single-node"
            }
        )?;

        if let Some(latency) = self.total_latency_ns {
            write!(f, " latency={}ns", latency)?;
        }

        if !self.causality_violations.is_empty() {
            write!(
                f,
                " [{} causality violations]",
                self.causality_violations.len()
            )?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_hop(node_name: &str, epoch_ns: i64, flow_id: &str) -> JourneyHop {
        JourneyHop {
            event_id: Uuid::new_v4(),
            node_id: Uuid::new_v4(),
            node_name: node_name.to_string(),
            epoch_ns,
            probe_point: "kprobe:test".to_string(),
            event_type: "kprobe".to_string(),
            flow_id: flow_id.to_string(),
        }
    }

    fn create_hop_with_node_id(
        node_id: Uuid,
        node_name: &str,
        epoch_ns: i64,
        flow_id: &str,
    ) -> JourneyHop {
        JourneyHop {
            event_id: Uuid::new_v4(),
            node_id,
            node_name: node_name.to_string(),
            epoch_ns,
            probe_point: "kprobe:test".to_string(),
            event_type: "kprobe".to_string(),
            flow_id: flow_id.to_string(),
        }
    }

    #[test]
    fn journey_empty_timing() {
        let mut journey = Journey::new("test".to_string());
        journey.recompute_timing();

        assert_eq!(journey.start_time_ns, 0);
        assert_eq!(journey.end_time_ns, 0);
        assert_eq!(journey.total_latency_ns, None);
    }

    #[test]
    fn journey_single_hop_has_no_latency() {
        let mut journey = Journey::new("test".to_string());
        journey
            .hops
            .push(create_hop("node1", 1_000_000, "tcp:1.2.3.4:80->5.6.7.8:443"));
        journey.recompute_timing();

        assert_eq!(journey.start_time_ns, 1_000_000);
        assert_eq!(journey.end_time_ns, 1_000_000);
        assert_eq!(journey.total_latency_ns, None);
    }

    #[test]
    fn journey_multi_hop_timing() {
        let mut journey = Journey::new("test".to_string());

        journey
            .hops
            .push(create_hop("node1", 1_000_000, "tcp:1.2.3.4:80->5.6.7.8:443"));
        journey
            .hops
            .push(create_hop("node2", 1_500_000, "tcp:1.2.3.4:80->5.6.7.8:443"));
        journey
            .hops
            .push(create_hop("node3", 2_000_000, "tcp:1.2.3.4:80->5.6.7.8:443"));
        journey.recompute_timing();

        assert_eq!(journey.start_time_ns, 1_000_000);
        assert_eq!(journey.end_time_ns, 2_000_000);
        assert_eq!(journey.total_latency_ns, Some(1_000_000));
    }

    #[test]
    fn journey_cross_node_detection() {
        let node1_id = Uuid::new_v4();
        let node2_id = Uuid::new_v4();
        let flow = "tcp:1.2.3.4:80->5.6.7.8:443";

        // Single-node journey (same node_id)
        let mut single_node = Journey::new("test".to_string());
        single_node
            .hops
            .push(create_hop_with_node_id(node1_id, "node1", 1000, flow));
        single_node
            .hops
            .push(create_hop_with_node_id(node1_id, "node1", 2000, flow));
        assert!(!single_node.is_cross_node());
        assert!(single_node.is_multi_hop());

        // Cross-node journey (different node_ids)
        let mut cross_node = Journey::new("test".to_string());
        cross_node
            .hops
            .push(create_hop_with_node_id(node1_id, "node1", 1000, flow));
        cross_node
            .hops
            .push(create_hop_with_node_id(node2_id, "node2", 2000, flow));
        assert!(cross_node.is_cross_node());
    }

    #[test]
    fn journey_display_shows_type_and_latency() {
        let mut journey = Journey::new("test".to_string());

        let node1_id = Uuid::new_v4();
        let node2_id = Uuid::new_v4();
        let flow = "tcp:1.2.3.4:80->5.6.7.8:443";

        journey
            .hops
            .push(create_hop_with_node_id(node1_id, "node1", 1_000_000, flow));
        journey
            .hops
            .push(create_hop_with_node_id(node2_id, "node2", 2_000_000, flow));
        journey.recompute_timing();

        let display = journey.to_string();
        assert!(display.contains("2 hops"));
        assert!(display.contains("cross-node"));
        assert!(display.contains("latency="));
    }
}
