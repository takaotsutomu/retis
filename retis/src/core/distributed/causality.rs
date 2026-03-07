//! Causality validation for cross-node packet journeys.
//!
//! Validates and corrects hop ordering in cross-node journeys using probe
//! direction classification. The core insight: TX probes must come before
//! RX probes for the same packet. Within a node group, ordering relies on
//! epoch_ns.
//!
//! # Ordering Strategy
//!
//! 1. **Node-group sorting**: Classify each node's role (Source, Intermediate,
//!    Destination) based on its probe directions, then reorder groups so
//!    Source comes first, Destination last, and Intermediates are sorted by
//!    their first hop's `epoch_ns`.
//!
//! 2. **Violation detection**: After reordering, scan consecutive hops for
//!    any remaining timestamp inversions across node boundaries.
//!
//! When OVS hop edges are available, `linearize_journey_hops` uses
//! edge-based ordering instead of the epoch_ns heuristic.

use std::collections::{HashMap, HashSet};

use uuid::Uuid;

use super::journey::{CausalityViolation, Journey, JourneyHop};
use super::probe::{classify_probe, ProbeDirection};

/// A directed edge: `from_node` forwarded this packet to `to_node`.
///
/// `from_tracking_id` ties this edge to a specific transit (passage)
/// through `from_node`. Two edges from the same `from_node` but
/// different `from_tracking_id` values represent separate transits
/// (e.g., a hypervisor appearing at multiple points in a service chain).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HopEdge {
    pub from_node: Uuid,
    pub from_tracking_id: String,
    pub to_node: Uuid,
}

/// Extract directed forwarding chains from hop edges, operating on group
/// indices rather than node IDs.
fn extract_forwarding_chains(groups: &[NodeGroup], edges: &[HopEdge]) -> Vec<Vec<usize>> {
    // Map (node_id, tracking_id) -> group index for edge source resolution.
    let mut transit_to_group: HashMap<(Uuid, &str), usize> = HashMap::new();
    // Map node_id -> group indices sorted by first_epoch_ns for destination resolution.
    let mut node_groups: HashMap<Uuid, Vec<usize>> = HashMap::new();

    for (idx, group) in groups.iter().enumerate() {
        transit_to_group.insert((group.node_id, &group.tracking_id), idx);
        node_groups.entry(group.node_id).or_default().push(idx);
    }

    // Sort each node's groups by first_epoch_ns for deterministic greedy matching.
    for indices in node_groups.values_mut() {
        indices.sort_by_key(|&idx| groups[idx].first_epoch_ns);
    }

    // Build outgoing: from_group_index -> destination node_id.
    let mut outgoing: HashMap<usize, Uuid> = HashMap::new();

    for edge in edges {
        let from_idx = *transit_to_group
            .get(&(edge.from_node, edge.from_tracking_id.as_str()))
            .expect("edge source must have a corresponding group");

        // Skip edges to nodes not in this journey.
        if !node_groups.contains_key(&edge.to_node) {
            continue;
        }

        if let Some(old_to_node) = outgoing.insert(from_idx, edge.to_node) {
            log::debug!(
                "Duplicate outgoing edge from group {} (node {:?}, tracking {:?}): \
                 was {:?}, now {:?}",
                from_idx,
                groups[from_idx].node_id,
                groups[from_idx].tracking_id,
                old_to_node,
                edge.to_node,
            );
        }
    }

    let mut visited: HashSet<usize> = HashSet::new();
    let mut segments: Vec<Vec<usize>> = Vec::new();

    let mut candidates: Vec<usize> = outgoing.keys().copied().collect();
    candidates.sort_unstable();

    for &start in &candidates {
        if visited.contains(&start) {
            continue;
        }

        let mut chain = vec![start];
        let mut current = start;

        while let Some(&dest_node) = outgoing.get(&current) {
            // Pick the first unvisited group at the destination node
            // (earliest `first_epoch_ns`). The greedy heuristic can
            // theoretically pick a terminal transit over one with
            // outgoing edges when a node has multiple transits. In
            // practice this is unreachable: a terminal transit (no TX
            // probe captured) classifies as Destination (RX-only),
            // creating 2+ Destinations, which causes
            // `linearize_journey_hops` to return `None` and fall back
            // to epoch_ns ordering.
            let next_idx = node_groups
                .get(&dest_node)
                .and_then(|indices| indices.iter().copied().find(|&idx| !visited.contains(&idx)));

            match next_idx {
                Some(idx) => {
                    chain.push(idx);
                    current = idx;
                }
                None => break,
            }
        }

        if chain.len() > 1 {
            for &idx in &chain {
                visited.insert(idx);
            }
            segments.push(chain);
        }
    }

    segments
}

/// Logical role of a node in a journey, inferred from its probe directions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NodeRole {
    /// Node has only TX probes. Packet originates here.
    Source,
    /// Node has both TX and RX probes. Packet passes through.
    Intermediate,
    /// Node has only RX probes. Packet terminates here.
    Destination,
    /// Cannot determine role (all probes are Unknown, or contradictory).
    Ambiguous,
}

/// Classify a node's role based on the probe directions of its hops.
pub(crate) fn classify_node_role(probe_points: &[&str]) -> NodeRole {
    let mut has_tx = false;
    let mut has_rx = false;

    for probe_point in probe_points {
        match classify_probe(probe_point) {
            ProbeDirection::Tx => has_tx = true,
            ProbeDirection::Rx => has_rx = true,
            ProbeDirection::Unknown => {}
        }
    }

    match (has_tx, has_rx) {
        (true, false) => NodeRole::Source,
        (false, true) => NodeRole::Destination,
        (true, true) => NodeRole::Intermediate,
        (false, false) => NodeRole::Ambiguous,
    }
}

/// A group of hops belonging to one transit through a node.
///
/// A transit is one passage of a packet through a node, identified by
/// `(node_id, tracking_id)`. `node_id` is **not** unique across groups
/// when node re-entry occurs (e.g., a hypervisor appearing at multiple
/// points in a service chain).
#[derive(Debug)]
struct NodeGroup {
    node_id: Uuid,
    /// Kernel SKB tracking hash identifying this transit. Empty when
    /// `skb_tracking` collector is not enabled, in which case all hops
    /// at a node collapse to one group.
    tracking_id: String,
    role: NodeRole,
    /// Indices into the journey's hop list (before reordering).
    hop_indices: Vec<usize>,
    /// Earliest epoch_ns among this transit's hops, NTP-corrected
    /// (`epoch_ns - ntp_offset_ns`) for cross-node comparison.
    /// Positive offset means the local clock was ahead; subtracting
    /// approximates true wall-clock time.
    first_epoch_ns: i64,
}

/// Enforces causality for a cross-node journey.
///
/// For single-node journeys (all hops on one node), this is a no-op since
/// intra-node ordering is handled by epoch_ns from the database's ORDER BY.
///
/// For cross-node journeys, performs three phases:
/// 1. **Classify**: Build node groups, infer each node's role (Source,
///    Intermediate, Destination) from its probe directions.
/// 2. **Reorder** node groups: Source -> Intermediates -> Destination.
///    Uses OVS hop edges when available, epoch_ns heuristic otherwise.
/// 3. **Detect** remaining timestamp inversions between consecutive
///    cross-node hops.
pub(crate) fn enforce_causality(journey: &mut Journey, edges: &[HopEdge]) {
    journey.causality_violations.clear();

    // Single-node journeys don't need cross-node causality validation.
    if !journey.is_cross_node() {
        return;
    }

    // Phase 1: Build node groups and classify roles
    let groups = build_node_groups(&journey.hops);

    // Phase 2: Compute the corrected hop ordering.
    // If OVS edges are available, try edge-based linearization.
    // Fall back to epoch_ns heuristic if linearization fails.
    let reordered_indices = if !edges.is_empty() {
        linearize_journey_hops(&groups, edges).unwrap_or_else(|| compute_reordered_indices(&groups))
    } else {
        compute_reordered_indices(&groups)
    };

    // Check if reordering actually changed anything
    let was_reordered = reordered_indices
        .iter()
        .enumerate()
        .any(|(pos, &orig)| pos != orig);

    if was_reordered {
        // Apply the reordering to the hop list
        let original_hops = journey.hops.clone();
        for (new_pos, &orig_idx) in reordered_indices.iter().enumerate() {
            journey.hops[new_pos] = original_hops[orig_idx].clone();
        }
        journey.recompute_timing();
    }

    // Phase 3: Detect remaining causality violations (timestamp inversions
    // between consecutive hops on different nodes).
    detect_cross_node_violations(journey, was_reordered);
}

/// Build node groups from a journey's hops, grouped by `(node_id, tracking_id)`.
///
/// Each transit (one passage through a node) gets its own group. When
/// `tracking_id` is empty (no `skb_tracking` collector), all hops at a
/// node collapse to key `(node_id, "")`.
fn build_node_groups(hops: &[JourneyHop]) -> Vec<NodeGroup> {
    // Preserve insertion order for deterministic output.
    let mut key_order: Vec<(Uuid, String)> = Vec::new();
    let mut groups_map: HashMap<(Uuid, String), Vec<usize>> = HashMap::new();

    for (idx, hop) in hops.iter().enumerate() {
        let key = (hop.node_id, hop.tracking_id.clone());
        if !groups_map.contains_key(&key) {
            key_order.push(key.clone());
        }
        groups_map.entry(key).or_default().push(idx);
    }

    key_order
        .into_iter()
        .map(|(node_id, tracking_id)| {
            let hop_indices = groups_map
                .remove(&(node_id, tracking_id.clone()))
                .expect("key was inserted");
            let probe_points: Vec<&str> = hop_indices
                .iter()
                .map(|&i| hops[i].probe_point.as_str())
                .collect();
            let role = classify_node_role(&probe_points);
            // NTP-corrected earliest timestamp for cross-node comparison.
            let first_epoch_ns = hop_indices
                .iter()
                .map(|&i| hops[i].epoch_ns - hops[i].ntp_offset_ns)
                .min()
                .expect("group is non-empty");

            NodeGroup {
                node_id,
                tracking_id,
                role,
                hop_indices,
                first_epoch_ns,
            }
        })
        .collect()
}

/// Compute the reordered hop indices based on node-group sorting.
///
/// Ordering: Source groups first, then Intermediates sorted by first_epoch_ns,
/// then Destination groups last. Ambiguous groups sort with Intermediates.
/// Within each group, hops retain their original relative order.
fn compute_reordered_indices(groups: &[NodeGroup]) -> Vec<usize> {
    let mut sources: Vec<&NodeGroup> = Vec::new();
    let mut intermediates: Vec<&NodeGroup> = Vec::new();
    let mut destinations: Vec<&NodeGroup> = Vec::new();

    for group in groups {
        match group.role {
            NodeRole::Source => sources.push(group),
            NodeRole::Intermediate => intermediates.push(group),
            NodeRole::Destination => destinations.push(group),
            NodeRole::Ambiguous => intermediates.push(group),
        }
    }

    let mut result = Vec::new();

    // Source groups first (if multiple sources, sort by first_epoch_ns)
    sources.sort_by_key(|g| g.first_epoch_ns);
    for group in &sources {
        result.extend_from_slice(&group.hop_indices);
    }

    // Intermediates in epoch_ns order
    intermediates.sort_by_key(|g| g.first_epoch_ns);
    for group in &intermediates {
        result.extend_from_slice(&group.hop_indices);
    }

    // Destination groups last (if multiple destinations, sort by first_epoch_ns)
    destinations.sort_by_key(|g| g.first_epoch_ns);
    for group in &destinations {
        result.extend_from_slice(&group.hop_indices);
    }

    result
}

/// Compute reordered hop indices using OVS hop edges for intermediate ordering.
///
/// Uses forwarding chains (returned as group indices by
/// `extract_forwarding_chains`) as rigid blocks that maintain their
/// internal order. Remaining intermediates (not in any chain) are
/// interleaved around rigid blocks by `first_epoch_ns`.
///
/// Returns `None` if the journey doesn't have exactly one Source and one
/// Destination.
fn linearize_journey_hops(groups: &[NodeGroup], edges: &[HopEdge]) -> Option<Vec<usize>> {
    // Require exactly 1 Source and 1 Destination (by group index).
    let source_indices: Vec<usize> = groups
        .iter()
        .enumerate()
        .filter(|(_, g)| g.role == NodeRole::Source)
        .map(|(i, _)| i)
        .collect();
    let dest_indices: Vec<usize> = groups
        .iter()
        .enumerate()
        .filter(|(_, g)| g.role == NodeRole::Destination)
        .map(|(i, _)| i)
        .collect();

    if source_indices.len() != 1 || dest_indices.len() != 1 {
        return None;
    }

    let source_idx = source_indices[0];
    let dest_idx = dest_indices[0];

    let segments = extract_forwarding_chains(groups, edges);

    // Build sortable items: rigid blocks (from segments) + single remaining
    // groups. Each item has a sort key (first_epoch_ns) and hop indices.
    // Rigid blocks are atomic units; remaining intermediates go AROUND
    // blocks, never inside them.
    struct HopBlock {
        sort_key: i64,
        hop_indices: Vec<usize>,
    }

    let mut items: Vec<HopBlock> = Vec::new();

    // Add segments as rigid blocks.
    for seg in &segments {
        let filtered: Vec<usize> = seg
            .iter()
            .copied()
            // Exclude Source/Dest from the segment body, they're
            // positioned by role, not by segment membership.
            .filter(|&idx| idx != source_idx && idx != dest_idx)
            .collect();

        if filtered.is_empty() {
            continue;
        }

        let sort_key = groups[filtered[0]].first_epoch_ns;
        let hop_indices: Vec<usize> = filtered
            .iter()
            .flat_map(|&idx| groups[idx].hop_indices.iter())
            .copied()
            .collect();

        items.push(HopBlock {
            sort_key,
            hop_indices,
        });
    }

    let segment_groups: HashSet<usize> = segments.iter().flat_map(|s| s.iter()).copied().collect();
    for (idx, group) in groups.iter().enumerate() {
        if idx == source_idx || idx == dest_idx || segment_groups.contains(&idx) {
            continue;
        }

        items.push(HopBlock {
            sort_key: group.first_epoch_ns,
            hop_indices: group.hop_indices.clone(),
        });
    }

    items.sort_by_key(|item| item.sort_key);

    // Assemble: Source -> sorted items -> Destination.
    let mut result = Vec::new();
    result.extend_from_slice(&groups[source_idx].hop_indices);
    for item in &items {
        result.extend_from_slice(&item.hop_indices);
    }
    result.extend_from_slice(&groups[dest_idx].hop_indices);

    Some(result)
}

/// Detect causality violations between consecutive cross-node hops.
///
/// A violation is reported when hop[i+1].epoch_ns < hop[i].epoch_ns and
/// the two hops are on different nodes (cross-node timestamp inversion).
///
/// Compares raw `epoch_ns` (not NTP-corrected) because violations are
/// user-facing diagnostics: the user sees raw timestamps in hop data.
/// NTP correction is only used in `build_node_groups` for ordering
/// decisions, not for violation reporting.
fn detect_cross_node_violations(journey: &mut Journey, was_reordered: bool) {
    for i in 0..journey.hops.len().saturating_sub(1) {
        let current = &journey.hops[i];
        let next = &journey.hops[i + 1];

        // Only flag cross-node inversions.
        if current.node_id == next.node_id {
            continue;
        }

        let time_diff = next.epoch_ns - current.epoch_ns;
        if time_diff < 0 {
            journey.causality_violations.push(CausalityViolation {
                earlier_hop_idx: i,
                later_hop_idx: i + 1,
                time_diff_ns: time_diff,
                reordered: was_reordered,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_hop(node_id: Uuid, node_name: &str, epoch_ns: i64, probe_point: &str) -> JourneyHop {
        JourneyHop {
            event_id: Uuid::new_v4(),
            node_id,
            node_name: node_name.to_string(),
            tracking_id: String::new(),
            ntp_offset_ns: 0,
            epoch_ns,
            probe_point: probe_point.to_string(),
            event_type: "kprobe".to_string(),
            flow_id: "tcp:10.0.0.1:1234->10.0.0.2:80".to_string(),
        }
    }

    fn create_journey(hops: Vec<JourneyHop>) -> Journey {
        let mut j = Journey::new("test-key".to_string());
        j.hops = hops;
        j.recompute_timing();
        j
    }

    // Fixed node IDs for readable tests.
    fn node_a() -> Uuid {
        Uuid::from_bytes([0xAA; 16])
    }
    fn node_b() -> Uuid {
        Uuid::from_bytes([0xBB; 16])
    }
    fn node_c() -> Uuid {
        Uuid::from_bytes([0xCC; 16])
    }
    fn node_d() -> Uuid {
        Uuid::from_bytes([0xDD; 16])
    }
    fn node_e() -> Uuid {
        Uuid::from_bytes([0xEE; 16])
    }
    fn node_f() -> Uuid {
        Uuid::from_bytes([0xFF; 16])
    }

    #[test]
    fn classify_node_role_by_probe_direction() {
        // TX-only -> Source
        assert_eq!(
            classify_node_role(&["kprobe:tcp_sendmsg", "kprobe:ip_output"]),
            NodeRole::Source,
        );

        // RX-only -> Destination
        assert_eq!(
            classify_node_role(&["kprobe:ip_rcv", "kprobe:tcp_v4_rcv"]),
            NodeRole::Destination,
        );

        // Both directions -> Intermediate
        assert_eq!(
            classify_node_role(&["kprobe:netif_receive_skb", "kprobe:dev_queue_xmit"]),
            NodeRole::Intermediate,
        );

        // Unknown probes only -> Ambiguous
        assert_eq!(
            classify_node_role(&["kprobe:some_internal_func"]),
            NodeRole::Ambiguous,
        );
    }

    #[test]
    fn single_node_journey_not_reordered() {
        let mut journey = create_journey(vec![
            create_hop(node_a(), "node", 1000, "kprobe:ip_rcv"),
            create_hop(node_a(), "node", 2000, "kprobe:tcp_v4_rcv"),
        ]);
        enforce_causality(&mut journey, &[]);

        assert!(journey.causality_violations.is_empty());
        assert_eq!(journey.hops[0].epoch_ns, 1000);
        assert_eq!(journey.hops[1].epoch_ns, 2000);
    }

    #[test]
    fn two_node_correct_order_no_violations() {
        // TX@A (1000ns) -> RX@B (2000ns), already correct
        let mut journey = create_journey(vec![
            create_hop(node_a(), "src", 1000, "kprobe:tcp_sendmsg"),
            create_hop(node_b(), "dst", 2000, "kprobe:tcp_v4_rcv"),
        ]);
        enforce_causality(&mut journey, &[]);

        assert!(journey.causality_violations.is_empty());
        assert_eq!(journey.hops[0].node_id, node_a());
        assert_eq!(journey.hops[1].node_id, node_b());
    }

    #[test]
    fn two_node_reversed_timestamps_reordered() {
        // RX@B appears first (epoch 1000), TX@A second (epoch 2000). Wrong
        // order from database. Validator should reorder: TX@A first.
        let mut journey = create_journey(vec![
            create_hop(node_b(), "dst", 1000, "kprobe:tcp_v4_rcv"),
            create_hop(node_a(), "src", 2000, "kprobe:tcp_sendmsg"),
        ]);
        enforce_causality(&mut journey, &[]);

        // Source should be first after reordering
        assert_eq!(journey.hops[0].node_id, node_a());
        assert_eq!(journey.hops[1].node_id, node_b());

        // There's a timestamp inversion (src epoch 2000 > dst epoch 1000)
        // which is flagged as a corrected violation.
        assert_eq!(journey.causality_violations.len(), 1);
        assert!(journey.causality_violations[0].reordered);
        assert!(journey.causality_violations[0].time_diff_ns < 0);
    }

    #[test]
    fn two_node_clock_skew_detected() {
        // TX@A (5000ns) -> RX@B (3000ns), correct logical order, but
        // destination timestamp is earlier (clock skew). The validator keeps
        // the order (Source before Destination) but flags the inversion.
        let mut journey = create_journey(vec![
            create_hop(node_a(), "src", 5000, "kprobe:tcp_sendmsg"),
            create_hop(node_b(), "dst", 3000, "kprobe:tcp_v4_rcv"),
        ]);
        enforce_causality(&mut journey, &[]);

        assert_eq!(journey.hops[0].node_id, node_a());
        assert_eq!(journey.hops[1].node_id, node_b());
        assert_eq!(journey.causality_violations.len(), 1);
        assert_eq!(journey.causality_violations[0].time_diff_ns, -2000);
    }

    #[test]
    fn three_node_correct_order() {
        let mut journey = create_journey(vec![
            create_hop(node_a(), "src", 1000, "kprobe:tcp_sendmsg"),
            create_hop(node_b(), "mid", 2000, "kprobe:netif_receive_skb"),
            create_hop(node_b(), "mid", 2100, "kprobe:dev_queue_xmit"),
            create_hop(node_c(), "dst", 3000, "kprobe:tcp_v4_rcv"),
        ]);
        enforce_causality(&mut journey, &[]);

        assert!(journey.causality_violations.is_empty());
        assert_eq!(journey.hops[0].node_id, node_a());
        assert_eq!(journey.hops[1].node_id, node_b());
        assert_eq!(journey.hops[2].node_id, node_b());
        assert_eq!(journey.hops[3].node_id, node_c());
    }

    #[test]
    fn three_node_misordered_destination_reordered() {
        // Database returned: src(1000) -> dst(1500) -> mid(2000)
        // Logical order should be: src -> mid -> dst
        let mut journey = create_journey(vec![
            create_hop(node_a(), "src", 1000, "kprobe:tcp_sendmsg"),
            create_hop(node_c(), "dst", 1500, "kprobe:tcp_v4_rcv"),
            create_hop(node_b(), "mid", 2000, "kprobe:netif_receive_skb"),
            create_hop(node_b(), "mid", 2100, "kprobe:dev_queue_xmit"),
        ]);
        enforce_causality(&mut journey, &[]);

        // After reordering: src -> mid -> mid -> dst
        assert_eq!(journey.hops[0].node_id, node_a());
        assert_eq!(journey.hops[1].node_id, node_b());
        assert_eq!(journey.hops[2].node_id, node_b());
        assert_eq!(journey.hops[3].node_id, node_c());
    }

    #[test]
    fn four_node_intermediates_sorted_by_epoch() {
        // Two intermediates with mid_b earlier than mid_c.
        // Database gives them in wrong order: src -> mid_c -> mid_b -> dst.
        let mut journey = create_journey(vec![
            create_hop(node_a(), "src", 1000, "kprobe:tcp_sendmsg"),
            create_hop(node_c(), "mid_c", 3000, "kprobe:netif_receive_skb"),
            create_hop(node_c(), "mid_c", 3100, "kprobe:dev_queue_xmit"),
            create_hop(node_b(), "mid_b", 2000, "kprobe:netif_receive_skb"),
            create_hop(node_b(), "mid_b", 2100, "kprobe:dev_queue_xmit"),
            create_hop(node_d(), "dst", 4000, "kprobe:tcp_v4_rcv"),
        ]);
        enforce_causality(&mut journey, &[]);

        // After reordering: src -> mid_b (epoch 2000) -> mid_c (epoch 3000) -> dst
        assert_eq!(journey.hops[0].node_id, node_a());
        assert_eq!(journey.hops[1].node_id, node_b());
        assert_eq!(journey.hops[2].node_id, node_b());
        assert_eq!(journey.hops[3].node_id, node_c());
        assert_eq!(journey.hops[4].node_id, node_c());
        assert_eq!(journey.hops[5].node_id, node_d());
        assert!(journey.causality_violations.is_empty());
    }

    #[test]
    fn ambiguous_nodes_sorted_as_intermediates() {
        // All probes are unknown, so nodes become Ambiguous, treated as
        // Intermediates and sorted by epoch_ns.
        let mut journey = create_journey(vec![
            create_hop(node_b(), "b", 2000, "kprobe:unknown_func"),
            create_hop(node_a(), "a", 1000, "kprobe:unknown_func"),
        ]);
        enforce_causality(&mut journey, &[]);

        // Both are Ambiguous -> sorted as intermediates by epoch_ns.
        // node_a (epoch 1000) comes first.
        assert_eq!(journey.hops[0].node_id, node_a());
        assert_eq!(journey.hops[1].node_id, node_b());
    }

    #[test]
    fn degenerate_input_no_crash() {
        // Empty journey
        let mut journey = create_journey(vec![]);
        enforce_causality(&mut journey, &[]);
        assert!(journey.causality_violations.is_empty());

        // Single hop
        let mut journey = create_journey(vec![create_hop(
            node_a(),
            "src",
            1000,
            "kprobe:tcp_sendmsg",
        )]);
        enforce_causality(&mut journey, &[]);
        assert!(journey.causality_violations.is_empty());
    }

    #[test]
    fn already_correct_order_not_modified() {
        let mut journey = create_journey(vec![
            create_hop(node_a(), "src", 1000, "kprobe:tcp_sendmsg"),
            create_hop(node_a(), "src", 1100, "kprobe:ip_output"),
            create_hop(node_b(), "dst", 2000, "kprobe:ip_rcv"),
            create_hop(node_b(), "dst", 2100, "kprobe:tcp_v4_rcv"),
        ]);

        let original_order: Vec<i64> = journey.hops.iter().map(|h| h.epoch_ns).collect();
        enforce_causality(&mut journey, &[]);
        let new_order: Vec<i64> = journey.hops.iter().map(|h| h.epoch_ns).collect();

        assert_eq!(original_order, new_order);
        assert!(journey.causality_violations.is_empty());
    }

    #[test]
    fn intra_group_order_preserved_after_reordering() {
        // Destination appears before Source in DB order, forcing actual
        // reordering. After reordering, hops within each group must keep
        // their relative epoch_ns order.
        let mut journey = create_journey(vec![
            create_hop(node_b(), "dst", 3000, "kprobe:ip_rcv"),
            create_hop(node_b(), "dst", 3100, "kprobe:tcp_v4_rcv"),
            create_hop(node_a(), "src", 1000, "kprobe:tcp_sendmsg"),
            create_hop(node_a(), "src", 1100, "kprobe:ip_output"),
            create_hop(node_a(), "src", 1200, "kprobe:dev_queue_xmit"),
        ]);
        enforce_causality(&mut journey, &[]);

        // Source group comes first after reordering.
        assert_eq!(journey.hops[0].epoch_ns, 1000);
        assert_eq!(journey.hops[1].epoch_ns, 1100);
        assert_eq!(journey.hops[2].epoch_ns, 1200);
        // Destination group preserves its internal order.
        assert_eq!(journey.hops[3].epoch_ns, 3000);
        assert_eq!(journey.hops[4].epoch_ns, 3100);
    }

    #[test]
    fn three_node_edge_based_ordering() {
        // Edges A->B, B->C override misleading timestamps.
        // DB order by epoch_ns: A(1000), C(2000), B(3000). Wrong.
        // Edges tell us the correct order is A->B->C.
        let mut journey = create_journey(vec![
            create_hop(node_a(), "src", 1000, "kprobe:tcp_sendmsg"),
            create_hop(node_c(), "dst", 2000, "kprobe:tcp_v4_rcv"),
            create_hop(node_b(), "mid", 3000, "kprobe:netif_receive_skb"),
            create_hop(node_b(), "mid", 3100, "kprobe:dev_queue_xmit"),
        ]);

        let edges = vec![
            HopEdge {
                from_node: node_a(),
                from_tracking_id: String::new(),
                to_node: node_b(),
            },
            HopEdge {
                from_node: node_b(),
                from_tracking_id: String::new(),
                to_node: node_c(),
            },
        ];

        enforce_causality(&mut journey, &edges);

        assert_eq!(journey.hops[0].node_id, node_a());
        assert_eq!(journey.hops[1].node_id, node_b());
        assert_eq!(journey.hops[2].node_id, node_b());
        assert_eq!(journey.hops[3].node_id, node_c());
    }

    #[test]
    fn edges_override_intermediate_epoch() {
        // 4-node journey where epoch_ns gives wrong intermediate order
        // but edges give the correct chain.
        // Edges: A->C, C->B, B->D (correct order: A->C->B->D)
        // Epoch order of intermediates: B(2000) < C(3000). Wrong.
        let mut journey = create_journey(vec![
            create_hop(node_a(), "src", 1000, "kprobe:tcp_sendmsg"),
            create_hop(node_b(), "mid_b", 2000, "kprobe:netif_receive_skb"),
            create_hop(node_b(), "mid_b", 2100, "kprobe:dev_queue_xmit"),
            create_hop(node_c(), "mid_c", 3000, "kprobe:netif_receive_skb"),
            create_hop(node_c(), "mid_c", 3100, "kprobe:dev_queue_xmit"),
            create_hop(node_d(), "dst", 4000, "kprobe:tcp_v4_rcv"),
        ]);

        let edges = vec![
            HopEdge {
                from_node: node_a(),
                from_tracking_id: String::new(),
                to_node: node_c(),
            },
            HopEdge {
                from_node: node_c(),
                from_tracking_id: String::new(),
                to_node: node_b(),
            },
            HopEdge {
                from_node: node_b(),
                from_tracking_id: String::new(),
                to_node: node_d(),
            },
        ];

        enforce_causality(&mut journey, &edges);

        // Edge chain wins over epoch_ns: A -> C -> B -> D
        assert_eq!(journey.hops[0].node_id, node_a());
        assert_eq!(journey.hops[1].node_id, node_c());
        assert_eq!(journey.hops[2].node_id, node_c());
        assert_eq!(journey.hops[3].node_id, node_b());
        assert_eq!(journey.hops[4].node_id, node_b());
        assert_eq!(journey.hops[5].node_id, node_d());
    }

    #[test]
    fn unchained_intermediate_interleaved() {
        // Edge A->C creates a rigid block [A, C]. B is an intermediate
        // not in any edge, placed by epoch_ns. B(1500) < C(2000), so
        // B goes before the rigid block containing C.
        // Result: A -> B -> C -> D
        let mut journey = create_journey(vec![
            create_hop(node_a(), "src", 1000, "kprobe:tcp_sendmsg"),
            create_hop(node_c(), "mid_c", 2000, "kprobe:netif_receive_skb"),
            create_hop(node_c(), "mid_c", 2100, "kprobe:dev_queue_xmit"),
            create_hop(node_b(), "mid_b", 1500, "kprobe:netif_receive_skb"),
            create_hop(node_b(), "mid_b", 1600, "kprobe:dev_queue_xmit"),
            create_hop(node_d(), "dst", 3000, "kprobe:tcp_v4_rcv"),
        ]);

        let edges = vec![HopEdge {
            from_node: node_a(),
            from_tracking_id: String::new(),
            to_node: node_c(),
        }];

        enforce_causality(&mut journey, &edges);

        // B(epoch 1500) sorts before the rigid block [C](epoch 2000).
        // Source A is anchored first, Destination D is anchored last.
        assert_eq!(journey.hops[0].node_id, node_a());
        assert_eq!(journey.hops[1].node_id, node_b());
        assert_eq!(journey.hops[2].node_id, node_b());
        assert_eq!(journey.hops[3].node_id, node_c());
        assert_eq!(journey.hops[4].node_id, node_c());
        assert_eq!(journey.hops[5].node_id, node_d());
    }

    #[test]
    fn non_unique_anchors_fall_back_to_epoch() {
        // linearize_journey_hops requires exactly 1 Source and 1
        // Destination. When either anchor is non-unique, edges are
        // ignored and we fall back to epoch_ns ordering.

        // Multiple sources
        {
            let mut journey = create_journey(vec![
                create_hop(node_a(), "src1", 1000, "kprobe:tcp_sendmsg"),
                create_hop(node_b(), "src2", 2000, "kprobe:ip_output"),
                create_hop(node_c(), "dst", 3000, "kprobe:tcp_v4_rcv"),
            ]);

            let edges = vec![HopEdge {
                from_node: node_a(),
                from_tracking_id: String::new(),
                to_node: node_b(),
            }];

            enforce_causality(&mut journey, &edges);

            assert_eq!(journey.hops[0].node_id, node_a());
            assert_eq!(journey.hops[1].node_id, node_b());
            assert_eq!(journey.hops[2].node_id, node_c());
        }

        // Multiple destinations
        {
            let mut journey = create_journey(vec![
                create_hop(node_a(), "src", 1000, "kprobe:tcp_sendmsg"),
                create_hop(node_b(), "dst1", 2000, "kprobe:ip_rcv"),
                create_hop(node_c(), "dst2", 3000, "kprobe:tcp_v4_rcv"),
            ]);

            let edges = vec![HopEdge {
                from_node: node_a(),
                from_tracking_id: String::new(),
                to_node: node_b(),
            }];

            enforce_causality(&mut journey, &edges);

            assert_eq!(journey.hops[0].node_id, node_a());
            assert_eq!(journey.hops[1].node_id, node_b());
            assert_eq!(journey.hops[2].node_id, node_c());
        }
    }

    #[test]
    fn disjoint_edge_segments_both_used() {
        // Two disjoint edge segments: A->B and D->E in a 6-node journey.
        // C is a standalone intermediate placed by epoch_ns between them.
        // A(src), B(mid), C(mid), D(mid), E(mid), F(dst)
        // Edges: A->B (segment 1), D->E (segment 2)
        // Epoch_ns: A=1000, B=2000, C=2500, D=3000, E=4000, F=5000
        let mut journey = create_journey(vec![
            create_hop(node_a(), "src", 1000, "kprobe:tcp_sendmsg"),
            create_hop(node_b(), "mid_b", 2000, "kprobe:netif_receive_skb"),
            create_hop(node_b(), "mid_b", 2100, "kprobe:dev_queue_xmit"),
            create_hop(node_c(), "mid_c", 2500, "kprobe:netif_receive_skb"),
            create_hop(node_c(), "mid_c", 2600, "kprobe:dev_queue_xmit"),
            create_hop(node_d(), "mid_d", 3000, "kprobe:netif_receive_skb"),
            create_hop(node_d(), "mid_d", 3100, "kprobe:dev_queue_xmit"),
            create_hop(node_e(), "mid_e", 4000, "kprobe:netif_receive_skb"),
            create_hop(node_e(), "mid_e", 4100, "kprobe:dev_queue_xmit"),
            create_hop(node_f(), "dst", 5000, "kprobe:tcp_v4_rcv"),
        ]);

        let edges = vec![
            HopEdge {
                from_node: node_a(),
                from_tracking_id: String::new(),
                to_node: node_b(),
            },
            HopEdge {
                from_node: node_d(),
                from_tracking_id: String::new(),
                to_node: node_e(),
            },
        ];

        enforce_causality(&mut journey, &edges);

        // Segment 1 [B] (sort_key=2000), C (sort_key=2500),
        // Segment 2 [D,E] (sort_key=3000).
        // Result: A -> B -> C -> D -> E -> F
        assert_eq!(journey.hops[0].node_id, node_a());
        assert_eq!(journey.hops[1].node_id, node_b());
        assert_eq!(journey.hops[2].node_id, node_b());
        assert_eq!(journey.hops[3].node_id, node_c());
        assert_eq!(journey.hops[4].node_id, node_c());
        assert_eq!(journey.hops[5].node_id, node_d());
        assert_eq!(journey.hops[6].node_id, node_d());
        assert_eq!(journey.hops[7].node_id, node_e());
        assert_eq!(journey.hops[8].node_id, node_e());
        assert_eq!(journey.hops[9].node_id, node_f());
    }

    #[test]
    fn node_reentry_ordering() {
        // Service-chain topology: VM1 -> Hyp -> VM2(fw) -> Hyp -> VM3
        // The hypervisor (node_b) appears at two points in the journey,
        // each with a different tracking_id (different SKB allocation).
        let hyp = node_b();
        let vm1 = node_a();
        let vm2 = node_c();
        let vm3 = node_d();

        // build_node_groups splits re-entries into separate groups
        // (same node_id, different tracking_id -> 2 groups)
        {
            let mut hop_t1_rx = create_hop(hyp, "hyp", 2000, "kprobe:netif_receive_skb");
            hop_t1_rx.tracking_id = "track-t1".to_string();
            let mut hop_t1_tx = create_hop(hyp, "hyp", 2100, "kprobe:dev_queue_xmit");
            hop_t1_tx.tracking_id = "track-t1".to_string();
            let mut hop_t3_rx = create_hop(hyp, "hyp", 4000, "kprobe:netif_receive_skb");
            hop_t3_rx.tracking_id = "track-t3".to_string();
            let mut hop_t3_tx = create_hop(hyp, "hyp", 4100, "kprobe:dev_queue_xmit");
            hop_t3_tx.tracking_id = "track-t3".to_string();

            let groups = build_node_groups(&[hop_t1_rx, hop_t1_tx, hop_t3_rx, hop_t3_tx]);

            assert_eq!(groups.len(), 2, "two transits -> two groups");
            assert_eq!(groups[0].node_id, hyp);
            assert_eq!(groups[1].node_id, hyp);
            assert_eq!(groups[0].tracking_id, "track-t1");
            assert_eq!(groups[1].tracking_id, "track-t3");
            assert_eq!(groups[0].hop_indices, vec![0, 1]);
            assert_eq!(groups[1].hop_indices, vec![2, 3]);
        }

        // Canonical service-chain: correct epoch order, no edges.
        // VM1->Hyp(t1)->VM2->Hyp(t3)->VM3
        {
            let mut hops = vec![
                create_hop(vm1, "vm1", 1000, "kprobe:tcp_sendmsg"),
                create_hop(hyp, "hyp", 2000, "kprobe:netif_receive_skb"),
                create_hop(hyp, "hyp", 2100, "kprobe:dev_queue_xmit"),
                create_hop(vm2, "vm2", 3000, "kprobe:netif_receive_skb"),
                create_hop(vm2, "vm2", 3100, "kprobe:dev_queue_xmit"),
                create_hop(hyp, "hyp", 4000, "kprobe:netif_receive_skb"),
                create_hop(hyp, "hyp", 4100, "kprobe:dev_queue_xmit"),
                create_hop(vm3, "vm3", 5000, "kprobe:tcp_v4_rcv"),
            ];
            hops[1].tracking_id = "track-t1".to_string();
            hops[2].tracking_id = "track-t1".to_string();
            hops[5].tracking_id = "track-t3".to_string();
            hops[6].tracking_id = "track-t3".to_string();

            let mut journey = create_journey(hops);
            enforce_causality(&mut journey, &[]);

            let node_order: Vec<Uuid> = journey.hops.iter().map(|h| h.node_id).collect();
            assert_eq!(node_order, vec![vm1, hyp, hyp, vm2, vm2, hyp, hyp, vm3]);
            assert!(journey.causality_violations.is_empty());
        }

        // Epoch_ns fallback with wrong initial order. Database delivers
        // Hyp(t3) before VM2, but first_epoch_ns sorting interleaves
        // correctly.
        {
            let mut hops = vec![
                create_hop(vm1, "vm1", 1000, "kprobe:tcp_sendmsg"),
                create_hop(hyp, "hyp", 2000, "kprobe:netif_receive_skb"),
                create_hop(hyp, "hyp", 2100, "kprobe:dev_queue_xmit"),
                // Hyp(t3) appears before VM2 in the input
                create_hop(hyp, "hyp", 4000, "kprobe:netif_receive_skb"),
                create_hop(hyp, "hyp", 4100, "kprobe:dev_queue_xmit"),
                create_hop(vm2, "vm2", 3000, "kprobe:netif_receive_skb"),
                create_hop(vm2, "vm2", 3100, "kprobe:dev_queue_xmit"),
                create_hop(vm3, "vm3", 5000, "kprobe:tcp_v4_rcv"),
            ];
            hops[1].tracking_id = "track-t1".to_string();
            hops[2].tracking_id = "track-t1".to_string();
            hops[3].tracking_id = "track-t3".to_string();
            hops[4].tracking_id = "track-t3".to_string();

            let mut journey = create_journey(hops);
            enforce_causality(&mut journey, &[]);

            // Intermediates are sorted by first_epoch_ns:
            // Hyp(t1)=2000, VM2=3000, Hyp(t3)=4000
            let node_order: Vec<Uuid> = journey.hops.iter().map(|h| h.node_id).collect();
            assert_eq!(node_order, vec![vm1, hyp, hyp, vm2, vm2, hyp, hyp, vm3]);
        }

        // Edge-based ordering. Edges Hyp(t1)->VM2, VM2->Hyp, Hyp(t3)->VM3
        // produce correct chain via greedy matching.
        {
            let mut hops = vec![
                create_hop(vm1, "vm1", 1000, "kprobe:tcp_sendmsg"),
                create_hop(hyp, "hyp", 2000, "kprobe:netif_receive_skb"),
                create_hop(hyp, "hyp", 2100, "kprobe:dev_queue_xmit"),
                create_hop(vm2, "vm2", 3000, "kprobe:netif_receive_skb"),
                create_hop(vm2, "vm2", 3100, "kprobe:dev_queue_xmit"),
                create_hop(hyp, "hyp", 4000, "kprobe:netif_receive_skb"),
                create_hop(hyp, "hyp", 4100, "kprobe:dev_queue_xmit"),
                create_hop(vm3, "vm3", 5000, "kprobe:tcp_v4_rcv"),
            ];
            hops[1].tracking_id = "track-t1".to_string();
            hops[2].tracking_id = "track-t1".to_string();
            hops[5].tracking_id = "track-t3".to_string();
            hops[6].tracking_id = "track-t3".to_string();

            let edges = vec![
                HopEdge {
                    from_node: hyp,
                    from_tracking_id: "track-t1".to_string(),
                    to_node: vm2,
                },
                HopEdge {
                    from_node: vm2,
                    from_tracking_id: String::new(),
                    to_node: vm3,
                },
                HopEdge {
                    from_node: hyp,
                    from_tracking_id: "track-t3".to_string(),
                    to_node: vm3,
                },
            ];

            let mut journey = create_journey(hops);
            enforce_causality(&mut journey, &edges);

            let node_order: Vec<Uuid> = journey.hops.iter().map(|h| h.node_id).collect();
            assert_eq!(node_order, vec![vm1, hyp, hyp, vm2, vm2, hyp, hyp, vm3]);
        }
    }

    #[test]
    fn reentry_dual_edges_preserved() {
        // Two outgoing edges from the same node_id (different transits)
        // must both be preserved in forwarding chains. Keying the outgoing
        // map by group index (not bare node_id) is what makes this work.
        let hyp = node_b();
        let vm1 = node_a();
        let vm2 = node_c();
        let vm4 = node_e();

        let mut hops = vec![
            create_hop(vm1, "vm1", 1000, "kprobe:tcp_sendmsg"),
            create_hop(hyp, "hyp", 2000, "kprobe:netif_receive_skb"),
            create_hop(hyp, "hyp", 2100, "kprobe:dev_queue_xmit"),
            create_hop(vm2, "vm2", 3000, "kprobe:netif_receive_skb"),
            create_hop(vm2, "vm2", 3100, "kprobe:dev_queue_xmit"),
            create_hop(hyp, "hyp", 4000, "kprobe:netif_receive_skb"),
            create_hop(hyp, "hyp", 4100, "kprobe:dev_queue_xmit"),
            create_hop(vm4, "vm4", 5000, "kprobe:tcp_v4_rcv"),
        ];
        hops[1].tracking_id = "track-t1".to_string();
        hops[2].tracking_id = "track-t1".to_string();
        hops[5].tracking_id = "track-t2".to_string();
        hops[6].tracking_id = "track-t2".to_string();

        let edges = vec![
            HopEdge {
                from_node: hyp,
                from_tracking_id: "track-t1".to_string(),
                to_node: vm2,
            },
            HopEdge {
                from_node: hyp,
                from_tracking_id: "track-t2".to_string(),
                to_node: vm4,
            },
        ];

        let groups = build_node_groups(&hops);
        let segments = extract_forwarding_chains(&groups, &edges);

        let edge_count: usize = segments.iter().map(|s| s.len() - 1).sum();
        assert_eq!(
            edge_count, 2,
            "both Hyp->VM2 and Hyp->VM4 edges must be preserved"
        );
    }

    #[test]
    fn reentry_source_distinct_from_intermediate() {
        // Source and intermediate sharing the same node_id are
        // distinguished by group index, not node_id. The Source transit
        // (TX only) and the Intermediate transit (RX+TX) must both appear
        // in the final ordering.
        let hyp = node_b();
        let vm2 = node_c();
        let vm3 = node_d();

        let mut hops = vec![
            // Hyp transit 1: TX only -> Source role
            create_hop(hyp, "hyp", 1000, "kprobe:dev_queue_xmit"),
            // VM2: RX+TX -> Intermediate
            create_hop(vm2, "vm2", 2000, "kprobe:netif_receive_skb"),
            create_hop(vm2, "vm2", 2100, "kprobe:dev_queue_xmit"),
            // Hyp transit 2: RX+TX -> Intermediate
            create_hop(hyp, "hyp", 3000, "kprobe:netif_receive_skb"),
            create_hop(hyp, "hyp", 3100, "kprobe:dev_queue_xmit"),
            // VM3: RX only -> Destination
            create_hop(vm3, "vm3", 4000, "kprobe:tcp_v4_rcv"),
        ];
        hops[0].tracking_id = "track-s1".to_string();
        hops[3].tracking_id = "track-s2".to_string();
        hops[4].tracking_id = "track-s2".to_string();

        // Edge from Source transit forces the `linearize_journey_hops` path,
        // where filtering by group index (not node_id) is critical.
        let edges = vec![HopEdge {
            from_node: hyp,
            from_tracking_id: "track-s1".to_string(),
            to_node: vm2,
        }];

        let mut journey = create_journey(hops);
        enforce_causality(&mut journey, &edges);

        // Hyp(t1) is Source, Hyp(t2) is Intermediate. Both must appear.
        let node_order: Vec<Uuid> = journey.hops.iter().map(|h| h.node_id).collect();
        assert_eq!(node_order, vec![hyp, vm2, vm2, hyp, hyp, vm3]);
    }

    #[test]
    fn edge_to_absent_node_skipped() {
        // An edge points to a node_id with no hops in the journey.
        // extract_forwarding_chains must skip it (the `continue` at the
        // `!node_groups.contains_key` check) rather than panic.
        let absent_node = node_d();

        let mut journey = create_journey(vec![
            create_hop(node_a(), "src", 1000, "kprobe:tcp_sendmsg"),
            create_hop(node_b(), "mid", 2000, "kprobe:netif_receive_skb"),
            create_hop(node_b(), "mid", 2100, "kprobe:dev_queue_xmit"),
            create_hop(node_c(), "dst", 3000, "kprobe:tcp_v4_rcv"),
        ]);

        let edges = vec![
            HopEdge {
                from_node: node_a(),
                from_tracking_id: String::new(),
                to_node: absent_node,
            },
            HopEdge {
                from_node: node_a(),
                from_tracking_id: String::new(),
                to_node: node_b(),
            },
        ];

        // Must not panic despite the dangling edge to absent_node.
        enforce_causality(&mut journey, &edges);

        assert_eq!(journey.hops[0].node_id, node_a());
        assert_eq!(journey.hops[1].node_id, node_b());
        assert_eq!(journey.hops[2].node_id, node_b());
        assert_eq!(journey.hops[3].node_id, node_c());
    }

    #[test]
    fn ntp_correction_changes_intermediate_order() {
        // Without NTP correction, epoch_ns ordering would place mid_b
        // (epoch 5000) after mid_c (epoch 3000). But mid_b has a large
        // positive NTP offset (clock was ahead), so its corrected time
        // (5000 - 3500 = 1500) is earlier than mid_c's (3000 - 0 = 3000).
        let mut hops = vec![
            create_hop(node_a(), "src", 1000, "kprobe:tcp_sendmsg"),
            create_hop(node_b(), "mid_b", 5000, "kprobe:netif_receive_skb"),
            create_hop(node_b(), "mid_b", 5100, "kprobe:dev_queue_xmit"),
            create_hop(node_c(), "mid_c", 3000, "kprobe:netif_receive_skb"),
            create_hop(node_c(), "mid_c", 3100, "kprobe:dev_queue_xmit"),
            create_hop(node_d(), "dst", 6000, "kprobe:tcp_v4_rcv"),
        ];
        // mid_b's clock was 3500ns ahead of true time.
        hops[1].ntp_offset_ns = 3500;
        hops[2].ntp_offset_ns = 3500;

        let mut journey = create_journey(hops);
        enforce_causality(&mut journey, &[]);

        // NTP-corrected first_epoch_ns: mid_b = 1500, mid_c = 3000.
        // Intermediates sort by corrected time: mid_b first.
        assert_eq!(journey.hops[0].node_id, node_a());
        assert_eq!(journey.hops[1].node_id, node_b());
        assert_eq!(journey.hops[2].node_id, node_b());
        assert_eq!(journey.hops[3].node_id, node_c());
        assert_eq!(journey.hops[4].node_id, node_c());
        assert_eq!(journey.hops[5].node_id, node_d());
    }
}
