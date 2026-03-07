//! Journey builder for constructing packet journeys from DuckDB events.
//!
//! Groups events by `tracking_id` (single-node) or `correlation_id` (cross-node).
//! See `correlation_id.h` for which protocols support cross-node correlation.

use std::collections::HashMap;

use anyhow::{Context, Result};
use log::warn;
use uuid::Uuid;

use super::causality::{enforce_causality, HopEdge};
use super::journey::{Journey, JourneyHop};
use super::query::{DuckDbQueryClient, EventQueryFilter, EventQueryRow};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum JourneyMode {
    #[default]
    SingleNode,
    CrossNode,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct JourneyFilter {
    pub start_ns: i64,
    pub end_ns: i64,
    pub mode: JourneyMode,
    /// None = all nodes.
    pub node_id: Option<Uuid>,
}

pub(crate) struct JourneyBuilder<'a> {
    client: &'a DuckDbQueryClient,
}

impl<'a> JourneyBuilder<'a> {
    pub fn new(client: &'a DuckDbQueryClient) -> Self {
        Self { client }
    }

    pub fn build_journey_by_tracking_id(&self, tracking_id: &str) -> Result<Option<Journey>> {
        let rows = self
            .client
            .query_by_tracking_id(tracking_id)
            .context("querying events by tracking_id")?;

        self.build_single_journey(tracking_id.to_string(), rows)
    }

    pub fn build_journey_by_correlation_id(&self, correlation_id: &str) -> Result<Option<Journey>> {
        let rows = self
            .client
            .query_by_correlation_id(correlation_id)
            .context("querying events by correlation_id")?;

        self.build_single_journey(correlation_id.to_string(), rows)
    }

    /// Groups events by `tracking_id` (SingleNode) or `correlation_id` (CrossNode).
    /// In CrossNode mode, events with empty `correlation_id` are excluded.
    pub fn build_journeys(&self, filter: &JourneyFilter) -> Result<Vec<Journey>> {
        let query_filter = EventQueryFilter {
            node_id: filter.node_id,
            start_time_ns: Some(filter.start_ns),
            end_time_ns: Some(filter.end_ns),
            ..Default::default()
        };

        let rows = self
            .client
            .query_events(&query_filter)
            .context("querying events for journeys")?;

        let groups: HashMap<String, Vec<EventQueryRow>> = match filter.mode {
            JourneyMode::SingleNode => group_by_tracking_id(rows),
            JourneyMode::CrossNode => group_by_correlation_id(rows),
        };

        let mut journeys = Vec::new();

        for (id, group_rows) in groups {
            if let Some(journey) = self.build_single_journey(id, group_rows)? {
                journeys.push(journey);
            }
        }

        Ok(journeys)
    }

    /// Assumes events are already ordered by `epoch_ns` (from DuckDB ORDER BY).
    fn build_single_journey(
        &self,
        journey_key: String,
        rows: Vec<EventQueryRow>,
    ) -> Result<Option<Journey>> {
        if rows.is_empty() {
            return Ok(None);
        }

        let mut journey = Journey::new(journey_key);
        let (hops, edges) = build_hops_and_edges(rows)?;
        journey.hops = hops;

        // Edge deduplication is intentionally omitted:
        // `extract_forwarding_chains` handles duplicates naturally via
        // its group-indexed map.
        enforce_causality(&mut journey, &edges);
        journey.recompute_timing();

        Ok(Some(journey))
    }
}

fn row_to_hop(row: &EventQueryRow) -> Result<JourneyHop> {
    Ok(JourneyHop {
        event_id: row.event_uuid().context("parsing event_id")?,
        node_id: row.node_uuid().context("parsing node_id")?,
        node_name: row.node_name.clone(),
        tracking_id: row.tracking_id.clone(),
        ntp_offset_ns: row.ntp_offset_ns,
        epoch_ns: row.epoch_ns,
        probe_point: row.probe_point.clone(),
        event_type: row.event_type.clone(),
        flow_id: row.flow_id.clone(),
    })
}

/// Converts query rows into journey hops and topology edges.
///
/// `node_id` is parsed with hard errors because it is our own node
/// identity and must always be valid. `next_hop_node_id` parse
/// failures are logged and skipped, since this is external mapping data
/// that may legitimately be absent or malformed.
fn build_hops_and_edges(rows: Vec<EventQueryRow>) -> Result<(Vec<JourneyHop>, Vec<HopEdge>)> {
    let mut hops = Vec::with_capacity(rows.len());
    let mut edges = Vec::new();

    for row in rows {
        let hop = row_to_hop(&row)?;

        if let Some(ref next_hop) = row.next_hop_node_id {
            match Uuid::parse_str(next_hop) {
                Ok(to) => {
                    edges.push(HopEdge {
                        from_node: hop.node_id,
                        from_tracking_id: row.tracking_id.clone(),
                        to_node: to,
                    });
                }
                Err(e) => {
                    warn!("Skipping malformed next_hop_node_id {:?}: {}", next_hop, e);
                }
            }
        }

        hops.push(hop);
    }

    Ok((hops, edges))
}

fn group_by_tracking_id(rows: Vec<EventQueryRow>) -> HashMap<String, Vec<EventQueryRow>> {
    let mut groups: HashMap<String, Vec<EventQueryRow>> = HashMap::new();

    for row in rows {
        groups.entry(row.tracking_id.clone()).or_default().push(row);
    }

    groups
}

fn group_by_correlation_id(rows: Vec<EventQueryRow>) -> HashMap<String, Vec<EventQueryRow>> {
    let mut groups: HashMap<String, Vec<EventQueryRow>> = HashMap::new();

    for row in rows {
        if row.correlation_id.is_empty() {
            continue;
        }
        groups
            .entry(row.correlation_id.clone())
            .or_default()
            .push(row);
    }

    groups
}

#[cfg(test)]
mod tests {
    use super::*;

    const NODE_A: &str = "00000000-0000-0000-0000-00000000000a";
    const NODE_B: &str = "00000000-0000-0000-0000-00000000000b";

    fn create_row_with_correlation(
        event_id: &str,
        node_id: &str,
        epoch_ns: i64,
        tracking_id: &str,
        correlation_id: &str,
        flow_id: &str,
    ) -> EventQueryRow {
        EventQueryRow {
            event_id: event_id.to_string(),
            node_id: node_id.to_string(),
            epoch_ns,
            ntp_offset_ns: 0,
            sync_status: 0,
            session_id: 1,
            node_name: "test-node".to_string(),
            hostname: "test-host".to_string(),
            tracking_id: tracking_id.to_string(),
            correlation_id: correlation_id.to_string(),
            flow_id: flow_id.to_string(),
            event_type: "kprobe".to_string(),
            probe_point: "kprobe:tcp_sendmsg".to_string(),
            next_hop_node_id: None,
            event_json: "{}".to_string(),
        }
    }

    #[test]
    fn group_by_correlation_id_skips_empty() {
        let rows = vec![
            create_row_with_correlation(
                "00000000-0000-0000-0000-000000000001",
                "00000000-0000-0000-0000-000000000001",
                1000,
                "track-a",
                "corr-x",
                "tcp:1.2.3.4:80->5.6.7.8:443",
            ),
            // This row has empty correlation_id (unsupported protocol)
            create_row_with_correlation(
                "00000000-0000-0000-0000-000000000002",
                "00000000-0000-0000-0000-000000000001",
                2000,
                "track-b",
                "", // Empty = unsupported protocol
                "gre:1.2.3.4->5.6.7.8",
            ),
            create_row_with_correlation(
                "00000000-0000-0000-0000-000000000003",
                "00000000-0000-0000-0000-000000000002",
                3000,
                "track-c",
                "corr-x",
                "tcp:1.2.3.4:80->5.6.7.8:443",
            ),
        ];

        let groups = group_by_correlation_id(rows);

        // Only 1 group (corr-x), the empty correlation_id row is excluded
        assert_eq!(groups.len(), 1);
        assert_eq!(groups.get("corr-x").map(|v| v.len()), Some(2));
        assert!(groups.get("").is_none());
    }

    #[test]
    fn build_hops_and_edges_correctness() {
        // Rows with next_hop_node_id produce correct edges.
        let mut row_a = create_row_with_correlation(
            "00000000-0000-0000-0000-000000000001",
            NODE_A,
            1000,
            "track-a",
            "corr-x",
            "tcp:1.2.3.4:80->5.6.7.8:443",
        );
        row_a.next_hop_node_id = Some(NODE_B.to_string());

        let row_b = create_row_with_correlation(
            "00000000-0000-0000-0000-000000000002",
            NODE_B,
            2000,
            "track-a",
            "corr-x",
            "tcp:1.2.3.4:80->5.6.7.8:443",
        );

        let (hops, edges) = build_hops_and_edges(vec![row_a, row_b]).unwrap();
        assert_eq!(hops.len(), 2);
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].from_node, Uuid::parse_str(NODE_A).unwrap());
        assert_eq!(edges[0].to_node, Uuid::parse_str(NODE_B).unwrap());

        // Self-edges pass through unfiltered;
        // `extract_forwarding_chains` handles them naturally.
        let mut self_edge_row = create_row_with_correlation(
            "00000000-0000-0000-0000-000000000003",
            NODE_A,
            3000,
            "track-a",
            "corr-x",
            "tcp:1.2.3.4:80->5.6.7.8:443",
        );
        self_edge_row.next_hop_node_id = Some(NODE_A.to_string());

        let (hops, edges) = build_hops_and_edges(vec![self_edge_row]).unwrap();
        assert_eq!(hops.len(), 1);
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].from_node, edges[0].to_node);

        // Malformed next_hop_node_id is skipped without error.
        let mut bad_hop_row = create_row_with_correlation(
            "00000000-0000-0000-0000-000000000005",
            NODE_A,
            5000,
            "track-a",
            "corr-x",
            "tcp:1.2.3.4:80->5.6.7.8:443",
        );
        bad_hop_row.next_hop_node_id = Some("not-a-uuid".to_string());

        let (hops, edges) = build_hops_and_edges(vec![bad_hop_row]).unwrap();
        assert_eq!(hops.len(), 1);
        assert!(edges.is_empty());
    }
}
