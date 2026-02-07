//! Journey builder for constructing packet journeys from DuckDB events.
//!
//! Groups events by `tracking_id` (single-node) or `correlation_id` (cross-node).
//! See `correlation_id.h` for which protocols support cross-node correlation.

use std::collections::HashMap;

use anyhow::{Context, Result};
use uuid::Uuid;

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
    /// Nanoseconds since Unix epoch, inclusive.
    pub start_ns: i64,
    /// Nanoseconds since Unix epoch, inclusive.
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

        if rows.is_empty() {
            return Ok(None);
        }

        self.build_single_journey(tracking_id.to_string(), rows)
    }

    pub fn build_journey_by_correlation_id(&self, correlation_id: &str) -> Result<Option<Journey>> {
        let rows = self
            .client
            .query_by_correlation_id(correlation_id)
            .context("querying events by correlation_id")?;

        if rows.is_empty() {
            return Ok(None);
        }

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

        if rows.is_empty() {
            return Ok(Vec::new());
        }

        // Group events based on mode
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
        let mut journey = Journey::new(journey_key);

        for row in rows {
            let hop = row_to_hop(&row)?;
            journey.hops.push(hop);
        }

        journey.recompute_timing();

        Ok(Some(journey))
    }
}

fn row_to_hop(row: &EventQueryRow) -> Result<JourneyHop> {
    Ok(JourneyHop {
        event_id: row.event_uuid().context("parsing event_id")?,
        node_id: row.node_uuid().context("parsing node_id")?,
        node_name: row.node_name.clone(),
        epoch_ns: row.epoch_ns,
        probe_point: row.probe_point.clone(),
        event_type: row.event_type.clone(),
        flow_id: row.flow_id.clone(),
    })
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

    /// Helper to create an EventQueryRow with explicit correlation_id.
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
}
