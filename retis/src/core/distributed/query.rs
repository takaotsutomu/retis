//! ClickHouse query client for journey building.
//!
//! Provides query capabilities against ClickHouse event storage for correlating
//! events across nodes. Used by [`JourneyBuilder`](super::journey_builder) to
//! fetch related events by tracking ID, flow ID, or time range.
//!
//! # Memory Considerations
//!
//! Queries use ClickHouse's JSON format which loads the entire result into memory.
//! For large result sets, use appropriate `limit` values in [`EventQueryFilter`]
//! to avoid excessive memory usage. The default `max_rows` of 10,000 is a
//! reasonable upper bound for most correlation queries.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use log::debug;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use uuid::Uuid;

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_IO_TIMEOUT: Duration = Duration::from_secs(60);
const DEFAULT_MAX_ROWS: u64 = 10_000;

/// Configuration for the ClickHouse query client.
#[derive(Debug, Clone)]
pub(crate) struct QueryConfig {
    pub url: String,
    pub database: String,
    pub table: String,
    pub user: Option<String>,
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
    pub max_rows: u64,
}

impl Default for QueryConfig {
    fn default() -> Self {
        Self {
            url: "http://localhost:8123".to_string(),
            database: "retis".to_string(),
            table: "retis_events".to_string(),
            user: None,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            io_timeout: DEFAULT_IO_TIMEOUT,
            max_rows: DEFAULT_MAX_ROWS,
        }
    }
}

impl QueryConfig {
    /// Creates a QueryConfig from ClickHouseConfig values.
    pub fn from_clickhouse_config(
        url: &str,
        database: &str,
        table: &str,
        user: Option<&str>,
    ) -> Self {
        Self {
            url: url.to_string(),
            database: database.to_string(),
            table: table.to_string(),
            user: user.map(String::from),
            ..Default::default()
        }
    }
}

/// A row returned from a ClickHouse event query.
///
/// Contains all fields needed to construct a [`JourneyHop`](super::journey::JourneyHop)
/// and correlate events across nodes.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct EventQueryRow {
    pub event_id: String,
    pub node_id: String,
    /// Nanoseconds since Unix epoch
    pub epoch_ns: i64,
    pub ntp_offset_ns: i64,
    pub ntp_uncertainty_ns: u64,
    /// 0=Synchronized, 1=Degraded, 2=Unsynchronized
    pub sync_status: u8,
    pub session_id: u64,
    pub node_name: String,
    pub hostname: String,
    /// Hex string (node-local tracking ID)
    pub tracking_id: String,
    /// Hex string (deterministic cross-node correlation ID)
    pub correlation_id: String,
    pub flow_id: String,
    pub event_type: String,
    pub probe_point: String,
    pub event_json: String,
}

impl EventQueryRow {
    pub fn node_uuid(&self) -> Result<Uuid> {
        Uuid::parse_str(&self.node_id).context("parsing node_id as UUID")
    }

    pub fn event_uuid(&self) -> Result<Uuid> {
        Uuid::parse_str(&self.event_id).context("parsing event_id as UUID")
    }

    /// Parse the event_json field into a typed struct.
    pub fn parse_event_json<T: DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_str(&self.event_json).context("parsing event_json")
    }
}

/// Filters for querying events from ClickHouse.
///
/// Multiple filters are combined with AND logic. At least one filter should
/// be specified to avoid unbounded queries.
#[derive(Debug, Clone, Default)]
pub(crate) struct EventQueryFilter {
    pub tracking_id: Option<String>,
    pub correlation_id: Option<String>,
    pub flow_id: Option<String>,
    /// Matches both directions of the flow
    pub canonical_flow_id: Option<String>,
    pub node_id: Option<Uuid>,
    /// Inclusive, nanoseconds since epoch
    pub start_time_ns: Option<i64>,
    /// Inclusive, nanoseconds since epoch
    pub end_time_ns: Option<i64>,
    pub event_type: Option<String>,
    /// Substring match
    pub probe_point_contains: Option<String>,
    pub limit: Option<u64>,
}

impl EventQueryFilter {
    pub fn by_tracking_id(tracking_id: &str) -> Self {
        Self {
            tracking_id: Some(tracking_id.to_string()),
            ..Default::default()
        }
    }

    /// Filter by correlation ID for cross-node correlation.
    pub fn by_correlation_id(correlation_id: &str) -> Self {
        Self {
            correlation_id: Some(correlation_id.to_string()),
            ..Default::default()
        }
    }

    pub fn by_flow_id(flow_id: &str) -> Self {
        Self {
            flow_id: Some(flow_id.to_string()),
            ..Default::default()
        }
    }

    pub fn by_time_range(start_ns: i64, end_ns: i64) -> Self {
        Self {
            start_time_ns: Some(start_ns),
            end_time_ns: Some(end_ns),
            ..Default::default()
        }
    }

    pub fn by_canonical_flow_id(canonical_flow_id: &str) -> Self {
        Self {
            canonical_flow_id: Some(canonical_flow_id.to_string()),
            ..Default::default()
        }
    }

    pub fn with_time_range(mut self, start_ns: i64, end_ns: i64) -> Self {
        self.start_time_ns = Some(start_ns);
        self.end_time_ns = Some(end_ns);
        self
    }

    pub fn with_limit(mut self, limit: u64) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn is_empty(&self) -> bool {
        self.tracking_id.is_none()
            && self.correlation_id.is_none()
            && self.flow_id.is_none()
            && self.canonical_flow_id.is_none()
            && self.node_id.is_none()
            && self.start_time_ns.is_none()
            && self.end_time_ns.is_none()
            && self.event_type.is_none()
            && self.probe_point_contains.is_none()
    }
}

/// Client for querying events from ClickHouse.
///
/// Used by [`JourneyBuilder`](super::journey_builder) to fetch events that
/// need to be correlated into journeys.
pub(crate) struct ClickHouseQueryClient {
    config: QueryConfig,
    agent: ureq::Agent,
    password: Option<String>,
}

impl ClickHouseQueryClient {
    pub fn new(config: QueryConfig, password: Option<&str>) -> Self {
        let agent = ureq::Agent::new_with_config(
            ureq::config::Config::builder()
                .timeout_connect(Some(config.connect_timeout))
                .timeout_recv_response(Some(config.io_timeout))
                .build(),
        );

        Self {
            config,
            agent,
            password: password.map(String::from),
        }
    }

    /// Results are ordered by `epoch_ns` ascending.
    pub fn query_events(&self, filter: &EventQueryFilter) -> Result<Vec<EventQueryRow>> {
        let query = self.build_query(filter)?;
        debug!("ClickHouse query: {}", query);

        self.execute_query(&query)
    }

    pub fn query_by_tracking_id(&self, tracking_id: &str) -> Result<Vec<EventQueryRow>> {
        self.query_events(&EventQueryFilter::by_tracking_id(tracking_id))
    }

    pub fn query_by_correlation_id(&self, correlation_id: &str) -> Result<Vec<EventQueryRow>> {
        self.query_events(&EventQueryFilter::by_correlation_id(correlation_id))
    }

    pub fn query_by_flow_id(&self, flow_id: &str) -> Result<Vec<EventQueryRow>> {
        self.query_events(&EventQueryFilter::by_flow_id(flow_id))
    }

    pub fn query_by_time_range(&self, start_ns: i64, end_ns: i64) -> Result<Vec<EventQueryRow>> {
        self.query_events(&EventQueryFilter::by_time_range(start_ns, end_ns))
    }

    pub fn count_events(&self, filter: &EventQueryFilter) -> Result<u64> {
        let conditions = self.build_where_conditions(filter);

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        let query = format!(
            "SELECT count() FROM {}.{} {}",
            self.config.database, self.config.table, where_clause
        );

        let mut request = self.agent.post(&self.config.url);
        if let Some(ref user) = self.config.user {
            request = request.header("X-ClickHouse-User", user);
        }
        if let Some(ref password) = self.password {
            request = request.header("X-ClickHouse-Key", password);
        }

        let mut response = request.send(&query).context("sending count query")?;

        if response.status().as_u16() != 200 {
            bail!("ClickHouse count failed with status {}", response.status());
        }

        let body = response
            .body_mut()
            .read_to_string()
            .context("reading count response")?;

        body.trim().parse::<u64>().context("parsing count result")
    }

    /// Build WHERE clause conditions from a filter.
    ///
    /// This is shared between query_events and count_events to ensure
    /// consistent filter behavior.
    fn build_where_conditions(&self, filter: &EventQueryFilter) -> Vec<String> {
        let mut conditions = Vec::new();

        if let Some(ref tracking_id) = filter.tracking_id {
            conditions.push(format!("tracking_id = '{}'", escape_sql(tracking_id)));
        }

        if let Some(ref correlation_id) = filter.correlation_id {
            conditions.push(format!("correlation_id = '{}'", escape_sql(correlation_id)));
        }

        if let Some(ref flow_id) = filter.flow_id {
            conditions.push(format!("flow_id = '{}'", escape_sql(flow_id)));
        }

        if let Some(ref canonical_flow_id) = filter.canonical_flow_id {
            // Match both directions of the flow. Escape both the original and
            // reversed flow IDs to prevent SQL injection.
            let reversed = reverse_flow_id(canonical_flow_id);
            conditions.push(format!(
                "(flow_id = '{}' OR flow_id = '{}')",
                escape_sql(canonical_flow_id),
                escape_sql(&reversed)
            ));
        }

        if let Some(node_id) = filter.node_id {
            conditions.push(format!("node_id = '{}'", node_id));
        }

        if let Some(start_ns) = filter.start_time_ns {
            conditions.push(format!("epoch_ns >= {}", start_ns));
        }

        if let Some(end_ns) = filter.end_time_ns {
            conditions.push(format!("epoch_ns <= {}", end_ns));
        }

        if let Some(ref event_type) = filter.event_type {
            conditions.push(format!("event_type = '{}'", escape_sql(event_type)));
        }

        if let Some(ref probe_point) = filter.probe_point_contains {
            // ClickHouse uses backslash as the default LIKE escape character,
            // so \% and \_ are interpreted as literal % and _ without needing
            // an explicit ESCAPE clause.
            conditions.push(format!(
                "probe_point LIKE '%{}%'",
                escape_sql_like(probe_point)
            ));
        }

        conditions
    }

    fn build_query(&self, filter: &EventQueryFilter) -> Result<String> {
        let conditions = self.build_where_conditions(filter);

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        let limit = filter.limit.unwrap_or(self.config.max_rows);

        Ok(format!(
            "SELECT \
                event_id, node_id, epoch_ns, ntp_offset_ns, ntp_uncertainty_ns, \
                sync_status, session_id, node_name, hostname, tracking_id, \
                correlation_id, flow_id, event_type, probe_point, event_json \
            FROM {}.{} \
            {} \
            ORDER BY epoch_ns ASC \
            LIMIT {} \
            FORMAT JSON",
            self.config.database, self.config.table, where_clause, limit
        ))
    }

    fn execute_query(&self, query: &str) -> Result<Vec<EventQueryRow>> {
        let mut request = self.agent.post(&self.config.url);

        if let Some(ref user) = self.config.user {
            request = request.header("X-ClickHouse-User", user);
        }
        if let Some(ref password) = self.password {
            request = request.header("X-ClickHouse-Key", password);
        }

        let mut response = request.send(query).context("sending query to ClickHouse")?;

        if response.status().as_u16() != 200 {
            // Don't try to read error body - it consumes the response and could
            // be large. Just report the status code.
            bail!("ClickHouse query failed with status {}", response.status());
        }

        let body = response
            .body_mut()
            .read_to_string()
            .context("reading response body")?;

        // ClickHouse JSON format wraps rows in a "data" array
        let parsed: ClickHouseJsonResponse =
            serde_json::from_str(&body).context("parsing ClickHouse JSON response")?;

        debug!(
            "Query returned {} rows ({} bytes read)",
            parsed.rows, parsed.statistics.bytes_read
        );

        Ok(parsed.data)
    }
}

#[derive(Debug, Deserialize)]
struct ClickHouseJsonResponse {
    data: Vec<EventQueryRow>,
    rows: u64,
    statistics: ClickHouseStatistics,
}

#[derive(Debug, Deserialize)]
struct ClickHouseStatistics {
    bytes_read: u64,
    #[allow(dead_code)]
    rows_read: u64,
    #[allow(dead_code)]
    elapsed: f64,
}

fn escape_sql(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "''")
}

/// Escape special characters for SQL LIKE patterns.
///
/// In addition to standard SQL escaping, also escapes LIKE wildcards.
/// ClickHouse uses backslash as the default escape character, so \% and \_
/// are interpreted as literal characters without an explicit ESCAPE clause.
fn escape_sql_like(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('\'', "''")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// Reverse the direction of a flow ID string.
///
/// Flow IDs are formatted as (per RFC 3986 for IPv6):
/// - IPv4 with ports: `proto:src_ip:src_port->dst_ip:dst_port`
/// - IPv6 with ports: `proto:[src_ip]:src_port->[dst_ip]:dst_port`
/// - Without ports (ICMP, etc.): `proto:src_ip->dst_ip`
///
/// This function swaps source and destination to enable bidirectional matching.
fn reverse_flow_id(flow_id: &str) -> String {
    let Some((proto_src, dst)) = flow_id.split_once("->") else {
        return flow_id.to_string();
    };

    let Some((proto, src)) = proto_src.split_once(':') else {
        return flow_id.to_string();
    };

    let (src_addr, src_port) = parse_addr_port(src);
    let (dst_addr, dst_port) = parse_addr_port(dst);

    let format_with_brackets = |addr: &str, had_brackets: bool| {
        if had_brackets {
            format!("[{}]", addr)
        } else {
            addr.to_string()
        }
    };

    let src_had_brackets = src.starts_with('[');
    let dst_had_brackets = dst.starts_with('[');

    match (src_port, dst_port) {
        (Some(sp), Some(dp)) => {
            format!(
                "{}:{}:{}->{}:{}",
                proto,
                format_with_brackets(dst_addr, dst_had_brackets),
                dp,
                format_with_brackets(src_addr, src_had_brackets),
                sp
            )
        }
        _ => {
            // No ports (ICMP, GRE, etc.)
            format!(
                "{}:{}->{}",
                proto,
                format_with_brackets(dst_addr, dst_had_brackets),
                format_with_brackets(src_addr, src_had_brackets)
            )
        }
    }
}

/// Parse an address:port string, handling both IPv4 and IPv6 formats.
///
/// IPv6 addresses are enclosed in brackets: `[2001:db8::1]:80`
/// IPv4 addresses use simple colon: `192.168.1.1:80`
/// Addresses without ports: `192.168.1.1` or `[2001:db8::1]`
///
/// Returns the address (without brackets for IPv6) and optional port.
fn parse_addr_port(s: &str) -> (&str, Option<&str>) {
    if s.starts_with('[') {
        if let Some(bracket_end) = s.find(']') {
            let addr = &s[1..bracket_end];
            let rest = &s[bracket_end + 1..];
            if let Some(port) = rest.strip_prefix(':') {
                return (addr, Some(port));
            }
            return (addr, None);
        }
        (s, None)
    } else if let Some((addr, port)) = s.rsplit_once(':') {
        // IPv4 format: check if this looks like a port (all digits)
        // to distinguish from bare IPv6 addresses without brackets.
        // If addr contains colons, it's likely an IPv6 address.
        if port.chars().all(|c| c.is_ascii_digit()) && !addr.contains(':') {
            (addr, Some(port))
        } else {
            // Likely an IPv6 address without brackets and no port
            (s, None)
        }
    } else {
        (s, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_sql_handles_special_chars() {
        assert_eq!(escape_sql("hello"), "hello");
        assert_eq!(escape_sql("it's"), "it''s");
        assert_eq!(escape_sql("a\\b"), "a\\\\b");
        assert_eq!(escape_sql("test'val\\end"), "test''val\\\\end");
    }

    #[test]
    fn escape_sql_like_handles_wildcards() {
        assert_eq!(escape_sql_like("100%"), "100\\%");
        assert_eq!(escape_sql_like("a_b"), "a\\_b");
        assert_eq!(escape_sql_like("test%_'\\"), "test\\%\\_''\\\\");
    }

    #[test]
    fn reverse_flow_id_handles_various_formats() {
        // TCP IPv4 with ports
        assert_eq!(
            reverse_flow_id("tcp:192.168.1.1:12345->10.0.0.1:80"),
            "tcp:10.0.0.1:80->192.168.1.1:12345"
        );

        // ICMP without ports
        assert_eq!(
            reverse_flow_id("icmp:192.168.1.1->10.0.0.1"),
            "icmp:10.0.0.1->192.168.1.1"
        );

        // IPv6 with brackets and ports
        assert_eq!(
            reverse_flow_id("tcp:[2001:db8::1]:443->[2001:db8::2]:80"),
            "tcp:[2001:db8::2]:80->[2001:db8::1]:443"
        );

        // IPv6 without ports
        assert_eq!(
            reverse_flow_id("icmpv6:[::1]->[::2]"),
            "icmpv6:[::2]->[::1]"
        );

        // Malformed input returns unchanged
        assert_eq!(reverse_flow_id("garbage"), "garbage");
    }

    #[test]
    fn parse_addr_port_handles_ipv4_ipv6_and_edge_cases() {
        // IPv4 with port
        assert_eq!(
            parse_addr_port("192.168.1.1:80"),
            ("192.168.1.1", Some("80"))
        );

        // IPv4 without port
        assert_eq!(parse_addr_port("192.168.1.1"), ("192.168.1.1", None));

        // IPv6 with brackets and port
        assert_eq!(
            parse_addr_port("[2001:db8::1]:443"),
            ("2001:db8::1", Some("443"))
        );

        // IPv6 with brackets, no port
        assert_eq!(parse_addr_port("[::1]"), ("::1", None));

        // Bare IPv6 without brackets - the rightmost ":1" looks like a port,
        // but addr contains colons, so we correctly treat it as a bare IPv6
        assert_eq!(parse_addr_port("2001:db8::1"), ("2001:db8::1", None));
    }

    #[test]
    fn filter_chaining_builds_correct_filter() {
        let filter = EventQueryFilter::by_tracking_id("test")
            .with_time_range(1000, 2000)
            .with_limit(100);

        assert_eq!(filter.tracking_id, Some("test".to_string()));
        assert_eq!(filter.start_time_ns, Some(1000));
        assert_eq!(filter.end_time_ns, Some(2000));
        assert_eq!(filter.limit, Some(100));
        assert!(!filter.is_empty());

        // Empty filter detection
        assert!(EventQueryFilter::default().is_empty());
    }

    #[test]
    fn build_query_generates_correct_sql() {
        let config = QueryConfig::default();
        let client = ClickHouseQueryClient::new(config, None);

        // Phase 1: Single filter produces correct WHERE clause
        let filter = EventQueryFilter::by_tracking_id("abc123");
        let query = client.build_query(&filter).unwrap();
        assert!(query.contains("WHERE tracking_id = 'abc123'"));
        assert!(query.contains("ORDER BY epoch_ns ASC"));
        assert!(query.contains("LIMIT 10000"));
        assert!(query.contains("FORMAT JSON"));

        // Phase 2: Time range filter
        let filter = EventQueryFilter::by_time_range(1_000_000, 2_000_000);
        let query = client.build_query(&filter).unwrap();
        assert!(query.contains("epoch_ns >= 1000000"));
        assert!(query.contains("epoch_ns <= 2000000"));

        // Phase 3: Multiple filters combined with AND
        let filter = EventQueryFilter {
            tracking_id: Some("abc".to_string()),
            flow_id: Some("tcp:1.2.3.4:80->5.6.7.8:443".to_string()),
            start_time_ns: Some(1000),
            limit: Some(50),
            ..Default::default()
        };
        let query = client.build_query(&filter).unwrap();
        assert!(query.contains("tracking_id = 'abc'"));
        assert!(query.contains("flow_id = 'tcp:1.2.3.4:80->5.6.7.8:443'"));
        assert!(query.contains("epoch_ns >= 1000"));
        assert!(query.contains("LIMIT 50"));
        assert!(query.contains(" AND "));

        // Phase 4: Empty filter produces no WHERE clause
        let empty = EventQueryFilter::default();
        let query = client.build_query(&empty).unwrap();
        assert!(!query.contains("WHERE"));
    }

    #[test]
    fn build_query_escapes_sql_injection_attempts() {
        let config = QueryConfig::default();
        let client = ClickHouseQueryClient::new(config, None);

        // Attempt SQL injection via tracking_id. The single quote at the start
        // must be escaped to '' so SQL treats the entire string as a literal.
        let filter = EventQueryFilter::by_tracking_id("'; DROP TABLE users; --");
        let query = client.build_query(&filter).unwrap();
        // The leading ' becomes '' (escaped), so the full SQL value is:
        // tracking_id = '''; DROP TABLE users; --'
        // This is safe because '' is a literal quote in SQL strings.
        assert!(query.contains("tracking_id = '''"));

        // Attempt SQL injection via canonical_flow_id (both original and
        // reversed should be escaped)
        let filter = EventQueryFilter::by_canonical_flow_id("tcp:1.2.3.4:80'->5.6.7.8:443");
        let query = client.build_query(&filter).unwrap();
        // The quote in the flow_id should be escaped
        assert!(query.contains("80''->"));
    }

    #[test]
    fn canonical_flow_id_matches_both_directions() {
        let config = QueryConfig::default();
        let client = ClickHouseQueryClient::new(config, None);

        let filter = EventQueryFilter::by_canonical_flow_id("tcp:192.168.1.1:12345->10.0.0.1:80");
        let query = client.build_query(&filter).unwrap();

        // Should contain OR clause with both directions
        assert!(query.contains("flow_id = 'tcp:192.168.1.1:12345->10.0.0.1:80'"));
        assert!(query.contains("flow_id = 'tcp:10.0.0.1:80->192.168.1.1:12345'"));
        assert!(query.contains(" OR "));
    }
}
