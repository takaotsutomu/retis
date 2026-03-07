//! Collector-side discovery of local network topology.
//!
//! Periodically collects interface and OVS port information from the local
//! system, producing [`NodeMappingSnapshot`]s that are sent to the aggregator.
//!
//! # Collection Methods
//!
//! 1. **Interfaces**: Parses `ip -j link show` and `ip -j addr show` (JSON
//!    output) for interface names, MACs, and IP addresses. Returns empty
//!    if JSON output is unavailable.
//!
//! 2. **OVS ports**: Runs `ovs-dpctl show` for port number -> name mappings,
//!    then `ovs-vsctl show` for tunnel remote_ip per interface. Joins on
//!    port name. Gracefully skips if OVS tools are not installed or the
//!    daemon is not running.

use std::collections::HashMap;
use std::process::Command;
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use log::{debug, info, warn};
use serde::Deserialize;

use super::client::CollectorCommand;
use super::node_mapping::{InterfaceMapping, NodeMappingSnapshot, OvsPortMapping};

/// Default interval between mapping discovery runs.
const DEFAULT_DISCOVERY_INTERVAL: Duration = Duration::from_secs(30);

/// Configuration for the mapping discovery background thread.
#[derive(Debug, Clone)]
pub(crate) struct MappingDiscoveryConfig {
    pub enabled: bool,
    pub interval: Duration,
}

impl Default for MappingDiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: DEFAULT_DISCOVERY_INTERVAL,
        }
    }
}

/// Background thread that periodically discovers local topology.
pub(crate) struct MappingDiscoverer {
    shutdown_sender: mpsc::SyncSender<()>,
    thread: Option<JoinHandle<()>>,
}

impl MappingDiscoverer {
    /// Start the discovery background thread.
    ///
    /// Sends an initial snapshot immediately, then periodically at the
    /// configured interval. Snapshots are sent via `command_sender` as
    /// [`CollectorCommand::NodeMapping`].
    pub fn start(
        node_id: [u8; 16],
        config: MappingDiscoveryConfig,
        command_sender: SyncSender<CollectorCommand>,
    ) -> Self {
        let (shutdown_sender, shutdown_receiver) = mpsc::sync_channel(1);

        let thread = thread::Builder::new()
            .name("mapping-discovery".into())
            .spawn(move || {
                run_discovery(
                    node_id,
                    config.interval,
                    &shutdown_receiver,
                    &command_sender,
                );
            })
            .expect("failed to spawn mapping discovery thread");

        Self {
            shutdown_sender,
            thread: Some(thread),
        }
    }

    /// Shut down the discovery thread and wait for it to finish.
    pub fn shutdown(&mut self) {
        let _ = self.shutdown_sender.send(());
        if let Some(thread) = self.thread.take() {
            if let Err(e) = thread.join() {
                warn!("Mapping discovery thread panicked: {:?}", e);
            }
        }
    }
}

impl Drop for MappingDiscoverer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Collect a snapshot immediately, then periodically at `interval`.
fn run_discovery(
    node_id: [u8; 16],
    interval: Duration,
    stop_receiver: &mpsc::Receiver<()>,
    command_sender: &SyncSender<CollectorCommand>,
) {
    info!("Mapping discovery started (interval: {:?})", interval);

    // Initial collection on startup
    collect_and_send(node_id, command_sender);

    loop {
        match stop_receiver.recv_timeout(interval) {
            Ok(()) => {
                info!("Mapping discovery shutting down");
                break;
            }
            Err(RecvTimeoutError::Timeout) => {
                collect_and_send(node_id, command_sender);
            }
            Err(RecvTimeoutError::Disconnected) => {
                debug!("Mapping discovery channel disconnected");
                break;
            }
        }
    }
}

fn collect_and_send(node_id: [u8; 16], sender: &SyncSender<CollectorCommand>) {
    let snapshot = collect_snapshot(node_id);

    debug!(
        "Discovered {} interfaces, {} OVS ports",
        snapshot.interfaces.len(),
        snapshot.ovs_ports.len()
    );

    // Use try_send (non-blocking): if the channel is full, the worker is
    // disconnected or heavily loaded, and events take priority. This snapshot
    // will be retransmitted on the next discovery cycle (~30s).
    if let Err(e) = sender.try_send(CollectorCommand::NodeMapping(snapshot)) {
        debug!("Failed to send mapping snapshot: {}", e);
    }
}

/// Collect a full mapping snapshot from the local system.
fn collect_snapshot(node_id: [u8; 16]) -> NodeMappingSnapshot {
    let timestamp_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is before Unix epoch")
        .as_nanos() as i64;

    let interfaces = collect_interfaces();
    let ovs_ports = collect_ovs_ports();

    NodeMappingSnapshot {
        node_id,
        timestamp_ns,
        interfaces,
        ovs_ports,
    }
}

/// JSON structure from `ip -j link show`.
#[derive(Deserialize, Debug)]
struct IpLinkEntry {
    ifname: String,
    address: Option<String>,
}

/// JSON structure from `ip -j addr show`.
#[derive(Deserialize, Debug)]
struct IpAddrEntry {
    ifname: String,
    addr_info: Option<Vec<IpAddrInfo>>,
}

#[derive(Deserialize, Debug)]
struct IpAddrInfo {
    family: String,
    local: String,
    /// Address scope from `ip -j addr show`. Used to filter out link-local
    /// addresses which can collide across nodes on separate L2 domains.
    scope: Option<String>,
}

/// Collect interface information using `ip -j` commands.
fn collect_interfaces() -> Vec<InterfaceMapping> {
    build_interface_mappings(collect_ip_links(), collect_ip_addrs())
}

/// Join link and address data into [`InterfaceMapping`]s.
///
/// Link-local addresses (scope "link") are filtered out because they can
/// collide across nodes on separate L2 domains (e.g., OVS internal bridges
/// with deterministic MACs often share fe80::1).
fn build_interface_mappings(
    links: Vec<IpLinkEntry>,
    addrs: Vec<IpAddrEntry>,
) -> Vec<InterfaceMapping> {
    // Build a map of interface name -> (ipv4, ipv6) address lists
    let mut addr_map: HashMap<String, (Vec<String>, Vec<String>)> = HashMap::new();
    for entry in &addrs {
        let (ipv4, ipv6) = addr_map.entry(entry.ifname.clone()).or_default();
        if let Some(ref infos) = entry.addr_info {
            for info in infos {
                // Skip link-local addresses, see doc comment above.
                if info.scope.as_deref() == Some("link") {
                    continue;
                }
                match info.family.as_str() {
                    "inet" => ipv4.push(info.local.clone()),
                    "inet6" => ipv6.push(info.local.clone()),
                    _ => {}
                }
            }
        }
    }

    links
        .into_iter()
        .map(|link| {
            let (ipv4, ipv6) = addr_map.remove(&link.ifname).unwrap_or_default();
            InterfaceMapping {
                name: link.ifname,
                mac: link.address.unwrap_or_default(),
                ipv4_addrs: ipv4,
                ipv6_addrs: ipv6,
            }
        })
        .collect()
}

fn collect_ip_links() -> Vec<IpLinkEntry> {
    match Command::new("ip").args(["-j", "link", "show"]).output() {
        Ok(output) if output.status.success() => {
            match serde_json::from_slice::<Vec<IpLinkEntry>>(&output.stdout) {
                Ok(entries) => entries,
                Err(e) => {
                    debug!("Failed to parse `ip -j link show` JSON: {}", e);
                    Vec::new()
                }
            }
        }
        Ok(output) => {
            debug!(
                "`ip -j link show` failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            Vec::new()
        }
        Err(e) => {
            debug!("`ip` command not found: {}", e);
            Vec::new()
        }
    }
}

fn collect_ip_addrs() -> Vec<IpAddrEntry> {
    match Command::new("ip").args(["-j", "addr", "show"]).output() {
        Ok(output) if output.status.success() => {
            match serde_json::from_slice::<Vec<IpAddrEntry>>(&output.stdout) {
                Ok(entries) => entries,
                Err(e) => {
                    debug!("Failed to parse `ip -j addr show` JSON: {}", e);
                    Vec::new()
                }
            }
        }
        Ok(output) => {
            debug!(
                "`ip -j addr show` failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            Vec::new()
        }
        Err(e) => {
            debug!("`ip` command not available: {}", e);
            Vec::new()
        }
    }
}

/// Collect OVS port mappings by joining `ovs-dpctl show` and `ovs-vsctl show`.
fn collect_ovs_ports() -> Vec<OvsPortMapping> {
    // Step 1: Get port_number -> port_name from ovs-dpctl show
    let dp_ports = match run_ovs_dpctl_show() {
        Some(output) => parse_ovs_dpctl_show(&output),
        None => return Vec::new(),
    };

    if dp_ports.is_empty() {
        return Vec::new();
    }

    // Step 2: Get port_name -> tunnel_remote_ip from ovs-vsctl show
    let tunnel_map = match run_ovs_vsctl_show() {
        Some(output) => parse_ovs_vsctl_show(&output),
        None => {
            warn!(
                "ovs-dpctl available but ovs-vsctl failed (ovsdb-server \
                 down?); OVS tunnel resolution will be unavailable"
            );
            return Vec::new();
        }
    };

    // Step 3: Join on port name
    dp_ports
        .into_iter()
        .map(|(port_number, port_name)| {
            let tunnel_remote_ip = tunnel_map.get(&port_name).cloned();
            OvsPortMapping {
                port_number,
                port_name,
                tunnel_remote_ip,
            }
        })
        .collect()
}

fn run_ovs_dpctl_show() -> Option<String> {
    match Command::new("ovs-dpctl").arg("show").output() {
        Ok(output) if output.status.success() => {
            Some(String::from_utf8_lossy(&output.stdout).to_string())
        }
        Ok(output) => {
            debug!(
                "`ovs-dpctl show` failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
            None
        }
        Err(e) => {
            // Command not found; OVS not installed, expected on non-OVS nodes
            debug!("`ovs-dpctl` not available: {}", e);
            None
        }
    }
}

fn run_ovs_vsctl_show() -> Option<String> {
    match Command::new("ovs-vsctl").arg("show").output() {
        Ok(output) if output.status.success() => {
            Some(String::from_utf8_lossy(&output.stdout).to_string())
        }
        Ok(output) => {
            debug!(
                "`ovs-vsctl show` failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
            None
        }
        Err(e) => {
            debug!("`ovs-vsctl` not available: {}", e);
            None
        }
    }
}

/// Parse `ovs-dpctl show` output to extract port_number -> port_name.
///
/// Example output:
/// ```text
/// system@ovs-system:
///   lookups: hit:123 missed:45 lost:0
///   flows: 10
///   masks: hit:123 total:5 hit/pkt:1.00
///   port 0: ovs-system (internal)
///   port 1: br-int (internal)
///   port 2: vxlan_sys_4789 (vxlan: ...)
///   port 3: tap12345
/// ```
pub(crate) fn parse_ovs_dpctl_show(output: &str) -> Vec<(u32, String)> {
    let mut ports = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();

        // Match lines like "port 3: tap12345" or "port 2: vxlan_sys_4789 (vxlan: ...)"
        if let Some(rest) = trimmed.strip_prefix("port ") {
            if let Some((num_str, after_colon)) = rest.split_once(": ") {
                if let Ok(port_number) = num_str.trim().parse::<u32>() {
                    // Port name is everything before the first space or parenthesis
                    let port_name = after_colon
                        .split_once(' ')
                        .map(|(name, _)| name)
                        .unwrap_or(after_colon)
                        .trim();
                    ports.push((port_number, port_name.to_string()));
                }
            }
        }
    }

    ports
}

/// Parse `ovs-vsctl show` output to extract port_name -> tunnel remote_ip.
///
/// Example output:
/// ```text
/// 1a2b3c4d-...
///     Bridge br-int
///         Port vxlan-10.0.0.2
///             Interface vxlan-10.0.0.2
///                 type: vxlan
///                 options: {remote_ip="10.0.0.2"}
///         Port br-int
///             Interface br-int
///                 type: internal
///         Port gre-fd00::2
///             Interface gre-fd00::2
///                 type: gre
///                 options: {remote_ip="fd00::2"}
/// ```
pub(crate) fn parse_ovs_vsctl_show(output: &str) -> HashMap<String, String> {
    let mut tunnel_map = HashMap::new();
    let mut current_interface: Option<String> = None;

    for line in output.lines() {
        let trimmed = line.trim();

        // Reset interface context on Port/Bridge lines. This must come
        // before the Interface/options checks to prevent misattributing
        // tunnel IPs if `options:` appears before `Interface` in
        // malformed output.
        if trimmed.starts_with("Port ") || trimmed.starts_with("Bridge ") {
            current_interface = None;
            continue;
        }

        if let Some(iface_name) = trimmed.strip_prefix("Interface ") {
            current_interface = Some(iface_name.trim().to_string());
            continue;
        }

        if trimmed.starts_with("options:") {
            if let Some(ref iface) = current_interface {
                if let Some(remote_ip) = extract_remote_ip(trimmed) {
                    tunnel_map.insert(iface.clone(), remote_ip);
                }
            }
        }
    }

    tunnel_map
}

/// Extract remote_ip value from an OVS options line.
///
/// Handles formats like:
/// - `options: {remote_ip="10.0.0.2"}`
/// - `options: {remote_ip="fd00::2", key=flow}`
/// - `options: {remote_ip=flow}` -> returns None (flow-based tunnels)
fn extract_remote_ip(options_line: &str) -> Option<String> {
    // Find remote_ip= in the options
    let remote_ip_start = options_line.find("remote_ip=")?;
    let after_key = &options_line[remote_ip_start + "remote_ip=".len()..];

    // Handle quoted value: remote_ip="10.0.0.2"
    if let Some(rest) = after_key.strip_prefix('"') {
        let end = rest.find('"')?;
        let ip = &rest[..end];
        // "flow" means OVN flow-based tunnel, no static remote IP
        if ip == "flow" {
            return None;
        }
        return Some(ip.to_string());
    }

    // Handle unquoted value: remote_ip=flow or remote_ip=10.0.0.2
    let end = after_key.find([',', '}']).unwrap_or(after_key.len());
    let ip = &after_key[..end];
    if ip == "flow" {
        return None;
    }
    Some(ip.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dpctl_show_typical_output() {
        let output = "\
system@ovs-system:
  lookups: hit:123456 missed:789 lost:0
  flows: 42
  masks: hit:123456 total:8 hit/pkt:1.50
  port 0: ovs-system (internal)
  port 1: br-int (internal)
  port 2: vxlan_sys_4789 (vxlan: packet_type=ptap)
  port 3: tap-vm1
  port 4: patch-br-ex (patch: peer=patch-br-int)
";
        let ports = parse_ovs_dpctl_show(output);

        assert_eq!(ports.len(), 5);
        assert_eq!(ports[0], (0, "ovs-system".to_string()));
        assert_eq!(ports[1], (1, "br-int".to_string()));
        assert_eq!(ports[2], (2, "vxlan_sys_4789".to_string()));
        assert_eq!(ports[3], (3, "tap-vm1".to_string()));
        assert_eq!(ports[4], (4, "patch-br-ex".to_string()));
    }

    #[test]
    fn parse_vsctl_show_multi_bridge() {
        let output = "\
uuid
    Bridge br-int
        Port vxlan-10.0.0.2
            Interface vxlan-10.0.0.2
                type: vxlan
                options: {remote_ip=\"10.0.0.2\"}
        Port br-int
            Interface br-int
                type: internal
    Bridge br-ex
        Port br-ex
            Interface br-ex
                type: internal
        Port patch-to-br-int
            Interface patch-to-br-int
                type: patch
                options: {peer=patch-to-br-ex}
        Port gre-10.0.0.3
            Interface gre-10.0.0.3
                type: gre
                options: {remote_ip=\"10.0.0.3\"}
";
        let tunnels = parse_ovs_vsctl_show(output);

        assert_eq!(tunnels.len(), 2);
        assert_eq!(tunnels.get("vxlan-10.0.0.2"), Some(&"10.0.0.2".to_string()));
        assert_eq!(tunnels.get("gre-10.0.0.3"), Some(&"10.0.0.3".to_string()));
        // Internal ports, patch ports (options without remote_ip) must not appear
        assert_eq!(tunnels.get("br-int"), None);
        assert_eq!(tunnels.get("br-ex"), None);
        assert_eq!(tunnels.get("patch-to-br-int"), None);
    }

    #[test]
    fn extract_remote_ip_flow() {
        assert_eq!(
            extract_remote_ip("options: {remote_ip=flow, key=flow}"),
            None
        );
        assert_eq!(extract_remote_ip("options: {remote_ip=\"flow\"}"), None);
    }

    #[test]
    fn extract_remote_ip_unquoted_ip() {
        // The unquoted non-flow branch: remote_ip=10.0.0.2 without quotes
        assert_eq!(
            extract_remote_ip("options: {remote_ip=10.0.0.2}"),
            Some("10.0.0.2".to_string())
        );
        assert_eq!(
            extract_remote_ip("options: {remote_ip=10.0.0.2, key=flow}"),
            Some("10.0.0.2".to_string())
        );
    }

    #[test]
    fn build_interface_mappings_filters_link_local() {
        let links = vec![IpLinkEntry {
            ifname: "eth0".into(),
            address: Some("aa:bb:cc:dd:ee:ff".into()),
        }];
        let addrs = vec![IpAddrEntry {
            ifname: "eth0".into(),
            addr_info: Some(vec![
                IpAddrInfo {
                    family: "inet".into(),
                    local: "10.0.0.1".into(),
                    scope: Some("global".into()),
                },
                IpAddrInfo {
                    family: "inet6".into(),
                    local: "fe80::1".into(),
                    scope: Some("link".into()),
                },
                IpAddrInfo {
                    family: "inet6".into(),
                    local: "fd00::1".into(),
                    scope: Some("global".into()),
                },
            ]),
        }];

        let mappings = build_interface_mappings(links, addrs);

        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].ipv4_addrs, vec!["10.0.0.1"]);
        // fe80::1 (link-local) must be excluded, fd00::1 (global) kept
        assert_eq!(mappings[0].ipv6_addrs, vec!["fd00::1"]);
    }

    #[test]
    fn build_interface_mappings_interface_without_addrs() {
        // An interface present in links but absent from addrs should still
        // appear with empty address lists.
        let links = vec![IpLinkEntry {
            ifname: "dummy0".into(),
            address: Some("00:11:22:33:44:55".into()),
        }];
        let addrs = Vec::new();

        let mappings = build_interface_mappings(links, addrs);

        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].name, "dummy0");
        assert_eq!(mappings[0].mac, "00:11:22:33:44:55");
        assert!(mappings[0].ipv4_addrs.is_empty());
        assert!(mappings[0].ipv6_addrs.is_empty());
    }

    #[test]
    fn build_interface_mappings_no_mac() {
        // Loopback and some virtual interfaces report no MAC in
        // `ip -j link show` (address field is null).
        let links = vec![IpLinkEntry {
            ifname: "lo".into(),
            address: None,
        }];
        let addrs = vec![IpAddrEntry {
            ifname: "lo".into(),
            addr_info: Some(vec![IpAddrInfo {
                family: "inet".into(),
                local: "127.0.0.1".into(),
                scope: Some("host".into()),
            }]),
        }];

        let mappings = build_interface_mappings(links, addrs);

        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].name, "lo");
        assert_eq!(mappings[0].mac, "");
        assert_eq!(mappings[0].ipv4_addrs, vec!["127.0.0.1"]);
    }
}
