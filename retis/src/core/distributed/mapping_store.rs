//! Aggregator-side storage for node mapping data.
//!
//! The [`MappingStore`] maintains an in-memory index of all connected nodes'
//! interface and OVS port configurations. It supports two key lookups:
//!
//! 1. **MAC -> node_id**: Given an Ethernet MAC, find which node owns it.
//! 2. **OVS port -> node_id**: Given a node and OVS port number,
//!    resolve directly to the destination node.
//!
//! OVS tunnel resolution is pre-computed at index-build time: each tunnel
//! port's remote IP is resolved to a node_id during `rebuild_indexes()`,
//! so query-time lookup is a single HashMap access.
//!
//! All indexes are rebuilt from scratch on each update to avoid stale
//! partial state. This is acceptable because updates are infrequent (~30s)
//! and the data set is small (typically 2-10 nodes).

use std::collections::HashMap;
use std::sync::RwLock;

use log::warn;
use uuid::Uuid;

use super::node_mapping::NodeMappingSnapshot;

/// Thread-safe mapping store for node topology data.
///
/// Shared across connection handler threads via `Arc<MappingStore>`.
/// Uses `RwLock` for concurrent read access during journey building
/// with exclusive write access during mapping updates.
pub(crate) struct MappingStore {
    inner: RwLock<MappingStoreInner>,
}

struct MappingStoreInner {
    /// node_id -> latest snapshot
    snapshots: HashMap<Uuid, NodeMappingSnapshot>,
    /// MAC address -> node_id. Used for underlay hop resolution when
    /// OVS tunnel data is unavailable (provider/flat networks).
    mac_to_node: HashMap<String, Uuid>,
    /// (node_id, port_number) -> destination node_id. Pre-resolved at
    /// index-build time by looking up each tunnel port's remote IP in
    /// the IP -> node_id index. Only tunnel ports with a resolvable
    /// remote IP appear in this map.
    ovs_port_to_node: HashMap<(Uuid, u32), Uuid>,
}

impl MappingStore {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(MappingStoreInner {
                snapshots: HashMap::new(),
                mac_to_node: HashMap::new(),
                ovs_port_to_node: HashMap::new(),
            }),
        }
    }

    /// Store a new mapping snapshot and rebuild all indexes.
    ///
    /// Replaces any existing snapshot for the same node_id.
    pub fn update(&self, snapshot: NodeMappingSnapshot) {
        let node_id = Uuid::from_bytes(snapshot.node_id);
        let mut inner = self.inner.write().expect("mapping store lock not poisoned");

        inner.snapshots.insert(node_id, snapshot);
        rebuild_indexes(&mut inner);
    }

    /// Resolve an OVS port to a destination node.
    ///
    /// Returns `None` if:
    /// - The port is not in the mapping (unknown port)
    /// - The port is not a tunnel port (local, internal, patch)
    /// - The tunnel's remote IP didn't match any known node at build time
    pub fn resolve_ovs_port(&self, node_id: Uuid, port: u32) -> Option<Uuid> {
        let inner = self.inner.read().expect("mapping store lock not poisoned");
        inner.ovs_port_to_node.get(&(node_id, port)).copied()
    }

    /// Resolve a MAC address to a node_id.
    ///
    /// Used for underlay hop resolution: at TX probe points, the Ethernet
    /// destination MAC identifies the next L2 hop. If that hop is another
    /// retis node, this returns its node_id.
    pub fn resolve_mac(&self, mac: &str) -> Option<Uuid> {
        let inner = self.inner.read().expect("mapping store lock not poisoned");
        inner.mac_to_node.get(mac).copied()
    }

    /// Remove a node's snapshot and rebuild indexes.
    ///
    /// Called on session termination to clean up stale data.
    pub fn remove_node(&self, node_id: Uuid) {
        let mut inner = self.inner.write().expect("mapping store lock not poisoned");

        if inner.snapshots.remove(&node_id).is_some() {
            rebuild_indexes(&mut inner);
        }
    }

    /// Returns the number of nodes currently in the store.
    #[cfg(test)]
    fn node_count(&self) -> usize {
        self.inner
            .read()
            .expect("mapping store lock not poisoned")
            .snapshots
            .len()
    }
}

/// Rebuild all derived indexes from the current set of snapshots.
///
/// This is a full rebuild rather than incremental update to avoid
/// stale entries when a node's configuration changes (e.g., IP
/// reassignment between nodes).
///
/// Uses two passes over the snapshots:
///
/// 1. **Pass 1 (addresses)**: Build the IP -> node_id and MAC -> node_id
///    indexes from all interface data.
///
/// 2. **Pass 2 (OVS ports)**: For each tunnel port, look up its remote
///    IP in the (now-complete) IP index to pre-resolve the destination
///    node_id. Two passes are necessary because a single pass would fail
///    when Node A's tunnel points to Node B's IP but Node B hasn't been
///    processed yet.
///
/// Snapshots are processed in ascending `timestamp_ns` order so that
/// when two nodes claim the same address, the most recent snapshot
/// wins deterministically.
fn rebuild_indexes(inner: &mut MappingStoreInner) {
    inner.mac_to_node.clear();
    inner.ovs_port_to_node.clear();

    // Sort by timestamp so that the most recent snapshot's values take
    // precedence on conflict.
    let mut ordered: Vec<_> = inner.snapshots.iter().collect();
    ordered.sort_by_key(|(_, snap)| snap.timestamp_ns);

    // Pass 1: Build address indexes (IP + MAC) from all interfaces.
    let mut ip_to_node: HashMap<String, Uuid> = HashMap::new();

    for (&node_id, snapshot) in &ordered {
        for iface in &snapshot.interfaces {
            for ip in &iface.ipv4_addrs {
                insert_mapping(&mut ip_to_node, ip.clone(), node_id, "IP");
            }
            for ip in &iface.ipv6_addrs {
                insert_mapping(&mut ip_to_node, ip.clone(), node_id, "IP");
            }

            // Skip empty and all-zero MACs, tunnel/virtual interfaces
            // (e.g., vxlan_sys_4789) often report 00:00:00:00:00:00.
            if !iface.mac.is_empty() && iface.mac != "00:00:00:00:00:00" {
                insert_mapping(&mut inner.mac_to_node, iface.mac.clone(), node_id, "MAC");
            }
        }
    }

    // Pass 2: Resolve OVS tunnel ports against the complete IP index.
    for (&node_id, snapshot) in &ordered {
        for port in &snapshot.ovs_ports {
            if let Some(remote_ip) = &port.tunnel_remote_ip {
                if let Some(&dest_node) = ip_to_node.get(remote_ip.as_str()) {
                    inner
                        .ovs_port_to_node
                        .insert((node_id, port.port_number), dest_node);
                }
            }
        }
    }
}

/// Insert a key -> node_id mapping, warning on conflicts.
fn insert_mapping(index: &mut HashMap<String, Uuid>, key: String, node_id: Uuid, kind: &str) {
    if let Some(&existing) = index.get(&key) {
        if existing != node_id {
            warn!(
                "{} {} claimed by nodes {} and {}; using most recent snapshot",
                kind, key, existing, node_id
            );
        }
    }
    index.insert(key, node_id);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::distributed::node_mapping::{InterfaceMapping, OvsPortMapping};

    fn node_a() -> Uuid {
        Uuid::from_bytes([0xAA; 16])
    }
    fn node_b() -> Uuid {
        Uuid::from_bytes([0xBB; 16])
    }
    fn node_c() -> Uuid {
        Uuid::from_bytes([0xCC; 16])
    }

    fn create_snapshot(
        node_id: Uuid,
        interfaces: Vec<InterfaceMapping>,
        ovs_ports: Vec<OvsPortMapping>,
    ) -> NodeMappingSnapshot {
        create_snapshot_at(node_id, 1_700_000_000_000_000_000, interfaces, ovs_ports)
    }

    fn create_snapshot_at(
        node_id: Uuid,
        timestamp_ns: i64,
        interfaces: Vec<InterfaceMapping>,
        ovs_ports: Vec<OvsPortMapping>,
    ) -> NodeMappingSnapshot {
        NodeMappingSnapshot {
            node_id: *node_id.as_bytes(),
            timestamp_ns,
            interfaces,
            ovs_ports,
        }
    }

    fn create_interface(name: &str, ipv4: &[&str], ipv6: &[&str]) -> InterfaceMapping {
        create_interface_with_mac(name, "00:00:00:00:00:00", ipv4, ipv6)
    }

    fn create_interface_with_mac(
        name: &str,
        mac: &str,
        ipv4: &[&str],
        ipv6: &[&str],
    ) -> InterfaceMapping {
        InterfaceMapping {
            name: name.to_string(),
            mac: mac.to_string(),
            ipv4_addrs: ipv4.iter().map(|s| s.to_string()).collect(),
            ipv6_addrs: ipv6.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn create_tunnel_port(port_number: u32, name: &str, remote_ip: &str) -> OvsPortMapping {
        OvsPortMapping {
            port_number,
            port_name: name.to_string(),
            tunnel_remote_ip: Some(remote_ip.to_string()),
        }
    }

    fn create_local_port(port_number: u32, name: &str) -> OvsPortMapping {
        OvsPortMapping {
            port_number,
            port_name: name.to_string(),
            tunnel_remote_ip: None,
        }
    }

    #[test]
    fn resolve_ovs_tunnel_port_to_node() {
        let store = MappingStore::new();

        // Node A has a VXLAN tunnel to 10.0.0.2
        store.update(create_snapshot(
            node_a(),
            vec![create_interface("eth0", &["10.0.0.1"], &[])],
            vec![create_tunnel_port(3, "vxlan-10.0.0.2", "10.0.0.2")],
        ));

        // Node B owns 10.0.0.2
        store.update(create_snapshot(
            node_b(),
            vec![create_interface("eth0", &["10.0.0.2"], &[])],
            vec![create_tunnel_port(3, "vxlan-10.0.0.1", "10.0.0.1")],
        ));

        // Node A port 3 -> tunnel to 10.0.0.2 -> node B
        assert_eq!(store.resolve_ovs_port(node_a(), 3), Some(node_b()));
        // Node B port 3 -> tunnel to 10.0.0.1 -> node A
        assert_eq!(store.resolve_ovs_port(node_b(), 3), Some(node_a()));
    }

    #[test]
    fn resolve_ovs_non_tunnel_port_returns_none() {
        let store = MappingStore::new();
        store.update(create_snapshot(
            node_a(),
            vec![create_interface("eth0", &["10.0.0.1"], &[])],
            vec![create_local_port(1, "br-int")],
        ));

        assert_eq!(store.resolve_ovs_port(node_a(), 1), None);
    }

    #[test]
    fn resolve_ovs_tunnel_to_unknown_ip_returns_none() {
        let store = MappingStore::new();
        store.update(create_snapshot(
            node_a(),
            vec![create_interface("eth0", &["10.0.0.1"], &[])],
            // Tunnel points to an IP that no known node owns
            vec![create_tunnel_port(3, "vxlan-remote", "10.0.0.99")],
        ));

        assert_eq!(store.resolve_ovs_port(node_a(), 3), None);
    }

    #[test]
    fn remove_node_cleans_up_indexes() {
        let store = MappingStore::new();
        store.update(create_snapshot(
            node_a(),
            vec![create_interface_with_mac(
                "eth0",
                "aa:bb:cc:dd:ee:01",
                &["10.0.0.1"],
                &[],
            )],
            vec![create_tunnel_port(3, "vxlan-b", "10.0.0.2")],
        ));
        store.update(create_snapshot(
            node_b(),
            vec![create_interface_with_mac(
                "eth0",
                "aa:bb:cc:dd:ee:02",
                &["10.0.0.2"],
                &[],
            )],
            vec![],
        ));

        assert_eq!(store.node_count(), 2);
        assert_eq!(store.resolve_mac("aa:bb:cc:dd:ee:01"), Some(node_a()));
        assert_eq!(store.resolve_ovs_port(node_a(), 3), Some(node_b()));

        store.remove_node(node_a());

        assert_eq!(store.node_count(), 1);
        assert_eq!(store.resolve_mac("aa:bb:cc:dd:ee:01"), None);
        assert_eq!(store.resolve_mac("aa:bb:cc:dd:ee:02"), Some(node_b()));
        // OVS port lookup for removed node returns None
        assert_eq!(store.resolve_ovs_port(node_a(), 3), None);
    }

    #[test]
    fn update_replaces_previous_snapshot() {
        let store = MappingStore::new();

        // First snapshot: node A has MAC aa:...:01
        store.update(create_snapshot(
            node_a(),
            vec![create_interface_with_mac(
                "eth0",
                "aa:bb:cc:dd:ee:01",
                &["10.0.0.1"],
                &[],
            )],
            vec![],
        ));
        assert_eq!(store.resolve_mac("aa:bb:cc:dd:ee:01"), Some(node_a()));

        // Second snapshot: node A's MAC changed
        store.update(create_snapshot(
            node_a(),
            vec![create_interface_with_mac(
                "eth0",
                "aa:bb:cc:dd:ee:99",
                &["10.0.0.99"],
                &[],
            )],
            vec![],
        ));

        // Old MAC should no longer resolve
        assert_eq!(store.resolve_mac("aa:bb:cc:dd:ee:01"), None);
        assert_eq!(store.resolve_mac("aa:bb:cc:dd:ee:99"), Some(node_a()));
    }

    #[test]
    fn three_node_ovs_chain_resolution() {
        let store = MappingStore::new();

        // Hyp1 (node_a) -> tunnel to Hyp2 (node_b) on port 5
        // Hyp2 (node_b) -> tunnel to Hyp1 (node_a) on port 5, tunnel to Hyp3 (node_c) on port 6
        // Hyp3 (node_c) -> tunnel to Hyp2 (node_b) on port 5
        store.update(create_snapshot(
            node_a(),
            vec![create_interface("eth0", &["10.0.0.1"], &[])],
            vec![create_tunnel_port(5, "vxlan-hyp2", "10.0.0.2")],
        ));
        store.update(create_snapshot(
            node_b(),
            vec![create_interface("eth0", &["10.0.0.2"], &[])],
            vec![
                create_tunnel_port(5, "vxlan-hyp1", "10.0.0.1"),
                create_tunnel_port(6, "vxlan-hyp3", "10.0.0.3"),
            ],
        ));
        store.update(create_snapshot(
            node_c(),
            vec![create_interface("eth0", &["10.0.0.3"], &[])],
            vec![create_tunnel_port(5, "vxlan-hyp2", "10.0.0.2")],
        ));

        // Hyp1 port 5 -> Hyp2
        assert_eq!(store.resolve_ovs_port(node_a(), 5), Some(node_b()));
        // Hyp2 port 5 -> Hyp1, port 6 -> Hyp3
        assert_eq!(store.resolve_ovs_port(node_b(), 5), Some(node_a()));
        assert_eq!(store.resolve_ovs_port(node_b(), 6), Some(node_c()));
        // Hyp3 port 5 -> Hyp2
        assert_eq!(store.resolve_ovs_port(node_c(), 5), Some(node_b()));
    }

    #[test]
    fn zero_mac_is_filtered_from_index() {
        let store = MappingStore::new();
        // create_interface uses the all-zero MAC by default, which
        // should be excluded from the index (tunnel/virtual interfaces
        // commonly report 00:00:00:00:00:00).
        store.update(create_snapshot(
            node_a(),
            vec![create_interface("eth0", &["10.0.0.1"], &[])],
            vec![],
        ));

        assert_eq!(store.resolve_mac("00:00:00:00:00:00"), None);
    }

    #[test]
    fn resolve_mac_conflict_uses_most_recent() {
        let store = MappingStore::new();

        // Node A claims MAC at t=100.
        store.update(create_snapshot_at(
            node_a(),
            100,
            vec![create_interface_with_mac(
                "eth0",
                "aa:bb:cc:dd:ee:01",
                &["10.0.0.1"],
                &[],
            )],
            vec![],
        ));

        // Node B claims the same MAC at t=200 (more recent).
        store.update(create_snapshot_at(
            node_b(),
            200,
            vec![create_interface_with_mac(
                "eth0",
                "aa:bb:cc:dd:ee:01",
                &["10.0.0.2"],
                &[],
            )],
            vec![],
        ));

        // Most recent snapshot (node B) wins deterministically.
        assert_eq!(store.resolve_mac("aa:bb:cc:dd:ee:01"), Some(node_b()));

        // Reversing insertion order should not change the result.
        let store2 = MappingStore::new();
        store2.update(create_snapshot_at(
            node_b(),
            200,
            vec![create_interface_with_mac(
                "eth0",
                "aa:bb:cc:dd:ee:01",
                &["10.0.0.2"],
                &[],
            )],
            vec![],
        ));
        store2.update(create_snapshot_at(
            node_a(),
            100,
            vec![create_interface_with_mac(
                "eth0",
                "aa:bb:cc:dd:ee:01",
                &["10.0.0.1"],
                &[],
            )],
            vec![],
        ));
        assert_eq!(store2.resolve_mac("aa:bb:cc:dd:ee:01"), Some(node_b()));
    }
}
