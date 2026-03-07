//! Node mapping data structures for OVS port -> tunnel -> node resolution.
//!
//! Each collector periodically reports its local interface and OVS port
//! configuration as a [`NodeMappingSnapshot`]. The aggregator uses these
//! snapshots to build an IP -> node_id index and resolve OVS output port
//! actions to remote node identities.

use bincode::{Decode, Encode};

/// Lightweight mapping data reported by each collector.
///
/// Used to resolve OVS port numbers to remote node identities. Collectors
/// send an initial snapshot on registration and periodic updates thereafter.
#[derive(Encode, Decode, Debug, Clone)]
pub(crate) struct NodeMappingSnapshot {
    pub node_id: [u8; 16],
    /// Nanoseconds since Unix epoch when this snapshot was collected.
    pub timestamp_ns: i64,
    pub interfaces: Vec<InterfaceMapping>,
    pub ovs_ports: Vec<OvsPortMapping>,
}

/// Node interface info. Used for IP -> node_id resolution.
#[derive(Encode, Decode, Debug, Clone)]
pub(crate) struct InterfaceMapping {
    pub name: String,
    /// MAC address in colon-separated hex format (e.g., "aa:bb:cc:dd:ee:ff").
    /// Used for underlay hop resolution when OVS tunnel data is unavailable.
    pub mac: String,
    pub ipv4_addrs: Vec<String>,
    pub ipv6_addrs: Vec<String>,
}

/// Maps an OVS datapath port to its tunnel remote IP.
#[derive(Encode, Decode, Debug, Clone)]
pub(crate) struct OvsPortMapping {
    pub port_number: u32,
    /// Join key with `ovs-vsctl show` during discovery; not read after
    /// construction.
    pub port_name: String,
    /// Remote tunnel endpoint IP. `None` for non-tunnel ports (local,
    /// internal, patch ports).
    pub tunnel_remote_ip: Option<String>,
}
