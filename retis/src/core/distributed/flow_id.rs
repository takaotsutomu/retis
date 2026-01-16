//! Flow ID extraction from packet data.
//!
//! Extracts the 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol) from
//! raw packet bytes for grouping events by connection.

use std::fmt;
use std::net::IpAddr;

use retis_pnet::{
    ethernet::{EtherType, EtherTypes, EthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    ipv6::{ExtensionIterable, ExtensionPacket, Ipv6Packet},
    tcp::TcpPacket,
    udp::UdpPacket,
    vlan::VlanPacket,
    Packet, PacketSize,
};

/// Maximum VLAN tag depth to traverse before giving up.
/// Prevents stack overflow from maliciously crafted packets.
const MAX_VLAN_DEPTH: usize = 8;

/// A normalized 5-tuple flow identifier.
///
/// Used for grouping events by network connection. The flow ID can be
/// canonicalized to match both directions
/// of a bidirectional flow (e.g., request and response packets).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct FlowId {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

impl FlowId {
    /// Extract a flow ID from raw packet bytes.
    ///
    /// Returns `None` if the packet is not a recognized IP packet or if
    /// parsing fails (truncated, unsupported encapsulation, etc.).
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let eth = EthernetPacket::new(data)?;
        Self::extract_from_ethernet(&eth)
    }

    fn extract_from_ethernet(eth: &EthernetPacket<'_>) -> Option<Self> {
        Self::traverse_vlan(eth.get_ethertype(), eth.payload(), 0)
    }

    /// Traverse VLAN tags to find the IP layer.
    ///
    /// Depth limit prevents stack overflow from maliciously crafted packets
    /// with excessive VLAN nesting.
    fn traverse_vlan(etype: EtherType, payload: &[u8], depth: usize) -> Option<Self> {
        if depth >= MAX_VLAN_DEPTH {
            return None;
        }

        match etype {
            EtherTypes::Vlan | EtherTypes::PBridge => {
                let vlan = VlanPacket::new(payload)?;
                // Use .get() to safely slice, avoiding panic on malformed packets
                let inner_payload = payload.get(vlan.packet_size()..)?;
                Self::traverse_vlan(vlan.get_ethertype(), inner_payload, depth + 1)
            }
            EtherTypes::Ipv4 => Self::extract_from_ipv4(payload),
            EtherTypes::Ipv6 => Self::extract_from_ipv6(payload),
            _ => None,
        }
    }

    fn extract_from_ipv4(payload: &[u8]) -> Option<Self> {
        let ip = Ipv4Packet::new(payload)?;

        let (src_port, dst_port) = match ip.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => {
                let tcp = TcpPacket::new(ip.payload())?;
                (tcp.get_source(), tcp.get_destination())
            }
            IpNextHeaderProtocols::Udp => {
                let udp = UdpPacket::new(ip.payload())?;
                (udp.get_source(), udp.get_destination())
            }
            // For ICMP and other protocols, use port 0
            _ => (0, 0),
        };

        Some(FlowId {
            src_ip: IpAddr::V4(ip.get_source()),
            dst_ip: IpAddr::V4(ip.get_destination()),
            src_port,
            dst_port,
            protocol: ip.get_next_level_protocol().0,
        })
    }

    /// Traverses IPv6 extension headers to find the transport layer protocol.
    fn extract_from_ipv6(payload: &[u8]) -> Option<Self> {
        let ip = Ipv6Packet::new(payload)?;

        // Traverse extension headers to find the actual transport protocol.
        // ExtensionIterable handles hop-by-hop, routing, fragment, AH, ESP,
        // destination options, mobility, HIP, and shim6 headers.
        let mut protocol = ip.get_next_header();
        let mut transport_payload = ip.payload();

        for ext in ExtensionIterable::from(&ip) {
            let ext: ExtensionPacket<'_> = ext;
            protocol = ext.get_next_header();
            transport_payload = transport_payload.get(ext.packet_size()..)?;
        }

        let (src_port, dst_port) = match protocol {
            IpNextHeaderProtocols::Tcp => {
                let tcp = TcpPacket::new(transport_payload)?;
                (tcp.get_source(), tcp.get_destination())
            }
            IpNextHeaderProtocols::Udp => {
                let udp = UdpPacket::new(transport_payload)?;
                (udp.get_source(), udp.get_destination())
            }
            _ => (0, 0),
        };

        Some(FlowId {
            src_ip: IpAddr::V6(ip.get_source()),
            dst_ip: IpAddr::V6(ip.get_destination()),
            src_port,
            dst_port,
            protocol: protocol.0,
        })
    }

    /// Return a canonicalized version of the flow ID.
    ///
    /// The canonical form always has the "smaller" endpoint first, enabling
    /// bidirectional flow matching (so request and response packets get the
    /// same canonical flow ID).
    #[allow(dead_code)]
    pub fn canonicalize(&self) -> Self {
        if (self.src_ip, self.src_port) <= (self.dst_ip, self.dst_port) {
            self.clone()
        } else {
            FlowId {
                src_ip: self.dst_ip,
                dst_ip: self.src_ip,
                src_port: self.dst_port,
                dst_port: self.src_port,
                protocol: self.protocol,
            }
        }
    }
}

impl fmt::Display for FlowId {
    /// Format the flow ID as a string.
    ///
    /// Uses RFC 3986 bracket notation for IPv6 addresses to avoid ambiguity
    /// when ports are present:
    /// - IPv4 with ports: `tcp:192.168.1.1:80->10.0.0.1:443`
    /// - IPv6 with ports: `tcp:[2001:db8::1]:80->[2001:db8::2]:443`
    /// - Without ports: `icmp:192.168.1.1->10.0.0.1` or `icmpv6:2001:db8::1->2001:db8::2`
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let proto = match self.protocol {
            1 => "icmp",
            6 => "tcp",
            17 => "udp",
            47 => "gre",
            58 => "icmpv6",
            132 => "sctp",
            _ => "other",
        };

        if self.src_port == 0 && self.dst_port == 0 {
            // No ports (e.g., ICMP, GRE) - no brackets needed since there's
            // no port delimiter ambiguity
            write!(f, "{}:{}->{}", proto, self.src_ip, self.dst_ip)
        } else {
            // With ports - use brackets for IPv6 to avoid ambiguity
            match (&self.src_ip, &self.dst_ip) {
                (IpAddr::V6(src), IpAddr::V6(dst)) => {
                    write!(
                        f,
                        "{}:[{}]:{}->[{}]:{}",
                        proto, src, self.src_port, dst, self.dst_port
                    )
                }
                _ => {
                    write!(
                        f,
                        "{}:{}:{}->{}:{}",
                        proto, self.src_ip, self.src_port, self.dst_ip, self.dst_port
                    )
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal Ethernet + IPv4 + TCP packet for testing.
    fn build_ipv4_tcp_packet(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut packet = Vec::new();

        // Ethernet header (14 bytes)
        packet.extend_from_slice(&[0u8; 6]); // dst mac
        packet.extend_from_slice(&[0u8; 6]); // src mac
        packet.extend_from_slice(&[0x08, 0x00]); // ethertype: IPv4

        // IPv4 header (20 bytes minimum)
        packet.push(0x45); // version + IHL
        packet.push(0x00); // DSCP + ECN
        packet.extend_from_slice(&[0x00, 0x28]); // total length (40 bytes)
        packet.extend_from_slice(&[0x00, 0x00]); // identification
        packet.extend_from_slice(&[0x00, 0x00]); // flags + fragment offset
        packet.push(64); // TTL
        packet.push(6); // protocol: TCP
        packet.extend_from_slice(&[0x00, 0x00]); // checksum
        packet.extend_from_slice(&src_ip); // source IP
        packet.extend_from_slice(&dst_ip); // dest IP

        // TCP header (20 bytes minimum)
        packet.extend_from_slice(&src_port.to_be_bytes()); // source port
        packet.extend_from_slice(&dst_port.to_be_bytes()); // dest port
        packet.extend_from_slice(&[0u8; 16]); // seq, ack, flags, etc.

        packet
    }

    /// Build a VLAN-tagged (802.1Q) Ethernet + IPv4 + TCP packet.
    /// TCI format: 3 bits PCP (priority) + 1 bit DEI + 12 bits VID
    fn build_vlan_tagged_packet(
        vlan_id: u16,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut packet = Vec::new();

        // Ethernet header with VLAN ethertype
        packet.extend_from_slice(&[0u8; 6]); // dst mac
        packet.extend_from_slice(&[0u8; 6]); // src mac
        packet.extend_from_slice(&[0x81, 0x00]); // ethertype: 802.1Q VLAN

        // VLAN tag (4 bytes): TCI (2 bytes) + inner ethertype (2 bytes)
        // TCI: PCP=0, DEI=0, VID=vlan_id
        let vlan_tci = vlan_id & 0x0FFF;
        packet.extend_from_slice(&vlan_tci.to_be_bytes());
        packet.extend_from_slice(&[0x08, 0x00]); // inner ethertype: IPv4

        // IPv4 header
        packet.push(0x45);
        packet.push(0x00);
        packet.extend_from_slice(&[0x00, 0x28]);
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.push(64);
        packet.push(6); // TCP
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.extend_from_slice(&src_ip);
        packet.extend_from_slice(&dst_ip);

        // TCP header
        packet.extend_from_slice(&src_port.to_be_bytes());
        packet.extend_from_slice(&dst_port.to_be_bytes());
        packet.extend_from_slice(&[0u8; 16]);

        packet
    }

    /// Build a double-tagged (802.1ad) packet with stacked VLANs.
    fn build_double_tagged_packet(
        outer_vlan: u16,
        inner_vlan: u16,
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut packet = Vec::new();

        // Ethernet header with 802.1ad (PBridge) ethertype
        packet.extend_from_slice(&[0u8; 6]); // dst mac
        packet.extend_from_slice(&[0u8; 6]); // src mac
        packet.extend_from_slice(&[0x88, 0xa8]); // ethertype: 802.1ad

        // Outer VLAN tag
        let outer_tci = outer_vlan & 0x0FFF;
        packet.extend_from_slice(&outer_tci.to_be_bytes());
        packet.extend_from_slice(&[0x81, 0x00]); // inner ethertype: 802.1Q

        // Inner VLAN tag
        let inner_tci = inner_vlan & 0x0FFF;
        packet.extend_from_slice(&inner_tci.to_be_bytes());
        packet.extend_from_slice(&[0x08, 0x00]); // inner ethertype: IPv4

        // IPv4 header
        packet.push(0x45);
        packet.push(0x00);
        packet.extend_from_slice(&[0x00, 0x28]);
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.push(64);
        packet.push(6); // TCP
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.extend_from_slice(&src_ip);
        packet.extend_from_slice(&dst_ip);

        // TCP header
        packet.extend_from_slice(&src_port.to_be_bytes());
        packet.extend_from_slice(&dst_port.to_be_bytes());
        packet.extend_from_slice(&[0u8; 16]);

        packet
    }

    /// Build an IPv6 packet with a hop-by-hop extension header followed by TCP.
    fn build_ipv6_with_extension_header(
        src_ip: [u8; 16],
        dst_ip: [u8; 16],
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut packet = Vec::new();

        // Ethernet header (14 bytes)
        packet.extend_from_slice(&[0u8; 6]); // dst mac
        packet.extend_from_slice(&[0u8; 6]); // src mac
        packet.extend_from_slice(&[0x86, 0xdd]); // ethertype: IPv6

        // IPv6 header (40 bytes)
        packet.push(0x60); // version (6) + traffic class high nibble
        packet.extend_from_slice(&[0x00, 0x00, 0x00]); // traffic class + flow label
        packet.extend_from_slice(&[0x00, 0x1c]); // payload length (28 = 8 ext + 20 TCP)
        packet.push(0x00); // next header: Hop-by-Hop Options (0)
        packet.push(64); // hop limit
        packet.extend_from_slice(&src_ip); // source IP
        packet.extend_from_slice(&dst_ip); // dest IP

        // Hop-by-Hop extension header (8 bytes minimum)
        packet.push(0x06); // next header: TCP
        packet.push(0x00); // header extension length (0 = 8 bytes total)
        packet.extend_from_slice(&[0x00; 6]); // padding/options

        // TCP header (20 bytes minimum)
        packet.extend_from_slice(&src_port.to_be_bytes());
        packet.extend_from_slice(&dst_port.to_be_bytes());
        packet.extend_from_slice(&[0u8; 16]); // seq, ack, flags, etc.

        packet
    }

    #[test]
    fn extract_tcp_flow() {
        let packet = build_ipv4_tcp_packet([192, 168, 1, 1], [10, 0, 0, 1], 12345, 80);

        let flow = FlowId::from_bytes(&packet).expect("should parse");

        assert_eq!(flow.src_ip, "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(flow.dst_ip, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(flow.src_port, 12345);
        assert_eq!(flow.dst_port, 80);
        assert_eq!(flow.protocol, 6); // TCP
    }

    #[test]
    fn extract_vlan_tagged_flow() {
        let packet = build_vlan_tagged_packet(100, [192, 168, 1, 1], [10, 0, 0, 1], 12345, 80);

        let flow = FlowId::from_bytes(&packet).expect("should parse VLAN-tagged packet");

        assert_eq!(flow.src_ip, "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(flow.dst_ip, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(flow.src_port, 12345);
        assert_eq!(flow.dst_port, 80);
        assert_eq!(flow.protocol, 6);
    }

    #[test]
    fn extract_double_tagged_flow() {
        let packet =
            build_double_tagged_packet(200, 100, [192, 168, 1, 1], [10, 0, 0, 1], 12345, 80);

        let flow = FlowId::from_bytes(&packet).expect("should parse double-tagged packet");

        assert_eq!(flow.src_ip, "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(flow.dst_ip, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(flow.src_port, 12345);
        assert_eq!(flow.dst_port, 80);
    }

    #[test]
    fn extract_ipv6_with_extension_header() {
        // ::1 and ::2 as IPv6 addresses
        let src_ip = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst_ip = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let packet = build_ipv6_with_extension_header(src_ip, dst_ip, 54321, 443);

        let flow = FlowId::from_bytes(&packet).expect("should parse IPv6 with extension header");

        assert_eq!(flow.src_ip, "::1".parse::<IpAddr>().unwrap());
        assert_eq!(flow.dst_ip, "::2".parse::<IpAddr>().unwrap());
        assert_eq!(flow.src_port, 54321);
        assert_eq!(flow.dst_port, 443);
        assert_eq!(flow.protocol, 6); // TCP (after traversing extension header)
    }

    #[test]
    fn canonicalize_orders_correctly() {
        let flow1 = FlowId {
            src_ip: "192.168.1.1".parse().unwrap(),
            dst_ip: "10.0.0.1".parse().unwrap(),
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
        };

        let flow2 = FlowId {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "192.168.1.1".parse().unwrap(),
            src_port: 80,
            dst_port: 12345,
            protocol: 6,
        };

        // Both should canonicalize to the same flow
        assert_eq!(flow1.canonicalize(), flow2.canonicalize());
    }

    #[test]
    fn display_format() {
        let flow = FlowId {
            src_ip: "192.168.1.1".parse().unwrap(),
            dst_ip: "10.0.0.1".parse().unwrap(),
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
        };

        assert_eq!(flow.to_string(), "tcp:192.168.1.1:12345->10.0.0.1:80");
    }

    #[test]
    fn display_icmp_no_ports() {
        let flow = FlowId {
            src_ip: "192.168.1.1".parse().unwrap(),
            dst_ip: "10.0.0.1".parse().unwrap(),
            src_port: 0,
            dst_port: 0,
            protocol: 1, // ICMP
        };

        assert_eq!(flow.to_string(), "icmp:192.168.1.1->10.0.0.1");
    }

    #[test]
    fn display_ipv6_uses_brackets_with_ports() {
        // IPv6 with ports uses RFC 3986 bracket notation
        let flow = FlowId {
            src_ip: "2001:db8::1".parse().unwrap(),
            dst_ip: "2001:db8::2".parse().unwrap(),
            src_port: 443,
            dst_port: 80,
            protocol: 6, // TCP
        };

        assert_eq!(flow.to_string(), "tcp:[2001:db8::1]:443->[2001:db8::2]:80");

        // IPv6 without ports doesn't need brackets (no ambiguity)
        let flow_no_ports = FlowId {
            src_ip: "::1".parse().unwrap(),
            dst_ip: "::2".parse().unwrap(),
            src_port: 0,
            dst_port: 0,
            protocol: 58, // ICMPv6
        };

        assert_eq!(flow_no_ports.to_string(), "icmpv6:::1->::2");
    }

    #[test]
    fn truncated_packet_returns_none() {
        let packet = vec![0u8; 10]; // Too short
        assert!(FlowId::from_bytes(&packet).is_none());
    }

    #[test]
    fn malformed_vlan_packet_returns_none() {
        let mut packet = Vec::new();

        // Ethernet header with VLAN ethertype
        packet.extend_from_slice(&[0u8; 6]); // dst mac
        packet.extend_from_slice(&[0u8; 6]); // src mac
        packet.extend_from_slice(&[0x81, 0x00]); // ethertype: VLAN

        // Truncated VLAN tag (only 1 byte instead of 4)
        packet.push(0x00);

        // Should return None gracefully, not panic
        assert!(FlowId::from_bytes(&packet).is_none());
    }

    #[test]
    fn excessive_vlan_depth_returns_none() {
        // Build packet with too many VLAN tags (exceeds MAX_VLAN_DEPTH)
        let mut packet = Vec::new();

        // Ethernet header
        packet.extend_from_slice(&[0u8; 12]); // MACs
        packet.extend_from_slice(&[0x81, 0x00]); // VLAN ethertype

        // Add MAX_VLAN_DEPTH + 1 VLAN tags
        for _ in 0..MAX_VLAN_DEPTH + 1 {
            packet.extend_from_slice(&[0x00, 0x01]); // TCI
            packet.extend_from_slice(&[0x81, 0x00]); // Another VLAN
        }

        // This should return None due to depth limit
        assert!(FlowId::from_bytes(&packet).is_none());
    }
}
