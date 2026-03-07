//! Probe direction classification for kernel probe points.
//!
//! Classifies probe points (kprobe, tracepoint, etc.) as TX or RX based
//! on the kernel function name. Used by both causality validation (to infer
//! node roles) and event ingestion (to decide whether MAC-based hop
//! resolution applies).

/// Direction of a probe point relative to packet flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeDirection {
    /// Packet is being transmitted (leaving the node).
    Tx,
    /// Packet is being received (arriving at the node).
    Rx,
    /// Direction cannot be determined from the probe name.
    Unknown,
}

/// Known TX probe points: functions where the kernel is sending a packet.
const TX_PROBES: &[&str] = &[
    "dev_queue_xmit",
    "dev_hard_start_xmit",
    "__dev_queue_xmit",
    "tcp_sendmsg",
    "tcp_write_xmit",
    "udp_sendmsg",
    "udp_send_skb",
    "ip_output",
    "ip_local_out",
    "ip_finish_output",
    "ip6_output",
    "ip6_local_out",
    "ip6_finish_output",
    "__ip_queue_xmit",
    "ip_queue_xmit",
    "kfree_skb", // Drop is terminal, treated as TX (packet left processing)
    "skb_drop_reason",
    "net_dev_queue",      // tracepoint, earliest TX point (enters qdisc)
    "net_dev_start_xmit", // tracepoint
    "net_dev_xmit",       // tracepoint
];

/// Known RX probe points: functions where the kernel is receiving a packet.
const RX_PROBES: &[&str] = &[
    "netif_receive_skb",
    "netif_receive_skb_core",
    "__netif_receive_skb",
    "__netif_receive_skb_core",
    "tcp_v4_rcv",
    "tcp_v6_rcv",
    "udp_rcv",
    "udp_queue_rcv_skb",
    "ip_rcv",
    "ip_rcv_finish",
    "ip_local_deliver",
    "ip_local_deliver_finish",
    "ip6_rcv",
    "ipv6_rcv",
    "ip6_rcv_finish",
    "napi_gro_receive",
    "netif_rx",
];

/// Classify a probe point string into a direction.
///
/// Extracts the function name from probe point formats like:
/// - `kprobe:tcp_sendmsg`
/// - `tracepoint:net:net_dev_xmit`
/// - `raw_tracepoint:tcp_v4_rcv`
/// - `kretprobe:ip_rcv`
///
/// Falls back to `Unknown` if the function name doesn't match any known probe.
pub(crate) fn classify_probe(probe_point: &str) -> ProbeDirection {
    let func_name = extract_function_name(probe_point);

    if TX_PROBES.contains(&func_name) {
        return ProbeDirection::Tx;
    }
    if RX_PROBES.contains(&func_name) {
        return ProbeDirection::Rx;
    }

    ProbeDirection::Unknown
}

/// Extract the bare function name from a probe point string.
///
/// Handles formats: `kprobe:func`, `kretprobe:func`,
/// `tracepoint:subsys:event`, `raw_tracepoint:func`.
fn extract_function_name(probe_point: &str) -> &str {
    probe_point.rsplit(':').next().unwrap_or(probe_point)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_probe_direction() {
        // Single-colon format (kprobe)
        assert_eq!(classify_probe("kprobe:tcp_sendmsg"), ProbeDirection::Tx);
        assert_eq!(classify_probe("kprobe:tcp_v4_rcv"), ProbeDirection::Rx);

        // Double-colon format (tracepoint): exercises rsplit extracting
        // the last segment past two colons.
        assert_eq!(
            classify_probe("tracepoint:net:net_dev_xmit"),
            ProbeDirection::Tx
        );

        // Unrecognized function falls through to Unknown.
        assert_eq!(
            classify_probe("kprobe:some_random_func"),
            ProbeDirection::Unknown
        );
    }
}
