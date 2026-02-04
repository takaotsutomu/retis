"""Integration tests for distributed tracing mode."""

from testlib import Retis


def test_distributed_metadata_present(two_ns_simple, aggregator):
    """Verify events in distributed mode contain distributed metadata."""
    ns = two_ns_simple
    retis = Retis()

    # Collect with distributed mode enabled, connecting to the aggregator.
    retis.collect(
        "-c", "skb",
        "-f", "icmp",
        "-p", "kprobe:ip_rcv",
        "--distributed",
        "--aggregator", aggregator.listen,
    )

    # Generate some traffic.
    ns.run("ns0", "ping", "-c", "1", "10.0.42.2")
    retis.stop()

    events = retis.events()
    assert len(events) > 0, "Expected at least one event"

    # Filter to only eBPF events (exclude startup/internal events).
    ebpf_events = [e for e in events if "kernel" in e]
    assert len(ebpf_events) > 0, "Expected at least one eBPF event"

    # Verify all eBPF events have distributed metadata.
    for event in ebpf_events:
        assert "distributed" in event, (
            f"Event missing 'distributed' field: {event}"
        )
        dist = event["distributed"]

        # Verify required fields are present.
        assert "node_id" in dist, "Missing node_id"
        assert "epoch_ns" in dist, "Missing epoch_ns"
        assert "sync_status" in dist, "Missing sync_status"

        # node_id is serialized as a list of 16 bytes (UUID bytes).
        node_id = dist["node_id"]
        assert isinstance(node_id, list), (
            f"node_id should be list, got {type(node_id)}"
        )
        assert len(node_id) == 16, (
            f"node_id should be 16 bytes (UUID), got {len(node_id)}"
        )
        assert all(0 <= b <= 255 for b in node_id), "node_id bytes invalid"

        # Verify epoch_ns is a reasonable timestamp (after year 2020).
        epoch_ns = dist["epoch_ns"]
        min_epoch_2020 = 1577836800_000_000_000  # 2020-01-01 00:00:00 UTC
        assert epoch_ns > min_epoch_2020, f"epoch_ns {epoch_ns} is too old"


def test_distributed_consistent_node_id(two_ns_simple, aggregator):
    """Verify all events from a single collector have the same node_id."""
    ns = two_ns_simple
    retis = Retis()

    retis.collect(
        "-c", "skb",
        "-f", "icmp",
        "-p", "kprobe:ip_rcv",
        "--distributed",
        "--aggregator", aggregator.listen,
    )

    # Generate multiple packets.
    ns.run("ns0", "ping", "-c", "3", "10.0.42.2")
    retis.stop()

    events = retis.events()

    # Filter to only eBPF events (exclude startup/internal events).
    ebpf_events = [e for e in events if "kernel" in e]
    assert len(ebpf_events) >= 2, "Expected at least 2 eBPF events"

    # All eBPF events should have the same node_id.
    # Convert lists to tuples for hashability.
    node_ids = {tuple(e["distributed"]["node_id"]) for e in ebpf_events}
    assert len(node_ids) == 1, f"Expected single node_id, got {node_ids}"
