//! Integration tests for distributed tracing.
//!
//! These tests validate the wire protocol between collectors and aggregator
//! using raw TCP connections. This approach directly tests the protocol layer
//! without requiring full Event construction.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use super::protocol::*;
use super::*;

fn send_message(stream: &mut TcpStream, sequence: u64, payload: Payload) {
    let msg = Message::new(sequence, 0, payload);
    let encoded = bincode::encode_to_vec(&msg, bincode::config::standard()).unwrap();
    let len = encoded.len() as u32;
    stream.write_all(&len.to_le_bytes()).unwrap();
    stream.write_all(&encoded).unwrap();
    stream.flush().unwrap();
}

fn recv_message(stream: &mut TcpStream) -> Message {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).unwrap();
    let len = u32::from_le_bytes(len_buf) as usize;

    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).unwrap();

    let (msg, _): (Message, _) =
        bincode::decode_from_slice(&buf, bincode::config::standard()).unwrap();
    msg
}

fn register_collector(stream: &mut TcpStream, node_id: [u8; 16], name: &str) -> u64 {
    let register = Register {
        node_id,
        node_name: name.to_string(),
        hostname: "test-host".to_string(),
        retis_version: "test".to_string(),
        kernel_version: "5.15.0".to_string(),
        capabilities: vec![],
    };

    send_message(stream, 0, Payload::Register(register));
    let response = recv_message(stream);

    match response.payload {
        Payload::RegisterAck(ack) => {
            assert!(ack.accepted, "Registration should be accepted");
            ack.session_id
        }
        _ => panic!("Expected RegisterAck"),
    }
}

fn create_test_events(count: usize, node_id: [u8; 16]) -> Vec<WireEvent> {
    // Use current time to avoid TTL expiration in ClickHouse tests.
    // The ClickHouse schema has a 7-day TTL based on epoch_ns.
    let base_epoch_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos() as i64;

    (0..count)
        .map(|i| WireEvent {
            distributed: WireDistributedMetadata {
                node_id,
                epoch_ns: base_epoch_ns + i as i64,
                ntp_offset_ns: 0,
                ntp_uncertainty_ns: 1000,
                sync_status: 0, // Synchronized
            },
            // Minimal valid Event JSON - all fields are Option so empty object works
            event_json: "{}".to_string(),
        })
        .collect()
}

fn send_batch(stream: &mut TcpStream, sequence: u64, batch_id: u64, events: Vec<WireEvent>) {
    let batch = EventBatch {
        batch_id,
        event_count: events.len() as u32,
        events,
    };
    send_message(stream, sequence, Payload::EventBatch(batch));
}

#[test]
fn multi_collector_sends_to_aggregator() {
    let config = AggregatorConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        ..Default::default()
    };

    let backpressure = Arc::new(SharedBackpressure::new());
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = Arc::clone(&shutdown);

    let sink = Box::new(LoggingEventSink::new());
    let mut aggregator = TraceAggregator::new(config, sink, backpressure, shutdown).unwrap();
    let addr = aggregator.local_addr().unwrap();

    let aggregator_handle = thread::spawn(move || {
        aggregator.run().unwrap();
        aggregator.stats()
    });

    thread::sleep(Duration::from_millis(50));

    let mut collector_handles = vec![];
    for i in 0..3u8 {
        let addr = addr;
        let handle = thread::spawn(move || {
            let mut stream = TcpStream::connect(addr).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();

            let mut node_id = [0u8; 16];
            node_id[0] = i;
            let name = format!("node-{}", i);

            register_collector(&mut stream, node_id, &name);

            let events = create_test_events(20, node_id);
            for (batch_idx, chunk) in events.chunks(10).enumerate() {
                send_batch(
                    &mut stream,
                    (batch_idx + 1) as u64,
                    (batch_idx + 1) as u64,
                    chunk.to_vec(),
                );

                let response = recv_message(&mut stream);
                match response.payload {
                    Payload::BatchAck(ack) => {
                        assert!(matches!(ack.status, BatchStatus::Accepted));
                    }
                    _ => panic!("Expected BatchAck"),
                }
            }

            let shutdown_msg = Shutdown {
                reason: ShutdownReason::Shutdown,
                total_events_sent: 20,
                total_batches_sent: 2,
            };
            send_message(&mut stream, 3, Payload::Shutdown(shutdown_msg));
        });
        collector_handles.push(handle);
    }

    for handle in collector_handles {
        handle.join().unwrap();
    }

    thread::sleep(Duration::from_millis(100));
    shutdown_clone.store(true, Ordering::SeqCst);

    let stats = aggregator_handle.join().unwrap();

    // 3 collectors * 20 events = 60 total
    assert!(
        stats.events_received >= 60,
        "Expected 60 events, got {}",
        stats.events_received
    );
}

#[test]
fn collector_reconnects_after_aggregator_restart() {
    // Use a random port to avoid conflicts with other tests.
    let config = AggregatorConfig {
        listen_addr: "127.0.0.1:0".to_string(),
        ..Default::default()
    };

    let backpressure = Arc::new(SharedBackpressure::new());
    let shutdown1 = Arc::new(AtomicBool::new(false));
    let shutdown1_clone = Arc::clone(&shutdown1);

    let sink = Box::new(LoggingEventSink::new());
    let mut aggregator1 =
        TraceAggregator::new(config.clone(), sink, Arc::clone(&backpressure), shutdown1).unwrap();
    let addr = aggregator1.local_addr().unwrap();
    let port = addr.port();

    let aggregator1_handle = thread::spawn(move || {
        aggregator1.run().unwrap();
        aggregator1.stats()
    });

    thread::sleep(Duration::from_millis(100));

    // Connect and send some events
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let node_id = [1u8; 16];
    register_collector(&mut stream, node_id, "test-node");

    let events = create_test_events(10, node_id);
    send_batch(&mut stream, 1, 1, events);
    let _ = recv_message(&mut stream); // BatchAck

    // Stop first aggregator
    shutdown1_clone.store(true, Ordering::SeqCst);
    drop(stream);
    let stats1 = aggregator1_handle.join().unwrap();
    assert_eq!(stats1.events_received, 10);

    thread::sleep(Duration::from_millis(200));

    // Start second aggregator on same port
    let config2 = AggregatorConfig {
        listen_addr: format!("127.0.0.1:{}", port),
        ..Default::default()
    };
    let shutdown2 = Arc::new(AtomicBool::new(false));
    let shutdown2_clone = Arc::clone(&shutdown2);

    let sink2 = Box::new(LoggingEventSink::new());
    let mut aggregator2 =
        TraceAggregator::new(config2, sink2, Arc::clone(&backpressure), shutdown2).unwrap();

    let aggregator2_handle = thread::spawn(move || {
        aggregator2.run().unwrap();
        aggregator2.stats()
    });

    thread::sleep(Duration::from_millis(100));

    // Reconnect and send more events
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    register_collector(&mut stream, node_id, "test-node");

    let events = create_test_events(15, node_id);
    send_batch(&mut stream, 1, 1, events);
    let _ = recv_message(&mut stream);

    let shutdown_msg = Shutdown {
        reason: ShutdownReason::Shutdown,
        total_events_sent: 15,
        total_batches_sent: 1,
    };
    send_message(&mut stream, 2, Payload::Shutdown(shutdown_msg));

    thread::sleep(Duration::from_millis(100));
    shutdown2_clone.store(true, Ordering::SeqCst);
    let stats2 = aggregator2_handle.join().unwrap();

    assert_eq!(
        stats2.events_received, 15,
        "Second aggregator should receive events after reconnection"
    );
}

#[cfg(feature = "test_clickhouse")]
mod clickhouse_tests {
    use super::*;

    #[test]
    fn clickhouse_stores_events() {
        let ch_config = ClickHouseConfig {
            url: "http://localhost:8123".to_string(),
            database: "retis_test".to_string(),
            table: format!("events_test_{}", std::process::id()),
            auto_create_tables: true,
            ..Default::default()
        };

        // Clean up any existing table
        let drop_url = format!(
            "{}/?query={}",
            ch_config.url,
            urlencoding::encode(&format!(
                "DROP TABLE IF EXISTS {}.{}",
                ch_config.database, ch_config.table
            ))
        );
        let _ = ureq::get(&drop_url).call();

        let config = AggregatorConfig {
            listen_addr: "127.0.0.1:0".to_string(),
            ..Default::default()
        };

        let backpressure = Arc::new(SharedBackpressure::new());
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = Arc::clone(&shutdown);

        let sink = Box::new(
            ClickHouseEventSink::new(ch_config.clone(), None, Arc::clone(&backpressure)).unwrap(),
        );

        let mut aggregator = TraceAggregator::new(config, sink, backpressure, shutdown).unwrap();
        let addr = aggregator.local_addr().unwrap();

        let aggregator_handle = thread::spawn(move || {
            aggregator.run().unwrap();
        });

        thread::sleep(Duration::from_millis(100));

        // Send events
        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let node_id = [42u8; 16];
        register_collector(&mut stream, node_id, "clickhouse-test");

        let events = create_test_events(50, node_id);
        for (batch_idx, chunk) in events.chunks(10).enumerate() {
            send_batch(
                &mut stream,
                (batch_idx + 1) as u64,
                (batch_idx + 1) as u64,
                chunk.to_vec(),
            );
            let _ = recv_message(&mut stream);
        }

        let shutdown_msg = Shutdown {
            reason: ShutdownReason::Shutdown,
            total_events_sent: 50,
            total_batches_sent: 5,
        };
        send_message(&mut stream, 6, Payload::Shutdown(shutdown_msg));

        // Allow time for events to be processed and written
        thread::sleep(Duration::from_secs(2));

        shutdown_clone.store(true, Ordering::SeqCst);
        aggregator_handle.join().unwrap();

        // Query ClickHouse to verify events were stored
        thread::sleep(Duration::from_secs(1)); // Allow async write to complete

        let query = format!(
            "SELECT COUNT(*) FROM {}.{}",
            ch_config.database, ch_config.table
        );
        let url = format!("{}/?query={}", ch_config.url, urlencoding::encode(&query));
        let mut response = ureq::get(&url).call().expect("ClickHouse query failed");
        let body = response.body_mut().read_to_string().expect("read response");

        let count: u64 = body.trim().parse().expect("parse count");

        assert!(
            count >= 50,
            "Expected at least 50 events in ClickHouse, got {}",
            count
        );

        // Cleanup
        let drop_url = format!(
            "{}/?query={}",
            ch_config.url,
            urlencoding::encode(&format!(
                "DROP TABLE IF EXISTS {}.{}",
                ch_config.database, ch_config.table
            ))
        );
        let _ = ureq::get(&drop_url).call();
    }
}
