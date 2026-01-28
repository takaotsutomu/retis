-- Retis Distributed Tracing - ClickHouse Schema
-- Replace {database} and {table} with actual names, or use auto-create.

CREATE DATABASE IF NOT EXISTS {database};

CREATE TABLE IF NOT EXISTS {database}.{table} (
    event_id UUID DEFAULT generateUUIDv4(),

    -- Distributed metadata
    node_id UUID,
    epoch_ns Int64,
    ntp_offset_ns Int64,
    sync_status Enum8('Synchronized' = 0, 'Degraded' = 1, 'Unsynchronized' = 2),

    -- Session info
    session_id UInt64,
    node_name String,
    hostname String,

    -- Correlation fields
    tracking_id String,
    correlation_id String,
    flow_id String,

    -- Event metadata
    event_type String,
    probe_point String,

    -- Full event
    event_json String,

    received_at DateTime64(9) DEFAULT now64(9)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(fromUnixTimestamp64Nano(epoch_ns))
ORDER BY (epoch_ns, node_id, tracking_id)
TTL toDateTime(fromUnixTimestamp64Nano(epoch_ns)) + INTERVAL 7 DAY
SETTINGS index_granularity = 8192;

-- Bloom filter indexes for correlation queries
ALTER TABLE {database}.{table}
    ADD INDEX IF NOT EXISTS idx_tracking_id tracking_id TYPE bloom_filter GRANULARITY 4;
ALTER TABLE {database}.{table}
    ADD INDEX IF NOT EXISTS idx_correlation_id correlation_id TYPE bloom_filter GRANULARITY 4;
ALTER TABLE {database}.{table}
    ADD INDEX IF NOT EXISTS idx_flow_id flow_id TYPE bloom_filter GRANULARITY 4;

-- Set indexes for low-cardinality fields
ALTER TABLE {database}.{table}
    ADD INDEX IF NOT EXISTS idx_event_type event_type TYPE set(100) GRANULARITY 4;
ALTER TABLE {database}.{table}
    ADD INDEX IF NOT EXISTS idx_probe_point probe_point TYPE set(100) GRANULARITY 4;
ALTER TABLE {database}.{table}
    ADD INDEX IF NOT EXISTS idx_node_name node_name TYPE set(100) GRANULARITY 4;
