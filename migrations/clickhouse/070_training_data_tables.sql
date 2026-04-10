-- ClickHouse DDL for platform training pipeline (Ticket 5).
-- Apply against the analytics / training ClickHouse cluster (not PostgreSQL):
--   clickhouse-client --multiquery < migrations/clickhouse/070_training_data_tables.sql
--
-- Design: ReplacingMergeTree partitioned by customer_id for idempotent re-ingest.

CREATE DATABASE IF NOT EXISTS training_data;

CREATE TABLE IF NOT EXISTS training_data.dpo_pairs
(
    customer_id            LowCardinality(String),
    investigation_id_hash  String,
    payload_json           String,
    ingested_at            DateTime64(3) DEFAULT now64(3),
    version                UInt64 DEFAULT toUnixTimestamp64Milli(now64(3))
)
ENGINE = ReplacingMergeTree(version)
PARTITION BY customer_id
ORDER BY (customer_id, investigation_id_hash, cityHash64(payload_json))
TTL ingested_at + INTERVAL 730 DAY;

CREATE TABLE IF NOT EXISTS training_data.novel_attacks
(
    customer_id            LowCardinality(String),
    investigation_id_hash  String,
    abstraction_json       String,
    ingested_at            DateTime64(3) DEFAULT now64(3),
    version                UInt64 DEFAULT toUnixTimestamp64Milli(now64(3))
)
ENGINE = ReplacingMergeTree(version)
PARTITION BY customer_id
ORDER BY (customer_id, investigation_id_hash)
TTL ingested_at + INTERVAL 730 DAY;

CREATE TABLE IF NOT EXISTS training_data.entity_graphs
(
    customer_id            LowCardinality(String),
    graph_id_hash          String,
    graph_json             String,
    ingested_at            DateTime64(3) DEFAULT now64(3),
    version                UInt64 DEFAULT toUnixTimestamp64Milli(now64(3))
)
ENGINE = ReplacingMergeTree(version)
PARTITION BY customer_id
ORDER BY (customer_id, graph_id_hash)
TTL ingested_at + INTERVAL 730 DAY;

CREATE TABLE IF NOT EXISTS training_data.dead_letters
(
    customer_id     LowCardinality(String),
    reason          LowCardinality(String),
    raw_payload     String,
    failed_at       DateTime64(3) DEFAULT now64(3),
    version         UInt64 DEFAULT toUnixTimestamp64Milli(now64(3))
)
ENGINE = ReplacingMergeTree(version)
PARTITION BY customer_id
ORDER BY (customer_id, failed_at, cityHash64(raw_payload))
TTL failed_at + INTERVAL 180 DAY;
