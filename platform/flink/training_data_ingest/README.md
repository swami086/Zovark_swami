# Flink — platform training-data ingest (Ticket 5)

Validates JSON payloads from `raw.training-data.{customer_id}`, deduplicates by
`(investigation_id_hash, customer_id)` using keyed state with **24h TTL**, routes
invalid records to a dead-letter Kafka topic, and batches inserts to ClickHouse
(`training_data.*` tables — see `migrations/clickhouse/070_training_data_tables.sql`).

## Build

```bash
cd platform/flink/training_data_ingest
mvn -q package
```

## Run (example)

```bash
export KAFKA_BROKERS=localhost:19092
export CLICKHOUSE_URL=jdbc:clickhouse://localhost:9000/training_data
java -cp target/training-data-ingest-1.0.0.jar com.zovark.flink.TrainingDataIngestJob
```

Submit to Flink cluster:

```bash
flink run -c com.zovark.flink.TrainingDataIngestJob target/training-data-ingest-1.0.0.jar
```

## Docker profile

`docker compose -f docker-compose.yml -f docker-compose.data-plane.yml --profile flink up -d`
