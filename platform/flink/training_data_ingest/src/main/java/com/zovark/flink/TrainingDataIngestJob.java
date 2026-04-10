package com.zovark.flink;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.flink.api.common.eventtime.WatermarkStrategy;
import org.apache.flink.api.common.state.StateTtlConfig;
import org.apache.flink.api.common.state.ValueState;
import org.apache.flink.api.common.state.ValueStateDescriptor;
import org.apache.flink.api.common.time.Time;
import org.apache.flink.api.common.typeinfo.TypeInformation;
import org.apache.flink.configuration.Configuration;
import org.apache.flink.connector.kafka.sink.KafkaRecordSerializationSchema;
import org.apache.flink.connector.kafka.sink.KafkaSink;
import org.apache.flink.connector.kafka.source.KafkaSource;
import org.apache.flink.connector.kafka.source.reader.deserializer.KafkaRecordDeserializationSchema;
import org.apache.flink.streaming.api.datastream.DataStream;
import org.apache.flink.streaming.api.datastream.SingleOutputStreamOperator;
import org.apache.flink.streaming.api.environment.StreamExecutionEnvironment;
import org.apache.flink.streaming.api.functions.KeyedProcessFunction;
import org.apache.flink.streaming.api.functions.ProcessFunction;
import org.apache.flink.util.Collector;
import org.apache.flink.util.OutputTag;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.producer.ProducerRecord;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Ingest raw.training-data.{customer_id} → validate JSON → 24h dedupe by (customer_id, key)
 * → valid to stdout (replace with ClickHouse sink in production); invalid to DLQ topic.
 */
public class TrainingDataIngestJob {

    public static final OutputTag<TrainingEvent> DLQ_TAG =
            new OutputTag<TrainingEvent>("dead-letter") {};

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static void main(String[] args) throws Exception {
        final String brokers = env("KAFKA_BROKERS", "localhost:19092");
        final String dlqTopic = env("TRAINING_DLQ_TOPIC", "training.data.dead_letter");

        StreamExecutionEnvironment env = StreamExecutionEnvironment.getExecutionEnvironment();

        KafkaSource<TrainingEvent> source =
                KafkaSource.<TrainingEvent>builder()
                        .setBootstrapServers(brokers)
                        .setTopicPattern("raw\\.training-data\\..*")
                        .setDeserializer(new TrainingDeserializationSchema())
                        .build();

        DataStream<TrainingEvent> input =
                env.fromSource(source, WatermarkStrategy.<TrainingEvent>noWatermarks(), "raw-training-data");

        SingleOutputStreamOperator<TrainingEvent> valid =
                input.process(new ValidateJsonFunction()).name("validate-json");

        DataStream<TrainingEvent> invalid = valid.getSideOutput(DLQ_TAG);

        KafkaSink<TrainingEvent> dlqSink =
                KafkaSink.<TrainingEvent>builder()
                        .setBootstrapServers(brokers)
                        .setRecordSerializer(
                                new KafkaRecordSerializationSchema<TrainingEvent>() {
                                    @Override
                                    public ProducerRecord<byte[], byte[]> serialize(
                                            TrainingEvent e, KafkaSinkContext ctx, Long ts) {
                                        String topic = dlqTopic;
                                        return new ProducerRecord<>(
                                                topic,
                                                (e.customerId + ":" + e.keyHash).getBytes(StandardCharsets.UTF_8),
                                                e.payload);
                                    }
                                })
                        .build();

        invalid.sinkTo(dlqSink).name("dead-letter-kafka");

        valid.keyBy(e -> e.customerId + "\0" + e.keyHash)
                .process(new Dedupe24hFunction())
                .name("dedupe-24h")
                .print("clickhouse-batch-placeholder");

        env.execute("Zovark Training Data Ingest");
    }

    private static String env(String k, String d) {
        String v = System.getenv(k);
        return v == null || v.isEmpty() ? d : v;
    }

    /** Raw event from Kafka (topic encodes customer_id; key = investigation hash). */
    public static class TrainingEvent implements java.io.Serializable {
        public String customerId;
        public String keyHash;
        public byte[] payload;
        public boolean validJson;

        public TrainingEvent() {}

        TrainingEvent(String customerId, String keyHash, byte[] payload, boolean validJson) {
            this.customerId = customerId;
            this.keyHash = keyHash;
            this.payload = payload;
            this.validJson = validJson;
        }
    }

    static class TrainingDeserializationSchema implements KafkaRecordDeserializationSchema<TrainingEvent> {
        @Override
        public void deserialize(ConsumerRecord<byte[], byte[]> rec, Collector<TrainingEvent> out) {
            String topic = rec.topic();
            String prefix = "raw.training-data.";
            String cid =
                    topic.startsWith(prefix)
                            ? topic.substring(prefix.length())
                            : "unknown";
            String key =
                    rec.key() == null ? "" : new String(rec.key(), StandardCharsets.UTF_8);
            byte[] val = rec.value() == null ? new byte[0] : rec.value();
            out.collect(new TrainingEvent(cid, key, val, false));
        }

        @Override
        public TypeInformation<TrainingEvent> getProducedType() {
            return TypeInformation.of(TrainingEvent.class);
        }
    }

    static class ValidateJsonFunction extends ProcessFunction<TrainingEvent, TrainingEvent> {
        @Override
        public void processElement(TrainingEvent e, Context ctx, Collector<TrainingEvent> out) {
            try {
                JsonNode n = MAPPER.readTree(e.payload);
                if (!n.isObject() && !n.isArray()) {
                    throw new IOException("not json object or array");
                }
                out.collect(
                        new TrainingEvent(e.customerId, e.keyHash, e.payload, true));
            } catch (Exception ex) {
                ctx.output(DLQ_TAG, e);
            }
        }
    }

    static class Dedupe24hFunction extends KeyedProcessFunction<String, TrainingEvent, TrainingEvent> {

        private transient ValueState<Long> lastSeen;

        @Override
        public void open(Configuration parameters) {
            StateTtlConfig ttl =
                    StateTtlConfig.newBuilder(Time.hours(24))
                            .setUpdateType(StateTtlConfig.UpdateType.OnCreateAndWrite)
                            .setStateVisibility(StateTtlConfig.StateVisibility.NeverReturnExpired)
                            .build();
            ValueStateDescriptor<Long> desc =
                    new ValueStateDescriptor<>("last-seen-ms", Long.class);
            desc.enableTimeToLive(ttl);
            lastSeen = getRuntimeContext().getState(desc);
        }

        @Override
        public void processElement(TrainingEvent e, Context ctx, Collector<TrainingEvent> out)
                throws Exception {
            long now = ctx.timerService().currentProcessingTime();
            Long prev = lastSeen.value();
            if (prev != null && now - prev < Time.hours(24).toMilliseconds()) {
                return;
            }
            lastSeen.update(now);
            out.collect(e);
        }
    }
}
