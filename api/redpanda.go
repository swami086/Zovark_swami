package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/segmentio/kafka-go"
)

// Canonical ingest / task dispatch transport (replaces NATS).
// Topics: tasks.new.{tenant_id}

var (
	redpandaWriter     *kafka.Writer
	redpandaWriterOnce sync.Once
)

func initRedpandaWriter() {
	redpandaWriterOnce.Do(func() {
		brokers := strings.TrimSpace(os.Getenv("ZOVARK_REDPANDA_BROKERS"))
		if brokers == "" {
			log.Println("[REDPANDA] ZOVARK_REDPANDA_BROKERS not set — task dispatch disabled")
			return
		}
		parts := strings.Split(brokers, ",")
		addrs := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				addrs = append(addrs, p)
			}
		}
		if len(addrs) == 0 {
			return
		}
		redpandaWriter = &kafka.Writer{
			Addr:                   kafka.TCP(addrs...),
			Balancer:               &kafka.LeastBytes{},
			AllowAutoTopicCreation: true,
			RequiredAcks:           kafka.RequireAll,
		}
		log.Printf("[REDPANDA] Writer ready (%d broker(s))", len(addrs))
	})
}

func closeRedpandaWriter() {
	if redpandaWriter != nil {
		_ = redpandaWriter.Close()
		redpandaWriter = nil
	}
}

// publishTaskNew publishes a workflow start envelope to tasks.new.{tenantID}.
func publishTaskNew(ctx context.Context, tenantID, taskID, taskType string, input map[string]interface{}) error {
	if redpandaWriter == nil {
		return fmt.Errorf("redpanda not configured (set ZOVARK_REDPANDA_BROKERS)")
	}
	wf := workflowName
	payload := map[string]interface{}{
		"schema":    "zovark.tasks.new.v1",
		"tenant_id": tenantID,
		"task_id":   taskID,
		"task_type": taskType,
		"workflow":  wf,
		"input":     input,
	}
	injectOTelTraceContext(ctx, payload)
	b, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal task envelope: %w", err)
	}
	topic := fmt.Sprintf("tasks.new.%s", tenantID)
	if err := redpandaWriter.WriteMessages(ctx, kafka.Message{
		Topic: topic,
		Key:   []byte(taskID),
		Value: b,
	}); err != nil {
		return fmt.Errorf("kafka publish %s: %w", topic, err)
	}
	log.Printf("[REDPANDA] Published task %s to %s", taskID, topic)
	return nil
}

// publishRawTrainingData publishes an opaque customer training payload to
// raw.training-data.{customerID} (Ticket 5 platform ingestion).
func publishRawTrainingData(ctx context.Context, customerID string, payload []byte) error {
	if redpandaWriter == nil {
		return fmt.Errorf("redpanda not configured (set ZOVARK_REDPANDA_BROKERS)")
	}
	cid := strings.TrimSpace(customerID)
	if cid == "" {
		return fmt.Errorf("customer_id required")
	}
	topic := fmt.Sprintf("raw.training-data.%s", cid)
	key := sha256Hex(payload)
	if err := redpandaWriter.WriteMessages(ctx, kafka.Message{
		Topic: topic,
		Key:   []byte(key),
		Value: payload,
	}); err != nil {
		return fmt.Errorf("kafka publish %s: %w", topic, err)
	}
	ks := 12
	if len(key) < ks {
		ks = len(key)
	}
	log.Printf("[REDPANDA] Published training payload to %s (key=%s…)", topic, key[:ks])
	return nil
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
