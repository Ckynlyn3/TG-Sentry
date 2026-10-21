package core

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"time"

	"github.com/sethvargo/go-retry"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl/plain"
	"github.com/twmb/franz-go/pkg/sasl/scram"
)

func (c kafkaConfig) options() []kgo.Opt {
	// Keep v1.22.2 defaults: all-ISR acknowledgements, idempotence and retries.
	// https://github.com/twmb/franz-go/blob/v1.22.2/pkg/kgo/config.go
	// AllowIdempotentProduceCancellation bounds shutdown without disabling
	// idempotence for internal retries. Uncertain sends stay pending; replay may duplicate.
	opts := []kgo.Opt{kgo.SeedBrokers(c.brokers...), kgo.DialTLSConfig(c.tls), kgo.AllowIdempotentProduceCancellation()}
	switch c.mechanism {
	case "PLAIN":
		opts = append(opts, kgo.SASL(plain.Auth{User: c.username, Pass: c.password}.AsMechanism()))
	case "SCRAM-SHA-256":
		opts = append(opts, kgo.SASL(scram.Auth{User: c.username, Pass: c.password}.AsSha256Mechanism()))
	case "SCRAM-SHA-512":
		opts = append(opts, kgo.SASL(scram.Auth{User: c.username, Pass: c.password}.AsSha512Mechanism()))
	}
	return opts
}

type kafkaSender struct {
	config kafkaConfig
	client *kgo.Client
}

func newKafkaSender(config *kafkaConfig) (*kafkaSender, error) {
	if config.tls == nil || config.tls.InsecureSkipVerify {
		return nil, errors.New("Kafka requires verified TLS")
	}
	client, err := kgo.NewClient(config.options()...)
	if err != nil {
		return nil, errors.New("cannot configure Kafka client")
	}
	return &kafkaSender{config: *config, client: client}, nil
}

func (c kafkaConfig) topic(raw json.RawMessage) (string, error) {
	var event struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &event) != nil {
		return "", errors.New("invalid stored Kafka event")
	}
	switch event.Type {
	case "tg.sentry.risk.v1":
		return c.riskTopic, nil
	case "tg.sentry.audit.v1":
		return c.auditTopic, nil
	default:
		return "", errors.New("unsupported Kafka event type")
	}
}

func (s *kafkaSender) send(ctx context.Context, row pendingLogDelivery) error {
	var event struct {
		ID string `json:"id"`
	}
	topic, err := s.config.topic(row.Event)
	if err != nil || json.Unmarshal(row.Event, &event) != nil || event.ID == "" {
		return errors.New("invalid stored Kafka event")
	}
	if row.Topic != topic || row.Address != s.config.address() || row.Transport != "kafka-tls" {
		return errors.New("pending Kafka route mismatch")
	}
	// CloudEvents Kafka binding v1.0.2 §3.3: structured value and content-type.
	// https://github.com/cloudevents/spec/blob/v1.0.2/cloudevents/bindings/kafka-protocol-binding.md#33-structured-content-mode
	record := &kgo.Record{Topic: topic, Key: []byte(event.ID), Value: row.Event, Headers: []kgo.RecordHeader{{Key: "content-type", Value: []byte("application/cloudevents+json")}}}
	if s.client.ProduceSync(ctx, record).FirstErr() != nil || ctx.Err() != nil {
		// Never forward broker/auth error text (may contain peer-supplied secrets).
		return errors.New("Kafka produce failed or cancelled")
	}
	return nil // Only a broker-confirmed Produce result permits outbox acknowledgement.
}

func (e *Engine) drainKafkaDeliveries(ctx context.Context, sender *kafkaSender) error {
	for {
		batch, err := e.pendingLogDeliveries(ctx, sender.config.destination())
		if err != nil {
			return err
		}
		for _, row := range batch {
			if err = sender.send(ctx, row); err != nil {
				return err
			}
			if err = e.ackLogDelivery(ctx, row.ID, row.Destination); err != nil {
				return err
			}
		}
		if len(batch) < eventExportBatchSize {
			return nil
		}
	}
}

func (e *Engine) kafkaDeliveryLoop(ctx context.Context, sender *kafkaSender) {
	defer e.workers.Done()
	defer sender.client.Close()
	for ctx.Err() == nil {
		err := retry.Do(ctx, logDeliveryBackoff(), func(ctx context.Context) error {
			err := e.drainKafkaDeliveries(ctx, sender)
			if err != nil && ctx.Err() == nil {
				status, statusErr := e.LogDeliveryStatus(ctx)
				log.Printf("Kafka delivery blocked: %v; pending=%d held=%d oldest=%s status_error=%v", err, status.Pending, status.Held, status.Oldest.Format(time.RFC3339Nano), statusErr)
				return retry.RetryableError(err)
			}
			return err
		})
		if err != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-e.kafkaWake:
		}
	}
}
