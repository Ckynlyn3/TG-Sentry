//go:build kafka_integration

package core

import (
	"aegishook/internal/teststore"
	"bytes"
	"os"
	"testing"

	"github.com/twmb/franz-go/pkg/kmsg"
)

// Required CI gate: missing broker configuration fails, never skips.
func TestKafkaBrokerAcceptance(t *testing.T) {
	cfg, err := loadKafkaConfig(os.Getenv)
	if err != nil || cfg == nil || cfg.mechanism == "" {
		t.Fatal("required TLS/SASL broker configuration absent or invalid")
	}
	if os.Getenv("TG_SENTRY_TEST_DATABASE_URL") == "" {
		t.Fatal("required disposable PostgreSQL configuration absent")
	}
	consumer := kafkaConsumer(t, cfg)
	ctx := kafkaTestContext(t)
	if err = consumer.Ping(ctx); err != nil {
		t.Fatal("broker metadata unavailable", err)
	}
	// Provision topics explicitly in this single-broker fixture (plan §5).
	req := kmsg.NewPtrCreateTopicsRequest()
	for _, topic := range []string{cfg.riskTopic, cfg.auditTopic} {
		row := kmsg.NewCreateTopicsRequestTopic()
		row.Topic, row.NumPartitions, row.ReplicationFactor = topic, 1, 1
		req.Topics = append(req.Topics, row)
	}
	resp, err := req.RequestWith(ctx, consumer)
	if err != nil {
		t.Fatal(err)
	}
	for _, topic := range resp.Topics {
		if topic.ErrorCode != 0 {
			t.Fatal("test topic provisioning failed", topic.ErrorCode)
		}
	}
	// Queue with no worker, then restart using real operator configuration.
	t.Setenv("TG_SENTRY_KAFKA_BROKERS", "")
	values := map[string]string{}
	for _, key := range []string{"RISK_TOPIC", "AUDIT_TOPIC", "CA_FILE", "CERT_FILE", "KEY_FILE", "SASL_MECHANISM", "SASL_USERNAME", "SASL_PASSWORD_FILE"} {
		full := "TG_SENTRY_KAFKA_" + key
		values[full] = os.Getenv(full)
		t.Setenv(full, "")
	}
	e, batch := queueKafkaFixture(t, cfg)
	dir := teststore.Dir(t, e.Dir)
	for _, failure := range []string{"wrong-hostname", "wrong-password"} {
		t.Run(failure, func(t *testing.T) {
			bad := *cfg
			bad.tls = cfg.tls.Clone()
			if failure == "wrong-hostname" {
				bad.tls.ServerName = "wrong.invalid"
			} else {
				bad.password = "wrong-password"
			}
			sender, err := newKafkaSender(&bad)
			if err != nil {
				t.Fatal(err)
			}
			defer sender.client.Close()
			if err = e.drainKafkaDeliveries(kafkaTestContext(t), sender); err == nil {
				t.Fatal("failed TLS/authentication acknowledged outbox")
			}
			status, err := e.LogDeliveryStatus(kafkaTestContext(t))
			if err != nil || status.Pending != int64(len(batch)) || status.Held != 0 {
				t.Fatal("failed delivery lost pending work", status, err)
			}
		})
	}
	replay, err := e.pendingLogDeliveries(kafkaTestContext(t), cfg.destination())
	if err != nil || len(replay) != len(batch) {
		t.Fatal("failed delivery lost stored occurrences", err)
	}
	for i := range batch {
		if batch[i].ID != replay[i].ID || batch[i].Topic != replay[i].Topic || !bytes.Equal(batch[i].Event, replay[i].Event) {
			t.Fatal("failed delivery changed stored identity or bytes")
		}
	}
	if err = e.Close(); err != nil {
		t.Fatal(err)
	}
	for key, value := range values {
		t.Setenv(key, value)
	}
	t.Setenv("TG_SENTRY_KAFKA_BROKERS", cfg.address())
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	verifyKafkaRecords(t, consumer, cfg, batch)
	waitLogStatus(t, reopened, func(s LogDeliveryStatus) bool { return s.Pending == 0 })
	if err = reopened.Close(); err != nil {
		t.Fatal(err)
	}
}
