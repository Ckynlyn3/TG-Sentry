package core

import (
	"aegishook/internal/teststore"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/twmb/franz-go/pkg/kfake"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/kmsg"
)

func kafkaEnv(values map[string]string) func(string) string {
	return func(key string) string { return values[strings.TrimPrefix(key, "TG_SENTRY_KAFKA_")] }
}

func TestKafkaConfigValidation(t *testing.T) {
	if cfg, err := loadKafkaConfig(kafkaEnv(nil)); cfg != nil || err != nil {
		t.Fatal(cfg, err)
	}
	for _, values := range []map[string]string{{"RISK_TOPIC": "risk"}, {"SASL_PASSWORD_FILE": "missing"}} {
		if _, err := loadKafkaConfig(kafkaEnv(values)); err == nil {
			t.Fatal("partial disabled configuration accepted")
		}
	}
	for _, overrides := range []map[string]string{
		{"RISK_TOPIC": ""}, {"AUDIT_TOPIC": ""}, {"BROKERS": "bad host"},
		{"BROKERS": "localhost:0"}, {"BROKERS": "localhost:65536"}, {"BROKERS": "localhost,,other"},
		{"RISK_TOPIC": ".."}, {"AUDIT_TOPIC": "bad/topic"}, {"RISK_TOPIC": strings.Repeat("x", 250)},
		{"CERT_FILE": "missing"}, {"SASL_MECHANISM": "OAUTHBEARER"}, {"SASL_MECHANISM": "PLAIN"},
		{"SASL_USERNAME": "user"}, {"CA_FILE": "missing"},
		// Plan §5 requires separate risk and audit topics; one topic would merge the streams.
		{"AUDIT_TOPIC": "risk"},
	} {
		values := map[string]string{"BROKERS": "localhost", "RISK_TOPIC": "risk", "AUDIT_TOPIC": "audit"}
		for key, value := range overrides {
			values[key] = value
		}
		if _, err := loadKafkaConfig(kafkaEnv(values)); err == nil {
			t.Fatalf("accepted invalid config %v", values)
		}
	}
	cfg, err := loadKafkaConfig(kafkaEnv(map[string]string{"BROKERS": "localhost,[::1]:9093", "RISK_TOPIC": "risk", "AUDIT_TOPIC": "audit"}))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(cfg.brokers, ",") != "localhost:9092,[::1]:9093" || cfg.tls == nil || cfg.tls.InsecureSkipVerify {
		t.Fatal("unsafe config")
	}
}

func kafkaFixture(t *testing.T, mechanism string) (*kfake.Cluster, *kafkaConfig) {
	t.Helper()
	pki := newLogTestPKI(t, []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")})
	cluster, err := kfake.NewCluster(kfake.NumBrokers(1), kfake.SeedTopics(1, "risk", "audit"), kfake.TLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pki.server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pki.roots}), kfake.EnableSASL(), kfake.Superuser(mechanism, "test", "fixture-password"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cluster.Close)
	password := filepath.Join(t.TempDir(), "sasl-password")
	if err = os.WriteFile(password, []byte("fixture-password\n"), 0600); err != nil {
		t.Fatal(err)
	}
	values := map[string]string{"BROKERS": strings.Join(cluster.ListenAddrs(), ","), "RISK_TOPIC": "risk", "AUDIT_TOPIC": "audit", "CA_FILE": pki.caFile, "CERT_FILE": pki.certFile, "KEY_FILE": pki.keyFile, "SASL_MECHANISM": mechanism, "SASL_USERNAME": "test", "SASL_PASSWORD_FILE": password}
	cfg, err := loadKafkaConfig(kafkaEnv(values))
	if err != nil {
		t.Fatal(err)
	}
	return cluster, cfg
}

func kafkaTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), logDeliveryIOBudget)
	t.Cleanup(cancel)
	return ctx
}

func kafkaConsumer(t *testing.T, cfg *kafkaConfig) *kgo.Client {
	t.Helper()
	opts := append(cfg.options(), kgo.ConsumeTopics(cfg.riskTopic, cfg.auditTopic), kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()))
	client, err := kgo.NewClient(opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

// verifyKafkaRecords asserts topic routing from the operator configuration and the
// event's own CloudEvent type, never from row.Topic (which the routing under test
// populated). Both event classes must arrive on their own topic.
func verifyKafkaRecords(t *testing.T, consumer *kgo.Client, cfg *kafkaConfig, batch []pendingLogDelivery) {
	t.Helper()
	expected := map[string]pendingLogDelivery{}
	classes := map[string]string{"tg.sentry.risk.v1": cfg.riskTopic, "tg.sentry.audit.v1": cfg.auditTopic}
	for _, row := range batch {
		var ev Event
		if json.Unmarshal(row.Event, &ev) != nil {
			t.Fatal("bad fixture")
		}
		if _, ok := classes[ev.Type]; !ok {
			t.Fatalf("fixture holds unsupported event class %q", ev.Type)
		}
		expected[ev.ID] = row
	}
	received := map[string]bool{}
	schemas := pinnedEventSchemas(t)
	ctx := kafkaTestContext(t)
	for len(expected) > 0 {
		fetches := consumer.PollFetches(ctx)
		if errs := fetches.Errors(); len(errs) > 0 {
			t.Fatal(errs)
		}
		fetches.EachRecord(func(record *kgo.Record) {
			row, ok := expected[string(record.Key)]
			if !ok {
				t.Fatalf("unexpected occurrence %q", record.Key)
			}
			var ev Event
			if json.Unmarshal(row.Event, &ev) != nil {
				t.Fatal("bad fixture")
			}
			if record.Topic != classes[ev.Type] || !bytes.Equal(record.Value, row.Event) {
				t.Fatalf("%s delivered to %q, want %q", ev.Type, record.Topic, classes[ev.Type])
			}
			received[ev.Type] = true
			var header bool
			for _, h := range record.Headers {
				if h.Key == "content-type" && string(h.Value) == "application/cloudevents+json" {
					header = true
				}
			}
			if !header {
				t.Fatal("missing structured content-type")
			}
			var wire map[string]any
			if err := json.Unmarshal(record.Value, &wire); err != nil {
				t.Fatal(err)
			}
			if err := validateEventWire(schemas, wire); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(record.Value), "passwd alice") || strings.Contains(string(record.Value), "fixture-password") {
				t.Fatal("sensitive content emitted")
			}
			delete(expected, string(record.Key))
		})
	}
	for eventType := range classes {
		if !received[eventType] {
			t.Fatalf("no %s record received", eventType)
		}
	}
}

func queueKafkaFixture(t *testing.T, cfg *kafkaConfig) (*Engine, []pendingLogDelivery) {
	t.Helper()
	e := engine(t)
	e.kafka = cfg
	if _, err := e.Submit(input(ID(), "bash", map[string]any{"command": "passwd alice"})); err != nil {
		t.Fatal(err)
	}
	batch, err := e.pendingLogDeliveries(kafkaTestContext(t), cfg.destination())
	if err != nil || len(batch) == 0 {
		t.Fatal("missing outbox", err)
	}
	types := map[string]bool{}
	for _, row := range batch {
		var ev Event
		if json.Unmarshal(row.Event, &ev) != nil {
			t.Fatal("bad fixture")
		}
		types[ev.Type] = true
	}
	if !types["tg.sentry.risk.v1"] || !types["tg.sentry.audit.v1"] {
		t.Fatalf("fixture must queue both event classes, got %v", types)
	}
	return e, batch
}

func TestKafkaDeliverySuccessTLSAndSASL(t *testing.T) {
	for _, mechanism := range []string{"PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512"} {
		t.Run(mechanism, func(t *testing.T) {
			cluster, cfg := kafkaFixture(t, mechanism)
			observed := make(chan bool, 1)
			cluster.ControlKey(0, func(req kmsg.Request) (kmsg.Response, error, bool) {
				produce := req.(*kmsg.ProduceRequest)
				select {
				case observed <- produce.Acks == -1 && produce.Version >= 3:
				default:
				}
				return nil, nil, false
			})
			e, batch := queueKafkaFixture(t, cfg)
			sender, err := newKafkaSender(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer sender.client.Close()
			if err = e.drainKafkaDeliveries(kafkaTestContext(t), sender); err != nil {
				t.Fatal(err)
			}
			verifyKafkaRecords(t, kafkaConsumer(t, cfg), cfg, batch)
			select {
			case ok := <-observed:
				if !ok {
					t.Fatal("not broker-confirmed/idempotent")
				}
			case <-kafkaTestContext(t).Done():
				t.Fatal("no produce")
			}
			status, err := e.LogDeliveryStatus(kafkaTestContext(t))
			if err != nil || status.Pending != 0 {
				t.Fatal(status, err)
			}
		})
	}
}

func TestKafkaDeliveryBrokerErrorAndReplay(t *testing.T) {
	cluster, cfg := kafkaFixture(t, "PLAIN")
	e, batch := queueKafkaFixture(t, cfg)
	var fail atomic.Bool
	fail.Store(true)
	cluster.ControlKey(0, func(req kmsg.Request) (kmsg.Response, error, bool) {
		if !fail.Load() {
			cluster.DropControl()
			return nil, nil, false
		}
		cluster.KeepControl()
		p := req.(*kmsg.ProduceRequest)
		r := kmsg.NewPtrProduceResponse()
		r.SetVersion(p.Version)
		for _, topic := range p.Topics {
			rt := kmsg.NewProduceResponseTopic()
			rt.Topic = topic.Topic
			rt.TopicID = topic.TopicID
			for _, part := range topic.Partitions {
				rp := kmsg.NewProduceResponseTopicPartition()
				rp.Partition = part.Partition
				rp.ErrorCode = 29
				rt.Partitions = append(rt.Partitions, rp)
			}
			r.Topics = append(r.Topics, rt)
		}
		return r, nil, true
	})
	sender, err := newKafkaSender(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer sender.client.Close()
	if err = e.drainKafkaDeliveries(kafkaTestContext(t), sender); err == nil {
		t.Fatal("broker error acknowledged")
	}
	status, err := e.LogDeliveryStatus(kafkaTestContext(t))
	if err != nil || status.Pending != int64(len(batch)) || status.Held != 0 {
		t.Fatal(status, err)
	}
	// Reopen the same durable store, with the same route; IDs and stored bytes survive.
	dir := e.Dir
	if err = e.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopened.kafka = cfg
	replay, err := reopened.pendingLogDeliveries(kafkaTestContext(t), cfg.destination())
	if err != nil {
		t.Fatal(err)
	}
	if len(replay) != len(batch) {
		t.Fatal("restart lost work")
	}
	for i := range batch {
		if batch[i].ID != replay[i].ID || !bytes.Equal(batch[i].Event, replay[i].Event) {
			t.Fatal("restart changed identity")
		}
	}
	fail.Store(false)
	replaySender, err := newKafkaSender(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer replaySender.client.Close()
	if err = reopened.drainKafkaDeliveries(kafkaTestContext(t), replaySender); err != nil {
		t.Fatal(err)
	}
	verifyKafkaRecords(t, kafkaConsumer(t, cfg), cfg, batch)

}

func TestKafkaDeliveryInflightCancellation(t *testing.T) {
	cluster, cfg := kafkaFixture(t, "SCRAM-SHA-512")
	e, batch := queueKafkaFixture(t, cfg)
	inflight := make(chan struct{}, 1)
	cluster.ControlKey(0, func(kmsg.Request) (kmsg.Response, error, bool) {
		select {
		case inflight <- struct{}{}:
		default:
		}
		return nil, nil, true
	})
	sender, err := newKafkaSender(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer sender.client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- e.drainKafkaDeliveries(ctx, sender) }()
	select {
	case <-inflight:
	case <-kafkaTestContext(t).Done():
		t.Fatal("no inflight produce")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancel acknowledged")
		}
	case <-kafkaTestContext(t).Done():
		t.Fatal("cancel did not join")
	}
	status, err := e.LogDeliveryStatus(kafkaTestContext(t))
	if err != nil || status.Pending != int64(len(batch)) {
		t.Fatal(status, err)
	}
}

func TestKafkaDeliveryTLSAndSASLFailure(t *testing.T) {
	for _, failure := range []string{"wrong-ca", "wrong-hostname", "missing-client-cert", "wrong-password"} {
		t.Run(failure, func(t *testing.T) {
			_, cfg := kafkaFixture(t, "PLAIN")
			bad := *cfg
			bad.tls = cfg.tls.Clone()
			switch failure {
			case "wrong-ca":
				bad.tls.RootCAs = newSyslogTestPKI(t).roots
			case "wrong-hostname":
				bad.tls.ServerName = "wrong.invalid"
			case "missing-client-cert":
				bad.tls.Certificates = nil
			case "wrong-password":
				bad.password = "wrong-password"
			}
			sender, err := newKafkaSender(&bad)
			if err != nil {
				t.Fatal(err)
			}
			defer sender.client.Close()
			if err = sender.client.Ping(kafkaTestContext(t)); err == nil {
				t.Fatal("bad TLS/auth accepted")
			}
		})
	}
}

func TestKafkaDeliveryWorkerRestart(t *testing.T) {
	pki := newLogTestPKI(t, []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")})
	cluster, err := kfake.NewCluster(kfake.NumBrokers(1), kfake.SeedTopics(1, "risk", "audit"), kfake.TLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pki.server}}))
	if err != nil {
		t.Fatal(err)
	}
	defer cluster.Close()
	values := map[string]string{"BROKERS": strings.Join(cluster.ListenAddrs(), ","), "RISK_TOPIC": "risk", "AUDIT_TOPIC": "audit", "CA_FILE": pki.caFile}
	cfg, err := loadKafkaConfig(kafkaEnv(values))
	if err != nil {
		t.Fatal(err)
	}
	e, batch := queueKafkaFixture(t, cfg)
	dir := teststore.Dir(t, e.Dir)
	if err = e.Close(); err != nil {
		t.Fatal(err)
	}
	for key, value := range values {
		t.Setenv("TG_SENTRY_KAFKA_"+key, value)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	verifyKafkaRecords(t, kafkaConsumer(t, cfg), cfg, batch)
	waitLogStatus(t, reopened, func(s LogDeliveryStatus) bool { return s.Pending == 0 })
}
