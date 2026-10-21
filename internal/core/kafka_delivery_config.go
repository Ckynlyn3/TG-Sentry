package core

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
)

type kafkaConfig struct {
	brokers                       []string
	riskTopic, auditTopic         string
	tls                           *tls.Config
	mechanism, username, password string
}

func (c kafkaConfig) address() string { return strings.Join(c.brokers, ",") }

func (c kafkaConfig) destination() string {
	// Non-secret route only. Credential rotation repairs the same route; broker/topic
	// changes hold backlog, rather than redirecting already committed occurrences.
	b, _ := json.Marshal([]any{"kafka-tls", c.brokers, c.riskTopic, c.auditTopic})
	hash := sha256.Sum256(b)
	return hex.EncodeToString(hash[:])
}

func loadKafkaConfig(getenv func(string) string) (*kafkaConfig, error) {
	cfg := &kafkaConfig{riskTopic: getenv("TG_SENTRY_KAFKA_RISK_TOPIC"), auditTopic: getenv("TG_SENTRY_KAFKA_AUDIT_TOPIC"), mechanism: getenv("TG_SENTRY_KAFKA_SASL_MECHANISM"), username: getenv("TG_SENTRY_KAFKA_SASL_USERNAME")}
	brokers := getenv("TG_SENTRY_KAFKA_BROKERS")
	ca, cert, key := getenv("TG_SENTRY_KAFKA_CA_FILE"), getenv("TG_SENTRY_KAFKA_CERT_FILE"), getenv("TG_SENTRY_KAFKA_KEY_FILE")
	password := getenv("TG_SENTRY_KAFKA_SASL_PASSWORD_FILE")
	if brokers == "" {
		if cfg.riskTopic != "" || cfg.auditTopic != "" || cfg.mechanism != "" || cfg.username != "" || ca != "" || cert != "" || key != "" || password != "" {
			return nil, errors.New("partial Kafka configuration: brokers are required")
		}
		return nil, nil
	}
	for _, broker := range strings.Split(brokers, ",") {
		address, err := kafkaAddress(strings.TrimSpace(broker))
		if err != nil {
			return nil, err
		}
		cfg.brokers = append(cfg.brokers, address)
	}
	if !kafkaTopic(cfg.riskTopic) || !kafkaTopic(cfg.auditTopic) {
		return nil, errors.New("Kafka requires valid risk and audit topics")
	}
	// Plan §5 routes the two event classes to separate topics; one topic would
	// silently merge risk and audit streams at the consumer.
	if cfg.riskTopic == cfg.auditTopic {
		return nil, errors.New("Kafka risk and audit topics must differ")
	}
	if (cert == "") != (key == "") {
		return nil, errors.New("Kafka client certificate and key files must be paired")
	}
	var err error
	// Reuse S1's verified TLS/file loader, sanitizing its transport-specific errors.
	cfg.tls, err = syslogTLS(ca, cert, key)
	if err != nil {
		return nil, errors.New("cannot load Kafka TLS files")
	}
	if err = cfg.loadSASL(password); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *kafkaConfig) loadSASL(passwordFile string) error {
	if c.mechanism == "" {
		if c.username != "" || passwordFile != "" {
			return errors.New("Kafka SASL mechanism is required with credentials")
		}
		return nil
	}
	if c.mechanism != "PLAIN" && c.mechanism != "SCRAM-SHA-256" && c.mechanism != "SCRAM-SHA-512" {
		return errors.New("unsupported Kafka SASL mechanism")
	}
	if c.username == "" || strings.ContainsRune(c.username, '\x00') || passwordFile == "" {
		return errors.New("Kafka SASL username and password file are required")
	}
	b, err := os.ReadFile(passwordFile)
	if err != nil {
		return errors.New("cannot read Kafka SASL password file")
	}
	// Reuse btpii.go's mounted text-secret whitespace convention.
	c.password = strings.TrimSpace(string(b))
	if c.password == "" || strings.ContainsRune(c.password, '\x00') {
		return errors.New("invalid Kafka SASL password file")
	}
	return nil
}

func kafkaAddress(address string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		host = address
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = host[1 : len(host)-1]
		}
		if strings.Contains(host, ":") && net.ParseIP(host) == nil {
			return "", errors.New("invalid Kafka host/port")
		}
		port = "9092" // franz-go v1.22.2 SeedBrokers' documented default.
	}
	n, err := strconv.Atoi(port)
	if host == "" || strings.ContainsAny(host, " \t\r\n/?#@\\") || err != nil || n < 1 || n > 65535 {
		return "", errors.New("invalid Kafka host/port")
	}
	return net.JoinHostPort(host, strconv.Itoa(n)), nil
}

func kafkaTopic(topic string) bool {
	// Apache Kafka Topic.validate: 249 characters, ASCII alnum, '.', '_' and '-'.
	// https://github.com/apache/kafka/blob/4.2.0/clients/src/main/java/org/apache/kafka/common/internals/Topic.java
	if len(topic) == 0 || len(topic) > 249 || topic == "." || topic == ".." {
		return false
	}
	for _, c := range []byte(topic) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
