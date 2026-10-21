package core

import (
	"strings"
	"testing"
)

func syslogEnv(values map[string]string) func(string) string {
	return func(key string) string { return values[strings.TrimPrefix(key, "TG_SENTRY_SYSLOG_")] }
}

func TestSyslogConfigDisabledAndPartial(t *testing.T) {
	cfg, err := loadSyslogConfig(syslogEnv(nil))
	if err != nil || cfg != nil {
		t.Fatalf("disabled: %v %v", cfg, err)
	}
	for _, values := range []map[string]string{
		{"FACILITY": "16"}, {"TRANSPORT": "tls"}, {"CA_FILE": "missing"},
		{"ADDRESS": "localhost"}, {"ADDRESS": "localhost", "FACILITY": "-1"},
		{"ADDRESS": "localhost", "FACILITY": "24"}, {"ADDRESS": "localhost", "FACILITY": "bad"},
		{"ADDRESS": "localhost:0", "FACILITY": "16"}, {"ADDRESS": ":6514", "FACILITY": "16"},
		{"ADDRESS": "localhost:65536", "FACILITY": "16"}, {"ADDRESS": "bad host", "FACILITY": "16"},
		{"ADDRESS": "localhost", "FACILITY": "16", "TRANSPORT": "udp"},
		{"ADDRESS": "localhost", "FACILITY": "16", "CERT_FILE": "missing"},
		{"ADDRESS": "localhost", "FACILITY": "16", "KEY_FILE": "missing"},
		{"ADDRESS": "localhost", "FACILITY": "16", "TRANSPORT": "tcp", "CA_FILE": "missing"},
	} {
		if _, err := loadSyslogConfig(syslogEnv(values)); err == nil {
			t.Fatalf("accepted partial/invalid config %+v", values)
		}
	}
}

func TestSyslogConfigVerifiedTLSDefaultAndExplicitTCP(t *testing.T) {
	cfg, err := loadSyslogConfig(syslogEnv(map[string]string{"ADDRESS": "localhost", "FACILITY": "16"}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.address != "localhost:6514" || cfg.transport != "tls" || cfg.tls.InsecureSkipVerify {
		t.Fatal("unsafe TLS defaults")
	}
	for _, address := range []string{"127.0.0.1:1234", "[::1]:1234", "::1"} {
		cfg, err := loadSyslogConfig(syslogEnv(map[string]string{"ADDRESS": address, "FACILITY": "0", "TRANSPORT": "tcp"}))
		if err != nil || cfg.transport != "tcp" || cfg.tls != nil {
			t.Fatalf("explicit TCP %q: %v", address, err)
		}
	}
}
