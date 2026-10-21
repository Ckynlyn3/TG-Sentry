package core

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
)

type syslogConfig struct {
	address, transport string
	facility           int
	tls                *tls.Config
}

// Routing identity excludes credentials. Changing endpoint, transport or facility
// holds the old backlog; replacing certificate files may repair that same route.
func (c syslogConfig) destination() string {
	b, _ := json.Marshal([]any{c.transport, c.address, c.facility})
	hash := sha256.Sum256(b)
	return hex.EncodeToString(hash[:])
}

func loadSyslogConfig(getenv func(string) string) (*syslogConfig, error) {
	address, transport, facility := getenv("TG_SENTRY_SYSLOG_ADDRESS"), getenv("TG_SENTRY_SYSLOG_TRANSPORT"), getenv("TG_SENTRY_SYSLOG_FACILITY")
	ca, cert, key := getenv("TG_SENTRY_SYSLOG_CA_FILE"), getenv("TG_SENTRY_SYSLOG_CERT_FILE"), getenv("TG_SENTRY_SYSLOG_KEY_FILE")
	if address == "" {
		if transport != "" || facility != "" || ca != "" || cert != "" || key != "" {
			return nil, errors.New("partial syslog configuration: address is required")
		}
		return nil, nil
	}
	if transport == "" {
		transport = "tls"
	}
	if transport != "tls" && transport != "tcp" {
		return nil, errors.New("syslog transport must be tls or explicit tcp")
	}
	n, err := strconv.Atoi(facility)
	if err != nil || n < 0 || n > 23 {
		return nil, errors.New("syslog facility must be an explicit RFC 5424 facility (0..23)")
	}
	address, err = syslogAddress(address)
	if err != nil {
		return nil, err
	}
	if (cert == "") != (key == "") {
		return nil, errors.New("syslog client certificate and key files must be paired")
	}
	cfg := &syslogConfig{address: address, transport: transport, facility: n}
	if transport == "tcp" {
		if ca != "" || cert != "" || key != "" {
			return nil, errors.New("syslog TLS files require tls transport")
		}
		return cfg, nil
	}
	cfg.tls, err = syslogTLS(ca, cert, key)
	return cfg, err
}

func syslogAddress(address string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		host = address
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = host[1 : len(host)-1]
		}
		if strings.Contains(host, ":") && net.ParseIP(host) == nil {
			return "", errors.New("invalid syslog host/port")
		}
		port = "6514" // RFC 5425 §4.1 default syslog TLS port.
	}
	n, err := strconv.Atoi(port)
	if host == "" || strings.ContainsAny(host, " \t\r\n/?#@\\") || err != nil || n < 1 || n > 65535 {
		return "", errors.New("invalid syslog host/port")
	}
	return net.JoinHostPort(host, strconv.Itoa(n)), nil
}

func syslogTLS(ca, cert, key string) (*tls.Config, error) {
	// RFC 9662 §4 updates RFC 5425: TLS 1.2 minimum, verified peer identity.
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if ca != "" {
		pem, err := os.ReadFile(ca)
		if err != nil {
			return nil, errors.New("cannot read syslog CA file")
		}
		cfg.RootCAs = x509.NewCertPool()
		if !cfg.RootCAs.AppendCertsFromPEM(pem) {
			return nil, errors.New("invalid syslog CA file")
		}
	}
	if cert != "" {
		pair, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return nil, errors.New("cannot load syslog client certificate/key files")
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	return cfg, nil
}
