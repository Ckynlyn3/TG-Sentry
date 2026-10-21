package core

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type syslogTestPKI struct {
	caFile, certFile, keyFile string
	server                    tls.Certificate
	roots                     *x509.CertPool
}

func newSyslogTestPKI(t *testing.T) syslogTestPKI {
	return newLogTestPKI(t, nil)
}

func newLogTestPKI(t *testing.T, ips []net.IP) syslogTestPKI {
	t.Helper()
	// Ephemeral P-256 certificate fixtures use Go crypto/x509 CreateCertificate,
	// https://pkg.go.dev/crypto/x509#example-CreateCertificate; no real credentials.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	roots.AppendCertsFromPEM(caPEM)
	issue := func(serial int64, usage x509.ExtKeyUsage) (tls.Certificate, []byte, []byte) {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cert := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "test endpoint"}, DNSNames: []string{"localhost"}, IPAddresses: ips, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		der, err := x509.CreateCertificate(rand.Reader, cert, ca, &k.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		certPEM, keyPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		return pair, certPEM, keyPEM
	}
	server, _, _ := issue(2, x509.ExtKeyUsageServerAuth)
	_, clientPEM, clientKey := issue(3, x509.ExtKeyUsageClientAuth)
	dir := t.TempDir()
	pki := syslogTestPKI{caFile: filepath.Join(dir, "ca.pem"), certFile: filepath.Join(dir, "client.pem"), keyFile: filepath.Join(dir, "client-key.pem"), server: server, roots: roots}
	for path, data := range map[string][]byte{pki.caFile: caPEM, pki.certFile: clientPEM, pki.keyFile: clientKey} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return pki
}

func TestSyslogTLSAndMutualTLSListener(t *testing.T) {
	pki := newSyslogTestPKI(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pki.server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pki.roots})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	cfg, err := loadSyslogConfig(syslogEnv(map[string]string{"ADDRESS": net.JoinHostPort("localhost", port), "FACILITY": "16", "CA_FILE": pki.caFile, "CERT_FILE": pki.certFile, "KEY_FILE": pki.keyFile}))
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan []byte, 1)
	errs := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errs <- err
			return
		}
		defer conn.Close()
		msg, err := readSyslogFrame(bufio.NewReader(conn))
		if err != nil {
			errs <- err
			return
		}
		received <- msg
	}()
	sender := syslogSender{config: *cfg}
	defer sender.close()
	ctx, cancel := context.WithTimeout(context.Background(), logDeliveryIOBudget)
	defer cancel()
	raw := json.RawMessage(`{"type":"tg.sentry.audit.v1","time":"2026-10-20T00:00:00.123456789Z","data":{"unicode":"日本語 😀"}}`)
	if err := sender.send(ctx, raw); err != nil {
		t.Fatal(err)
	}
	select {
	case msg := <-received:
		if !bytes.HasSuffix(msg, raw) {
			t.Fatal("TLS changed stored payload")
		}
	case err := <-errs:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestSyslogTLSFailuresNeverDowngrade(t *testing.T) {
	pki, wrong := newSyslogTestPKI(t), newSyslogTestPKI(t)
	for _, failure := range []string{"wrong-ca", "wrong-hostname", "missing-client-cert"} {
		t.Run(failure, func(t *testing.T) {
			// TLS 1.2 makes client authentication rejection observable in Handshake
			// before Write; TLS 1.3 may deliver the peer's alert only after a write.
			listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pki.server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pki.roots})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			errs := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err == nil {
					defer conn.Close()
					err = conn.(*tls.Conn).Handshake()
				}
				errs <- err
			}()
			_, port, _ := net.SplitHostPort(listener.Addr().String())
			values := map[string]string{"ADDRESS": net.JoinHostPort("localhost", port), "FACILITY": "16", "CA_FILE": pki.caFile, "CERT_FILE": pki.certFile, "KEY_FILE": pki.keyFile}
			switch failure {
			case "wrong-ca":
				values["CA_FILE"] = wrong.caFile
			case "wrong-hostname":
				values["ADDRESS"] = listener.Addr().String()
			case "missing-client-cert":
				delete(values, "CERT_FILE")
				delete(values, "KEY_FILE")
			}
			cfg, err := loadSyslogConfig(syslogEnv(values))
			if err != nil {
				t.Fatal(err)
			}
			sender := syslogSender{config: *cfg}
			defer sender.close()
			ctx, cancel := context.WithTimeout(context.Background(), logDeliveryIOBudget)
			defer cancel()
			if err := sender.send(ctx, []byte(`{"type":"ok","time":"2026-10-20T00:00:00Z"}`)); err == nil {
				t.Fatal("TLS failure accepted")
			}
			if sender.conn != nil || sender.config.transport != "tls" {
				t.Fatal("TLS failure retained/downgraded connection")
			}
			select {
			case err := <-errs:
				if err == nil {
					t.Fatal("server handshake unexpectedly succeeded")
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			// Any fallback would establish a second connection. A bounded accept
			// deadline uses the existing IO budget, not a new transport threshold.
			listener.Close()
		})
	}
}

func TestSyslogTLSConfigFileErrorsAreSanitized(t *testing.T) {
	pki := newSyslogTestPKI(t)
	bad := filepath.Join(t.TempDir(), "bad.pem")
	canary := "PRIVATE-KEY-CANARY-MUST-NOT-LEAK"
	if err := os.WriteFile(bad, []byte(canary), 0600); err != nil {
		t.Fatal(err)
	}
	for _, values := range []map[string]string{
		{"CA_FILE": "missing"}, {"CA_FILE": bad}, {"CERT_FILE": bad, "KEY_FILE": bad}, {"CERT_FILE": pki.certFile, "KEY_FILE": "missing"},
	} {
		values["ADDRESS"], values["FACILITY"] = "localhost", "16"
		if _, err := loadSyslogConfig(syslogEnv(values)); err == nil || strings.Contains(err.Error(), canary) || strings.Contains(err.Error(), bad) {
			t.Fatalf("unsanitized file error %v", err)
		}
	}
}

func TestSyslogDisconnectReconnectAndShortWrites(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	sender := syslogSender{config: syslogConfig{address: listener.Addr().String(), transport: "tcp", facility: 16}}
	defer sender.close()
	// A closed real TCP connection gives a deterministic detectable failure.
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	peer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	peer.Close()
	conn.Close()
	sender.conn = conn
	raw := json.RawMessage(`{"type":"ok","time":"2026-10-20T00:00:00Z"}`)
	if err := sender.send(context.Background(), raw); err == nil || sender.conn != nil {
		t.Fatal("disconnect not retained for retry")
	}
	received := make(chan []byte, 1)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		msg, err := readSyslogFrame(bufio.NewReader(c))
		if err == nil {
			received <- msg
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), logDeliveryIOBudget)
	defer cancel()
	if err := sender.send(ctx, raw); err != nil {
		t.Fatal(err)
	}
	select {
	case msg := <-received:
		if !bytes.HasSuffix(msg, raw) {
			t.Fatal("reconnect changed frame")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	// net.Conn guarantees a short Write returns an error. Exercise both a
	// short successful test double and zero-write/error branches defensively.
	for _, mode := range []string{"short", "zero", "error", "deadline"} {
		c := &shortSyslogConn{mode: mode}
		s := syslogSender{config: sender.config, conn: c}
		err := s.send(ctx, raw)
		if mode == "short" {
			if err != nil {
				t.Fatal(err)
			}
			msg, err := readSyslogFrame(bufio.NewReader(bytes.NewReader(c.Bytes())))
			if err != nil || !bytes.HasSuffix(msg, raw) {
				t.Fatal("short writes lost frame bytes")
			}
		} else if err == nil || s.conn != nil {
			t.Fatal("write failure not closed")
		}
	}
}

type shortSyslogConn struct {
	bytes.Buffer
	mode string
}

func (c *shortSyslogConn) Write(p []byte) (int, error) {
	switch c.mode {
	case "zero":
		return 0, nil
	case "error":
		return 0, io.ErrClosedPipe
	}
	return c.Buffer.Write(p[:1])
}
func (*shortSyslogConn) Read([]byte) (int, error)        { return 0, io.EOF }
func (*shortSyslogConn) Close() error                    { return nil }
func (*shortSyslogConn) LocalAddr() net.Addr             { return &net.TCPAddr{} }
func (*shortSyslogConn) RemoteAddr() net.Addr            { return &net.TCPAddr{} }
func (*shortSyslogConn) SetDeadline(time.Time) error     { return nil }
func (*shortSyslogConn) SetReadDeadline(time.Time) error { return nil }
func (c *shortSyslogConn) SetWriteDeadline(time.Time) error {
	if c.mode == "deadline" {
		return errors.New("injected")
	}
	return nil
}

func TestSyslogStalledReceiverDeadlineAndCancellation(t *testing.T) {
	for _, mode := range []string{"deadline", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			conn, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			peer, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			// Request the smallest OS send buffer, then exceed it. Buffer configuration
			// is test-only; no production event-size limit/truncation is introduced.
			if err := conn.(*net.TCPConn).SetWriteBuffer(1); err != nil {
				t.Fatal(err)
			}
			sender := syslogSender{config: syslogConfig{transport: "tcp", facility: 16}, conn: conn}
			defer sender.close()
			// Reuse scripts.go's existing 1 MiB maxReviewScriptBytes fixture size,
			// not a sender cap; the listener deliberately consumes no bytes.
			raw, _ := json.Marshal(map[string]any{"type": "ok", "time": "2026-10-20T00:00:00Z", "data": strings.Repeat("x", maxReviewScriptBytes)})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancel" {
				cancel()
			}
			started := time.Now()
			if err := sender.send(ctx, raw); err == nil {
				t.Fatal("stalled/cancelled write acknowledged")
			}
			elapsed := time.Since(started)
			t.Logf("%s elapsed=%s budget=%s", mode, elapsed, logDeliveryIOBudget)
			if mode == "deadline" && elapsed < logDeliveryIOBudget {
				t.Fatal("deadline test did not exercise configured IO budget")
			}
			if sender.conn != nil {
				t.Fatal("uncertain connection retained")
			}
		})
	}
}
