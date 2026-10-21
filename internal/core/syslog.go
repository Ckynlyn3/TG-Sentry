package core

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
	"unicode/utf8"
)

// Named local exception log-delivery-io-budget: 10 s dial/write budget,
// borrowed from franz-go v1.22.2 DialTimeout and measured with stalled collectors.
const logDeliveryIOBudget = 10 * time.Second

func syslogFrame(raw json.RawMessage, facility int) ([]byte, error) {
	var event struct {
		Type string    `json:"type"`
		Time time.Time `json:"time"`
	}
	if !utf8.Valid(raw) || json.Unmarshal(raw, &event) != nil || event.Time.IsZero() || !syslogHeaderField(event.Type, 32) || facility < 0 || facility > 23 {
		return nil, errors.New("invalid stored syslog event/header")
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return nil, errors.New("invalid stored syslog JSON")
	}
	// RFC 5424 §§6.2–6.4: at most six fractional digits; unavailable host/PID
	// are NILVALUE; UTF-8 MSG includes BOM. Original JSON time remains unchanged.
	timestamp := event.Time.UTC().Truncate(time.Microsecond).Format("2006-01-02T15:04:05.999999Z07:00")
	// Named local exception syslog-envelope-informational: severity 6 is only
	// the transport envelope; actual severity stays in OCSF. Facility is operator-selected.
	msg := []byte(fmt.Sprintf("<%d>1 %s - tg-sentry - %s - \xef\xbb\xbf", facility*8+6, timestamp, event.Type))
	msg = append(msg, compact.Bytes()...)
	// RFC 6587 §3.4.1 / RFC 5425 §4.3.1 count all message octets, not runes.
	return append([]byte(fmt.Sprintf("%d ", len(msg))), msg...), nil
}

func syslogHeaderField(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum {
		return false
	}
	for _, c := range []byte(value) {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}

type syslogSender struct {
	config syslogConfig
	conn   net.Conn // Owned by one destination worker, never concurrent sends.
}

func (s *syslogSender) close() {
	if s.conn != nil {
		_ = s.conn.Close()
		s.conn = nil
	}
}

func (s *syslogSender) send(ctx context.Context, raw json.RawMessage) error {
	frame, err := syslogFrame(raw, s.config.facility)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, logDeliveryIOBudget)
	defer cancel()
	if s.conn == nil {
		dialer := &net.Dialer{Timeout: logDeliveryIOBudget}
		if s.config.transport == "tls" {
			s.conn, err = (&tls.Dialer{NetDialer: dialer, Config: s.config.tls}).DialContext(ctx, "tcp", s.config.address)
		} else {
			s.conn, err = dialer.DialContext(ctx, "tcp", s.config.address)
		}
		if err != nil {
			return errors.New("syslog connect/verification failed")
		} // No TLS downgrade; no peer-controlled error text.
	}
	conn := s.conn
	deadline, _ := ctx.Deadline()
	if err = conn.SetWriteDeadline(deadline); err != nil {
		s.close()
		return errors.New("syslog write deadline failed")
	}
	// Cancellation closes an in-flight write immediately, before Engine closes DB.
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = conn.Close(); close(closed) })
	for len(frame) > 0 {
		var n int
		n, err = conn.Write(frame)
		if err != nil {
			break
		}
		if n == 0 {
			err = io.ErrShortWrite
			break
		}
		frame = frame[n:]
	}
	if !stop() {
		<-closed
	}
	if err != nil || ctx.Err() != nil {
		s.close()
		return errors.New("syslog write failed or cancelled")
	}
	return nil // RFC 5425 §6.3: socket success is not collector receipt/persistence.
}
