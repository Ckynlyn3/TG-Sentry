package core

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Independent RFC 6587 parser: the space-terminated decimal count measures bytes,
// not runes or TLS records; io.ReadFull also handles fragmented network reads.
func readSyslogFrame(r *bufio.Reader) ([]byte, error) {
	count, err := r.ReadString(' ')
	if err != nil {
		return nil, err
	}
	n, err := strconv.Atoi(strings.TrimSuffix(count, " "))
	if err != nil || n <= 0 {
		return nil, fmt.Errorf("invalid frame count %q", count)
	}
	msg := make([]byte, n)
	_, err = io.ReadFull(r, msg)
	return msg, err
}

func TestSyslogFrameUnicodePrecisionAndMultipleFrames(t *testing.T) {
	raw := json.RawMessage(`{ "type":"tg.sentry.risk.v1", "time":"2026-10-20T12:34:56.123456789Z", "id":"unchanged", "data":{"text":"日本語 é 😀\nnext", "number":9007199254740993} }`)
	frame, err := syslogFrame(raw, 16)
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(&fragmentedReader{data: append(append([]byte(nil), frame...), frame...)})
	for range 2 {
		msg, err := readSyslogFrame(reader)
		if err != nil {
			t.Fatal(err)
		}
		header := []byte("<134>1 2026-10-20T12:34:56.123456Z - tg-sentry - tg.sentry.risk.v1 - \xef\xbb\xbf")
		if !bytes.HasPrefix(msg, header) {
			t.Fatalf("unexpected header %q", msg)
		}
		var compact bytes.Buffer
		if err := json.Compact(&compact, raw); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(msg[len(header):], compact.Bytes()) {
			t.Fatal("MSG changed stored event bytes, timestamp, unknown fields or number")
		}
	}
	if _, err := reader.ReadByte(); err != io.EOF {
		t.Fatal("encoder appended delimiters beyond octet-counted frames")
	}
}

type fragmentedReader struct{ data []byte }

func (r *fragmentedReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	// One byte per read deliberately splits both UTF-8 and frame prefixes.
	p[0] = r.data[0]
	r.data = r.data[1:]
	return 1, nil
}

func TestSyslogHeaderValidation(t *testing.T) {
	for _, typ := range []string{"", "with space", "newline\n", "é", strings.Repeat("x", 33)} {
		raw, _ := json.Marshal(map[string]any{"type": typ, "time": time.Now()})
		if _, err := syslogFrame(raw, 0); err == nil {
			t.Fatalf("accepted invalid MSGID %q", typ)
		}
	}
	for _, raw := range []json.RawMessage{[]byte(`{`), []byte(`{"type":"ok","time":"bad"}`), []byte(`{"type":"ok"}`), []byte("{\"type\":\"ok\",\"time\":\"2026-10-20T00:00:00Z\",\"data\":\"\xff\"}")} {
		if _, err := syslogFrame(raw, 0); err == nil {
			t.Fatal("accepted invalid event")
		}
	}
	for _, facility := range []int{-1, 24} {
		if _, err := syslogFrame([]byte(`{"type":"ok","time":"2026-10-20T00:00:00Z"}`), facility); err == nil {
			t.Fatal("accepted invalid facility")
		}
	}
}

func TestSyslogTCPListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	received := make(chan []byte, 2)
	errs := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errs <- err
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		for range 2 {
			msg, err := readSyslogFrame(r)
			if err != nil {
				errs <- err
				return
			}
			received <- msg
		}
	}()
	sender := syslogSender{config: syslogConfig{address: listener.Addr().String(), transport: "tcp", facility: 16}}
	defer sender.close()
	ctx, cancel := context.WithTimeout(context.Background(), logDeliveryIOBudget)
	defer cancel()
	raw := json.RawMessage(`{"type":"tg.sentry.audit.v1","time":"2026-10-20T00:00:00Z","id":"one"}`)
	for range 2 {
		if err := sender.send(ctx, raw); err != nil {
			t.Fatal(err)
		}
		select {
		case msg := <-received:
			if !bytes.HasSuffix(msg, raw) {
				t.Fatal("listener payload changed")
			}
		case err := <-errs:
			t.Fatal(err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}
