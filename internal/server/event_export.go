package server

import (
	"aegishook/internal/core"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

// csv-nested-json is the existing EVENT-SCHEMA §6 projection: nested OCSF
// objects/arrays stay JSON cells; no new event representation is persisted.
var eventCSVColumns = []string{
	"specversion", "id", "source", "type", "time", "datacontenttype",
	"data.category_uid", "data.class_uid", "data.activity_id", "data.activity_name",
	"data.type_uid", "data.severity_id", "data.time", "data.metadata", "data.actor",
	"data.finding_info", "data.action_id", "data.disposition_id", "data.src_endpoint",
	"data.api", "data.status_id", "data.unmapped",
}

func eventExportFilter(r *http.Request) (core.EventExportFilter, error) {
	q := r.URL.Query()
	filter := core.EventExportFilter{RiskEventFilter: core.RiskEventFilter{Severity: q.Get("severity"), Category: q.Get("category"), Agent: q.Get("agent")}}
	for key, dst := range map[string]*time.Time{"start": &filter.Start, "end": &filter.End} {
		if value := q.Get(key); value != "" {
			parsed, err := time.Parse(time.RFC3339Nano, value)
			if err != nil || parsed.IsZero() {
				return filter, core.ErrRiskEventQuery
			}
			*dst = parsed
		}
	}
	return filter, nil
}

func (s *Server) eventExport(w http.ResponseWriter, r *http.Request, eventType string) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "jsonl" && format != "csv" {
		fail(w, 400, errors.New("format must be csv, json or jsonl"))
		return
	}
	filter, err := eventExportFilter(r)
	if err != nil {
		fail(w, 400, err)
		return
	}
	name := "risk-events"
	if eventType == "tg.sentry.audit.v1" {
		name = "audit"
	}
	out := eventExportWriter{w: w, format: format, name: name}
	err = s.Engine.StreamEvents(r.Context(), eventType, filter, out.write)
	if err == nil {
		err = out.finish()
	}
	if err == nil {
		return
	}
	if out.started {
		// net/http terminates the response (including HTTP/2 streams). Never append
		// an error event or a closing bracket that could imply a complete export.
		panic(http.ErrAbortHandler)
	}
	if errors.Is(err, core.ErrRiskEventQuery) {
		fail(w, 400, err)
		return
	}
	fail(w, 500, errors.New("event export unavailable"))
}

type eventExportWriter struct {
	w            http.ResponseWriter
	format, name string
	started      bool
	count        int
}

func (out *eventExportWriter) start() error {
	if out.started {
		return nil
	}
	out.started = true
	contentType := "application/cloudevents-batch+json"
	if out.format == "jsonl" {
		contentType = "application/x-ndjson"
	}
	if out.format == "csv" {
		contentType = "text/csv; charset=utf-8"
	}
	out.w.Header().Set("Content-Type", contentType)
	out.w.Header().Set("Content-Disposition", `attachment; filename="tg-sentry-`+out.name+`.`+out.format+`"`)
	if out.format == "json" {
		_, err := io.WriteString(out.w, "[")
		return err
	}
	if out.format == "csv" {
		return writeEventCSVRecord(out.w, eventCSVColumns)
	}
	return nil
}

func (out *eventExportWriter) write(event json.RawMessage) error {
	if err := out.start(); err != nil {
		return err
	}
	if out.format == "csv" {
		record, err := eventCSVRecord(event)
		if err != nil {
			return err
		}
		if err = writeEventCSVRecord(out.w, record); err != nil {
			return err
		}
	} else {
		if out.format == "json" && out.count > 0 {
			if _, err := io.WriteString(out.w, ","); err != nil {
				return err
			}
		}
		if err := json.NewEncoder(out.w).Encode(event); err != nil {
			return err
		}
	}
	out.count++
	return http.NewResponseController(out.w).Flush()
}

func (out *eventExportWriter) finish() error {
	if err := out.start(); err != nil {
		return err
	}
	if out.format == "json" {
		if _, err := io.WriteString(out.w, "]\n"); err != nil {
			return err
		}
	}
	// Make the empty JSONL response a 200 attachment as well.
	return http.NewResponseController(out.w).Flush()
}

func eventCSVRecord(event json.RawMessage) ([]string, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(event, &envelope); err != nil {
		return nil, err
	}
	var data map[string]json.RawMessage
	if err := json.Unmarshal(envelope["data"], &data); err != nil {
		return nil, err
	}
	record := make([]string, len(eventCSVColumns))
	for i, column := range eventCSVColumns {
		value := envelope[column]
		if field, ok := strings.CutPrefix(column, "data."); ok {
			value = data[field]
		}
		if len(value) == 0 {
			continue
		}
		cell := string(value)
		if value[0] == '"' {
			if err := json.Unmarshal(value, &cell); err != nil {
				return nil, err
			}
		}
		// OWASP CSV Injection: neutralize formula/control prefixes before RFC4180
		// quoting, including LF and full-width variants in the current guidance.
		if cell != "" && strings.ContainsRune("=+-@\t\r\n＝＋－＠", []rune(cell)[0]) {
			cell = "'" + cell
		}
		record[i] = cell
	}
	return record, nil
}

func writeEventCSVRecord(w io.Writer, record []string) error {
	// Keep embedded CR bytes intact (csv.Writer.UseCRLF strips them). Only the
	// record terminator changes to RFC4180 CRLF; memory is bounded to one row.
	var line bytes.Buffer
	writer := csv.NewWriter(&line)
	if err := writer.Write(record); err != nil {
		return err
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return err
	}
	raw := line.Bytes()
	if _, err := w.Write(raw[:len(raw)-1]); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\r\n")
	return err
}
