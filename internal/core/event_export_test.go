package core

import (
	"aegishook/internal/teststore"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"
)

func TestStreamEventsParityFiltersAndCancellation(t *testing.T) {
	e := engine(t)
	now := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	risk := Event{ID: "risk", Type: "tg.sentry.risk.v1", Time: now, Data: EventData{SeverityID: 4, Actor: EventActor{AppUID: "agent"}, FindingInfo: &EventFinding{Types: []string{"category::behavior"}}}}
	audit := Event{ID: "audit", Type: "tg.sentry.audit.v1", Time: now}
	if err := e.put("audit", "export", Audit{Events: []Event{risk, audit}}); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(Audit{Events: []Event{risk}})
	if _, err := teststore.Admin(t, e.DB).Exec("INSERT INTO records(tenant_id,kind,id,payload) VALUES('foreign','audit','foreign',$1)", string(raw)); err != nil {
		t.Fatal(err)
	}
	filter := EventExportFilter{RiskEventFilter: RiskEventFilter{Severity: "high", Category: "category::behavior", Agent: "agent"}, Start: now, End: now}
	var got []Event
	err := e.StreamEvents(context.Background(), "tg.sentry.risk.v1", filter, func(raw json.RawMessage) error {
		var event Event
		if err := json.Unmarshal(raw, &event); err != nil {
			return err
		}
		got = append(got, event)
		return nil
	})
	if err != nil || !reflect.DeepEqual(got, []Event{risk}) {
		t.Fatal(got, err)
	}
	for _, f := range []EventExportFilter{
		{RiskEventFilter: RiskEventFilter{Agent: "missing"}},
		{RiskEventFilter: RiskEventFilter{Severity: "low"}},
		{RiskEventFilter: RiskEventFilter{Category: "category::prompt-attack"}},
		{Start: now.Add(time.Second)}, {End: now.Add(-time.Second)},
	} {
		if err := e.StreamEvents(context.Background(), risk.Type, f, func(json.RawMessage) error { t.Fatal("filter ignored"); return nil }); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []EventExportFilter{{RiskEventFilter: RiskEventFilter{Severity: "bad"}}, {RiskEventFilter: RiskEventFilter{Category: "bad"}}, {Start: now.Add(time.Second), End: now}} {
		if err := e.StreamEvents(context.Background(), risk.Type, f, func(json.RawMessage) error { return nil }); !errors.Is(err, ErrRiskEventQuery) {
			t.Fatal(err)
		}
	}
	stop := errors.New("writer stopped")
	if err := e.StreamEvents(context.Background(), audit.Type, EventExportFilter{}, func(json.RawMessage) error { return stop }); !errors.Is(err, stop) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := e.StreamEvents(ctx, audit.Type, EventExportFilter{}, func(json.RawMessage) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	// Callback failure/cancellation must release the only store connection.
	if err := e.put("audit", "still-usable", Audit{}); err != nil {
		t.Fatal(err)
	}
}

func TestStreamEventsPreservesUnknownFieldsAndStopsAtCorruption(t *testing.T) {
	e := engine(t)
	raw := `{"events":[{"type":"tg.sentry.risk.v1","id":"exact","extension":{"integer":9007199254740993},"data":{"future_ocsf":{"nested":[true,null,"line\nvalue"]}}}]}`
	if err := e.put("audit", "a", json.RawMessage(raw)); err != nil {
		t.Fatal(err)
	}
	// Corruption after the first record proves iteration delivers before reading all rows.
	if err := e.put("audit", "z", map[string]any{"events": "not-an-array"}); err != nil {
		t.Fatal(err)
	}
	count := 0
	err := e.StreamEvents(context.Background(), "tg.sentry.risk.v1", EventExportFilter{}, func(event json.RawMessage) error {
		count++
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(event, &obj); err != nil {
			return err
		}
		if string(obj["extension"]) != `{"integer":9007199254740993}` {
			t.Fatal(string(event))
		}
		return nil
	})
	if err == nil || count != 1 {
		t.Fatal("not incremental or corruption ignored", count, err)
	}
	if err := e.put("audit", "usable", Audit{}); err != nil {
		t.Fatal(err)
	}
}

func TestStreamEventsBoundedKeysetBatches(t *testing.T) {
	e := engine(t)
	if _, err := teststore.Admin(t, e.DB).Exec("DELETE FROM records WHERE tenant_id='default' AND kind='audit'"); err != nil {
		t.Fatal(err)
	}
	const count = eventExportBatchSize*2 + 1
	for i := 0; i < count; i++ {
		if err := e.put("audit", fmt.Sprintf("row-%03d", i), Audit{Events: []Event{{ID: fmt.Sprint(i), Type: "tg.sentry.audit.v1"}}}); err != nil {
			t.Fatal(err)
		}
	}
	after, upper, batches, total := "", "", 0, 0
	for {
		batch, bound, err := e.eventExportBatch(context.Background(), after, upper)
		if err != nil {
			t.Fatal(err)
		}
		if len(batch) > eventExportBatchSize || len(batch) == 0 {
			t.Fatal("unbounded or empty batch", len(batch))
		}
		upper = bound
		batches++
		total += len(batch)
		after = batch[len(batch)-1].id
		if len(batch) < eventExportBatchSize {
			break
		}
	}
	if batches != 3 || total != count {
		t.Fatal(batches, total)
	}
	delivered := 0
	err := e.StreamEvents(context.Background(), "tg.sentry.audit.v1", EventExportFilter{}, func(json.RawMessage) error {
		delivered++
		if e.DB.Stats().InUse != 0 {
			t.Fatal("connection held across callback")
		}
		if delivered == 1 {
			return e.put("audit", "zzz-new", Audit{Events: []Event{{ID: "new", Type: "tg.sentry.audit.v1"}}})
		}
		return nil
	})
	if err != nil || delivered != count {
		t.Fatal("upper bound or keyset lost", delivered, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	delivered = 0
	err = e.StreamEvents(ctx, "tg.sentry.audit.v1", EventExportFilter{}, func(json.RawMessage) error { delivered++; cancel(); return nil })
	if !errors.Is(err, context.Canceled) || delivered != 1 {
		t.Fatal(delivered, err)
	}
	if err = e.put("audit", "still-usable", Audit{}); err != nil {
		t.Fatal(err)
	}
}

func TestStreamEventsRejectsCorruptEvent(t *testing.T) {
	e := engine(t)
	if err := e.put("audit", "corrupt-event", map[string]any{"events": []any{"not-an-object"}}); err != nil {
		t.Fatal(err)
	}
	if err := e.StreamEvents(context.Background(), "tg.sentry.audit.v1", EventExportFilter{}, func(json.RawMessage) error { t.Fatal("corrupt event delivered"); return nil }); err == nil {
		t.Fatal("ignored event corruption")
	}
	if err := e.StreamEvents(context.Background(), "invalid-type", EventExportFilter{}, func(json.RawMessage) error { return nil }); !errors.Is(err, ErrRiskEventQuery) {
		t.Fatal(err)
	}
}
