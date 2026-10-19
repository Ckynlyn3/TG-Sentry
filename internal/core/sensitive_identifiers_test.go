package core

import (
	"strings"
	"testing"
	"time"
)

func TestSensitiveIdentifierChecksApplyWithoutDetectorEnabled(t *testing.T) {
	card, id := syntheticCard(), syntheticID()
	review := Review{SessionID: card, Agent: id}
	event := newReviewEvent(review, "synthetic-node", time.Unix(0, 0))
	if event.Data.Metadata.CorrelationUID == card || !strings.HasPrefix(event.Data.Metadata.CorrelationUID, "sha256:") {
		t.Fatal("PAN-like session ID leaked")
	}
	if strings.Contains(event.Data.Actor.AppUID, id) || !strings.Contains(event.Data.Actor.AppUID, "sha256:") {
		t.Fatal("ID-like agent ID leaked")
	}
	if eventIdentifier("ordinary-session-1") != "ordinary-session-1" || eventIdentifier("") != "" {
		t.Fatal("ordinary identifiers changed")
	}
	// Non-PAN length numeric opaque identifiers remain ordinary metadata.
	if eventIdentifier("123") != "123" {
		t.Fatal("short ordinary ID changed")
	}
}
