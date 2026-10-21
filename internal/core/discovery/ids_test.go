package discovery

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestIdentityGoldenJSONTuples(t *testing.T) {
	// Independently computed with Python hashlib.sha256 over compact JSON arrays.
	if got := testAgentID(t, "node", "501", "claude"); got != "a014fefcc8630363b90226de5baa0edf5477e873927989fdf6fa4bbfb96eefd3" {
		t.Fatalf("agent ID = %s", got)
	}
	got := testAssetID(t, "node", "501", "claude", "skills", ".claude/skills/review/SKILL.md", "review")
	if got != "9daf5ff72e426a46d2207625166f40dc9f52def3dea6e630abd3586179d68108" {
		t.Fatalf("asset ID = %s", got)
	}
	decoded, err := hex.DecodeString(got)
	if err != nil || len(decoded) != 32 || got != strings.ToLower(got) {
		t.Fatalf("ID is not lowercase SHA-256: %s", got)
	}
}

func TestAssetIdentityIncludesEveryTupleComponent(t *testing.T) {
	base := [6]string{"node", "501", "claude", "skills", ".claude/skills/review/SKILL.md", "review"}
	id := testAssetID(t, base[0], base[1], base[2], base[3], base[4], base[5])
	for i := range base {
		other := base
		other[i] += "other"
		if got := testAssetID(t, other[0], other[1], other[2], other[3], other[4], other[5]); got == id {
			t.Fatalf("component %d omitted from identity", i)
		}
	}
}

func TestIdentityIsUnambiguousAndPreservesObservedCase(t *testing.T) {
	if testAgentID(t, "a|b", "c", "d") == testAgentID(t, "a", "b|c", "d") {
		t.Fatal("ambiguous tuple boundaries")
	}
	if testAgentID(t, "node", "501", "claude") == testAgentID(t, "Node", "501", "claude") {
		t.Fatal("observed identity case was lost")
	}
	if testAssetID(t, "n", "a", "f", "memory", "Memory.md", "same") == testAssetID(t, "n", "a", "f", "memory", "memory.md", "same") {
		t.Fatal("observed path case was lost")
	}
}

func testAgentID(t *testing.T, node, account, family string) string {
	t.Helper()
	id, err := DiscoveredAgentID(node, account, family)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func testAssetID(t *testing.T, node, account, family, category, path, name string) string {
	t.Helper()
	id, err := AssetID(node, account, family, category, path, name)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
