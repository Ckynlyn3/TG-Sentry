package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// DiscoveredAgentID binds an agent to one enrolled node and device-local account.
func DiscoveredAgentID(nodeID, accountID, family string) (string, error) {
	return tupleID(nodeID, accountID, family)
}

// AssetID uses the home-relative, slash-separated source path supplied by the
// endpoint. It never resolves a remote path using the server's filesystem rules.
func AssetID(nodeID, accountID, family, category, sourceRelPath, name string) (string, error) {
	return tupleID(nodeID, accountID, family, category, sourceRelPath, name)
}

func tupleID(parts ...string) (string, error) {
	// Reject lossy conversion before json.Marshal (RFC 7493 §2.1). A validated
	// string slice is always JSON-encodable; valid tuple bytes stay unchanged.
	if !validStrings(parts...) {
		return "", ErrInvalidReport
	}
	encoded, _ := json.Marshal(parts)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}
