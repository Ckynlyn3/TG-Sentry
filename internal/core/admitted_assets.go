package core

import (
	"strings"
	"time"
)

// AdmittedAsset is a tenant-wide exception for an exact #42 captured subject.
// Family, SubjectDigest and SourceSnapshotID are immutable; display metadata
// cannot authorize different bytes. Publication and authenticated human-admin
// attribution belong to the existing protection review/confirm boundary.
//
// Precedents: Microsoft Defender file-hash indicators (independent protections
// remain authoritative) and Santa SHA-256 binary rules (changed bytes lose the
// match): https://learn.microsoft.com/en-us/defender-endpoint/indicator-file#policy-conflict-handling-for-file-indicators
// and https://northpole.dev/features/binary-authorization/.
// No expiry, grade restriction, wildcard, path matching or second hashing format.
type AdmittedAsset struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	Description      string            `json:"description"`
	Enabled          bool              `json:"enabled"`
	Family           SupplyChainFamily `json:"family"`
	SubjectDigest    string            `json:"subjectDigest"`
	SourceSnapshotID string            `json:"sourceSnapshotId"`
	CreatedAt        time.Time         `json:"createdAt"`
	UpdatedAt        time.Time         `json:"updatedAt"`
	CreatedBy        Actor             `json:"createdBy"`
	UpdatedBy        Actor             `json:"updatedBy"`
}

// AdmittedAssetCreateInput selects an existing trusted complete capture, not a
// client manifest. The server must resolve its family and recheck the expected
// digest before publication; syntax validation alone does not establish trust.
type AdmittedAssetCreateInput struct {
	Name                  string `json:"name"`
	Description           string `json:"description"`
	Enabled               bool   `json:"enabled"`
	SourceSnapshotID      string `json:"sourceSnapshotId"`
	ExpectedSubjectDigest string `json:"expectedSubjectDigest"`
}

// AdmittedAssetUpdateInput cannot change the admitted identity or provenance.
// Like ACL metadata replacement, omitted description/enabled use empty/false.
type AdmittedAssetUpdateInput struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

// Validate checks resource syntax, not capture trust or publisher authorization.
func (a AdmittedAsset) Validate() error {
	if strings.TrimSpace(a.ID) == "" || !validProtectionName(a.Name) ||
		!validAdmittedAssetFamily(a.Family) || !isSupplyChainHash(a.SubjectDigest) ||
		strings.TrimSpace(a.SourceSnapshotID) == "" {
		return ErrProtectionInvalid
	}
	return nil
}

func (in AdmittedAssetCreateInput) Validate() error {
	if !validProtectionName(in.Name) || strings.TrimSpace(in.SourceSnapshotID) == "" ||
		!isSupplyChainHash(in.ExpectedSubjectDigest) {
		return ErrProtectionInvalid
	}
	return nil
}

func (in AdmittedAssetUpdateInput) Validate() error {
	if !validProtectionName(in.Name) {
		return ErrProtectionInvalid
	}
	return nil
}

func validAdmittedAssetFamily(family SupplyChainFamily) bool {
	switch family {
	case SupplyChainFamilySkill, SupplyChainFamilyMCP, SupplyChainFamilyPlugin,
		SupplyChainFamilyBuiltinTool, SupplyChainFamilyMemoryFile:
		return true
	default:
		return false
	}
}

// MatchAdmission requires a list already scoped to the authenticated server
// tenant and a trusted, complete current capture. #42's constructor verifies
// membership syntax and digest consistency; it cannot establish that an unseen
// member was captured. That coverage proof remains the caller's responsibility.
// A match suppresses ONLY the supply-chain restriction. It never returns a
// terminal approve, changes findings, or exempts the call from other checks.
// The returned metadata is a copy; neither input is mutated.
func MatchAdmission(list []AdmittedAsset, family SupplyChainFamily, subject SupplyChainSubject) (*AdmittedAsset, bool) {
	if !validAdmittedAssetFamily(family) || !isSupplyChainHash(subject.Digest) {
		return nil, false
	}
	validated, err := NewSupplyChainSubject(subject.Files)
	if err != nil || validated.Digest != subject.Digest {
		return nil, false
	}
	for _, admission := range list {
		if admission.Enabled && admission.Family == family && admission.SubjectDigest == subject.Digest {
			return &admission, true
		}
	}
	return nil, false
}
