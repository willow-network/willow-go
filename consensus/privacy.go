package consensus

import (
	"encoding/json"
	"fmt"
)

// CommitmentFrequency defines how often a provider must publish state root
// commitments on-chain for a private subgrove.
//
// JSON serialization matches the chain's (Rust serde) encoding:
//   - EveryUpdate   → "EveryUpdate"
//   - EveryNBlocks  → {"EveryNBlocks": n}
//   - EveryNSeconds → {"EveryNSeconds": n}
//   - Never         → "Never"
//
// The zero value is EveryUpdate.
type CommitmentFrequency struct {
	variant string
	n       uint64
}

// NewCommitmentFrequencyEveryUpdate returns a CommitmentFrequency that commits
// after every write/block update (default, strongest freshness).
func NewCommitmentFrequencyEveryUpdate() CommitmentFrequency {
	return CommitmentFrequency{variant: "EveryUpdate"}
}

// NewCommitmentFrequencyNever returns a CommitmentFrequency that disables
// on-chain commitments.
func NewCommitmentFrequencyNever() CommitmentFrequency {
	return CommitmentFrequency{variant: "Never"}
}

// NewCommitmentFrequencyEveryNBlocks returns a CommitmentFrequency that commits
// every n blocks processed.
func NewCommitmentFrequencyEveryNBlocks(n uint64) CommitmentFrequency {
	return CommitmentFrequency{variant: "EveryNBlocks", n: n}
}

// NewCommitmentFrequencyEveryNSeconds returns a CommitmentFrequency that commits
// at least every n seconds.
func NewCommitmentFrequencyEveryNSeconds(n uint64) CommitmentFrequency {
	return CommitmentFrequency{variant: "EveryNSeconds", n: n}
}

// MarshalJSON implements json.Marshaler, producing JSON matching the Rust serde format.
func (cf CommitmentFrequency) MarshalJSON() ([]byte, error) {
	switch cf.variant {
	case "EveryUpdate", "Never":
		return json.Marshal(cf.variant)
	case "EveryNBlocks":
		return json.Marshal(map[string]uint64{"EveryNBlocks": cf.n})
	case "EveryNSeconds":
		return json.Marshal(map[string]uint64{"EveryNSeconds": cf.n})
	default:
		return json.Marshal("EveryUpdate")
	}
}

// UnmarshalJSON implements json.Unmarshaler, parsing JSON in the Rust serde format.
func (cf *CommitmentFrequency) UnmarshalJSON(data []byte) error {
	// Try as a plain string first ("EveryUpdate" or "Never").
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		switch s {
		case "EveryUpdate", "Never":
			cf.variant = s
			cf.n = 0
			return nil
		default:
			return fmt.Errorf("unknown CommitmentFrequency variant: %q", s)
		}
	}

	// Try as an object ({"EveryNBlocks": n} or {"EveryNSeconds": n}).
	var obj map[string]uint64
	if err := json.Unmarshal(data, &obj); err != nil {
		return fmt.Errorf("invalid CommitmentFrequency JSON: %s", string(data))
	}

	if n, ok := obj["EveryNBlocks"]; ok {
		cf.variant = "EveryNBlocks"
		cf.n = n
		return nil
	}
	if n, ok := obj["EveryNSeconds"]; ok {
		cf.variant = "EveryNSeconds"
		cf.n = n
		return nil
	}

	return fmt.Errorf("unknown CommitmentFrequency object: %s", string(data))
}

// PrivacyConfig contains privacy configuration for a private subgrove.
type PrivacyConfig struct {
	// AllowedIndexers is an optional whitelist of indexer DIDs allowed to index
	// this subgrove: nil lets any indexer participate (sent as null), and a
	// non-nil list, even an empty one, admits only the DIDs on it.
	AllowedIndexers []string `json:"allowed_indexers"`
	// CommitmentFrequency controls how often the provider must publish state
	// root commitments on-chain.
	CommitmentFrequency CommitmentFrequency `json:"commitment_frequency"`
}

// EncryptedKeyGrant represents an encrypted key grant for a subgrove,
// allowing a specific DID to decrypt the subgrove's data.
type EncryptedKeyGrant struct {
	GranteeDID         string `json:"grantee_did"`
	KeyEpoch           uint32 `json:"key_epoch"`
	GranteePublicKeyID string `json:"grantee_public_key_id"`
	// Byte fields are JSON arrays of numbers, as the chain's types encode them.
	EphemeralPublicKey ByteArray `json:"ephemeral_public_key"`
	EncryptedKey       ByteArray `json:"encrypted_key"`
	GrantedBy          string    `json:"granted_by"`
	GrantedAt          uint64    `json:"granted_at"`
}
