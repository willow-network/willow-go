package willow

import (
	"context"
	"encoding/json"
	"fmt"
)

// CommitmentFrequency defines how often a provider must publish state root
// commitments on-chain for a private subgrove.
//
// JSON serialization matches Rust serde output:
//   - EveryUpdate   → "EveryUpdate"
//   - EveryNBlocks  → {"EveryNBlocks": n}
//   - EveryNSeconds → {"EveryNSeconds": n}
//   - Never         → "Never"
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
	// this subgrove. When empty, any indexer may participate.
	AllowedIndexers []string `json:"allowed_indexers,omitempty"`
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
	EphemeralPublicKey []byte `json:"ephemeral_public_key"`
	EncryptedKey       []byte `json:"encrypted_key"`
	GrantedBy          string `json:"granted_by"`
	GrantedAt          uint64 `json:"granted_at"`
}

// PrivacyOperations provides methods for managing private subgroves,
// including key grant management and key rotation.
type PrivacyOperations struct {
	client *Client
}

// GetMyKeyGrant retrieves the encryption key grant for the authenticated DID,
// allowing it to decrypt the subgrove's data.
func (p *PrivacyOperations) GetMyKeyGrant(ctx context.Context, subgroveID string) (*EncryptedKeyGrant, error) {
	if err := p.client.RequireAuth(); err != nil {
		return nil, err
	}

	identity := p.client.GetIdentity()
	path := fmt.Sprintf("/key-grants/%s/%s", subgroveID, identity.DID())
	var grant EncryptedKeyGrant
	if err := p.client.get(ctx, path, &grant); err != nil {
		return nil, err
	}
	return &grant, nil
}

// ListKeyGrantees retrieves the list of DIDs that have been granted access
// to a subgrove's encryption key. Only the subgrove owner or admin can call this.
func (p *PrivacyOperations) ListKeyGrantees(ctx context.Context, subgroveID string) ([]string, error) {
	if err := p.client.RequireAuth(); err != nil {
		return nil, err
	}

	path := fmt.Sprintf("/key-grants/%s", subgroveID)
	var grantees []string
	if err := p.client.get(ctx, path, &grantees); err != nil {
		return nil, err
	}
	return grantees, nil
}

// GetKeyGrantProof retrieves the GroveDB Merkle proof for a key grant.
// This is a public endpoint since proofs are non-sensitive.
func (p *PrivacyOperations) GetKeyGrantProof(ctx context.Context, subgroveID, did string) (json.RawMessage, error) {
	path := fmt.Sprintf("/proof/key-grant/%s/%s", subgroveID, did)
	var proof json.RawMessage
	if err := p.client.get(ctx, path, &proof); err != nil {
		return nil, err
	}
	return proof, nil
}

// grantSubgroveKeyRequest is the internal request body for the GrantSubgroveKey transaction.
type grantSubgroveKeyRequest struct {
	SubgroveID        string            `json:"subgrove_id"`
	EncryptedKeyGrant EncryptedKeyGrant `json:"encrypted_key_grant"`
	SenderDID         string            `json:"sender_did"`
	Signature         string            `json:"signature"`
	PublicKeyID       string            `json:"public_key_id"`
	Nonce             uint64            `json:"nonce"`
}

// GrantSubgroveKey broadcasts a GrantSubgroveKey transaction, granting the
// specified DID access to the subgrove's encryption key.
func (p *PrivacyOperations) GrantSubgroveKey(ctx context.Context, subgroveID string, grant EncryptedKeyGrant) error {
	if err := p.client.RequireAuth(); err != nil {
		return err
	}

	identity := p.client.GetIdentity()

	// Retrieve the current nonce for signing
	didInfo, err := p.client.GetDID(ctx, identity.DID())
	if err != nil {
		return fmt.Errorf("failed to get nonce: %w", err)
	}
	nonce := didInfo.Nonce + 1

	message := fmt.Sprintf("GrantSubgroveKey:%s:%s:%s:%d",
		subgroveID, grant.GranteeDID, identity.DID(), nonce)

	signature, err := identity.SignHex([]byte(message))
	if err != nil {
		return err
	}

	req := grantSubgroveKeyRequest{
		SubgroveID:        subgroveID,
		EncryptedKeyGrant: grant,
		SenderDID:         identity.DID(),
		Signature:         signature,
		PublicKeyID:       identity.PublicKeyID(),
		Nonce:             nonce,
	}

	tx := map[string]interface{}{
		"GrantSubgroveKey": req,
	}

	return p.client.post(ctx, "/broadcast_tx", tx, nil)
}

// revokeSubgroveKeyRequest is the internal request body for the RevokeSubgroveKey transaction.
type revokeSubgroveKeyRequest struct {
	SubgroveID string `json:"subgrove_id"`
	RevokeeDID string `json:"revokee_did"`
	SenderDID  string `json:"sender_did"`
	Signature  string `json:"signature"`
	PublicKeyID string `json:"public_key_id"`
	Nonce      uint64 `json:"nonce"`
}

// RevokeSubgroveKey broadcasts a RevokeSubgroveKey transaction, revoking
// the specified DID's access to the subgrove's encryption key.
func (p *PrivacyOperations) RevokeSubgroveKey(ctx context.Context, subgroveID, revokeeDID string) error {
	if err := p.client.RequireAuth(); err != nil {
		return err
	}

	identity := p.client.GetIdentity()

	didInfo, err := p.client.GetDID(ctx, identity.DID())
	if err != nil {
		return fmt.Errorf("failed to get nonce: %w", err)
	}
	nonce := didInfo.Nonce + 1

	message := fmt.Sprintf("RevokeSubgroveKey:%s:%s:%s:%d",
		subgroveID, revokeeDID, identity.DID(), nonce)

	signature, err := identity.SignHex([]byte(message))
	if err != nil {
		return err
	}

	req := revokeSubgroveKeyRequest{
		SubgroveID:  subgroveID,
		RevokeeDID:  revokeeDID,
		SenderDID:   identity.DID(),
		Signature:   signature,
		PublicKeyID: identity.PublicKeyID(),
		Nonce:       nonce,
	}

	tx := map[string]interface{}{
		"RevokeSubgroveKey": req,
	}

	return p.client.post(ctx, "/broadcast_tx", tx, nil)
}

// rotateSubgroveKeyRequest is the internal request body for the RotateSubgroveKey transaction.
type rotateSubgroveKeyRequest struct {
	SubgroveID string              `json:"subgrove_id"`
	NewEpoch   uint32              `json:"new_epoch"`
	NewGrants  []EncryptedKeyGrant `json:"new_grants"`
	SenderDID  string              `json:"sender_did"`
	Signature  string              `json:"signature"`
	PublicKeyID string             `json:"public_key_id"`
	Nonce      uint64              `json:"nonce"`
}

// RotateSubgroveKey broadcasts a RotateSubgroveKey transaction, rotating the
// subgrove encryption key to a new epoch and re-granting access to the
// specified DIDs with newly encrypted keys.
func (p *PrivacyOperations) RotateSubgroveKey(ctx context.Context, subgroveID string, newEpoch uint32, newGrants []EncryptedKeyGrant) error {
	if err := p.client.RequireAuth(); err != nil {
		return err
	}

	identity := p.client.GetIdentity()

	didInfo, err := p.client.GetDID(ctx, identity.DID())
	if err != nil {
		return fmt.Errorf("failed to get nonce: %w", err)
	}
	nonce := didInfo.Nonce + 1

	message := fmt.Sprintf("RotateSubgroveKey:%s:%d:%s:%d",
		subgroveID, newEpoch, identity.DID(), nonce)

	signature, err := identity.SignHex([]byte(message))
	if err != nil {
		return err
	}

	req := rotateSubgroveKeyRequest{
		SubgroveID:  subgroveID,
		NewEpoch:    newEpoch,
		NewGrants:   newGrants,
		SenderDID:   identity.DID(),
		Signature:   signature,
		PublicKeyID: identity.PublicKeyID(),
		Nonce:       nonce,
	}

	tx := map[string]interface{}{
		"RotateSubgroveKey": req,
	}

	return p.client.post(ctx, "/broadcast_tx", tx, nil)
}
