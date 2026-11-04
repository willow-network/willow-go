package willow

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/willow-network/willow-go/consensus"
)

// CommitmentFrequency defines how often a provider must publish state root
// commitments on-chain for a private subgrove (see consensus.CommitmentFrequency).
type CommitmentFrequency = consensus.CommitmentFrequency

// NewCommitmentFrequencyEveryUpdate returns a CommitmentFrequency that commits
// after every write/block update (default, strongest freshness).
func NewCommitmentFrequencyEveryUpdate() CommitmentFrequency {
	return consensus.NewCommitmentFrequencyEveryUpdate()
}

// NewCommitmentFrequencyNever returns a CommitmentFrequency that disables
// on-chain commitments.
func NewCommitmentFrequencyNever() CommitmentFrequency {
	return consensus.NewCommitmentFrequencyNever()
}

// NewCommitmentFrequencyEveryNBlocks returns a CommitmentFrequency that commits
// every n blocks processed.
func NewCommitmentFrequencyEveryNBlocks(n uint64) CommitmentFrequency {
	return consensus.NewCommitmentFrequencyEveryNBlocks(n)
}

// NewCommitmentFrequencyEveryNSeconds returns a CommitmentFrequency that commits
// at least every n seconds.
func NewCommitmentFrequencyEveryNSeconds(n uint64) CommitmentFrequency {
	return consensus.NewCommitmentFrequencyEveryNSeconds(n)
}

// PrivacyConfig contains privacy configuration for a private subgrove (see
// consensus.PrivacyConfig).
type PrivacyConfig = consensus.PrivacyConfig

// EncryptedKeyGrant represents an encrypted key grant for a subgrove,
// allowing a specific DID to decrypt the subgrove's data (see
// consensus.EncryptedKeyGrant).
type EncryptedKeyGrant = consensus.EncryptedKeyGrant

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
	var grant *EncryptedKeyGrant
	if err := p.client.getData(ctx, path, &grant); err != nil {
		return nil, err
	}
	if grant == nil {
		return nil, NewNotFoundError("key grant")
	}
	return grant, nil
}

// ListKeyGrantees retrieves the list of DIDs that have been granted access
// to a subgrove's encryption key. Only the subgrove owner or admin can call this.
func (p *PrivacyOperations) ListKeyGrantees(ctx context.Context, subgroveID string) ([]string, error) {
	if err := p.client.RequireAuth(); err != nil {
		return nil, err
	}

	path := fmt.Sprintf("/key-grants/%s", subgroveID)
	var grantees []string
	if err := p.client.getData(ctx, path, &grantees); err != nil {
		return nil, err
	}
	return grantees, nil
}

// GetKeyGrantProof retrieves the GroveDB Merkle proof for a key grant: the
// data of the API's answer, {"proof": <hex>, "subgrove_id": ..., "grantee_did": ...}.
func (p *PrivacyOperations) GetKeyGrantProof(ctx context.Context, subgroveID, did string) (json.RawMessage, error) {
	path := fmt.Sprintf("/proof/key-grant/%s/%s", subgroveID, did)
	var proof json.RawMessage
	if err := p.client.getData(ctx, path, &proof); err != nil {
		return nil, err
	}
	return proof, nil
}

// grantSubgroveKeyRequest is the internal request body for the GrantSubgroveKey transaction.
type grantSubgroveKeyRequest struct {
	SubgroveID        string              `json:"subgrove_id"`
	EncryptedKeyGrant EncryptedKeyGrant   `json:"encrypted_key_grant"`
	SenderDID         string              `json:"sender_did"`
	Signature         consensus.ByteArray `json:"signature"`
	PublicKeyID       string              `json:"public_key_id"`
	Nonce             uint64              `json:"nonce"`
}

// GrantSubgroveKey broadcasts a GrantSubgroveKey transaction, granting the
// specified DID access to the subgrove's encryption key. It is signed over
// FormatGrantSubgroveKeyMessage, which binds every field of the grant and the
// transaction's nonce (see Client.NextNonce). It returns once CheckTx accepts
// the transaction, with the nonce and transaction hash.
func (p *PrivacyOperations) GrantSubgroveKey(ctx context.Context, subgroveID string, grant EncryptedKeyGrant) (*WriteResult, error) {
	if err := p.client.RequireAuth(); err != nil {
		return nil, err
	}

	identity := p.client.GetIdentity()
	return p.client.signedWrite(ctx, identity.DID(), func(nonce uint64) (interface{}, error) {
		message, err := FormatGrantSubgroveKeyMessage(subgroveID, identity.DID(), grant, nonce)
		if err != nil {
			return nil, err
		}
		signature, err := identity.Sign([]byte(message))
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{
			"GrantSubgroveKey": grantSubgroveKeyRequest{
				SubgroveID:        subgroveID,
				EncryptedKeyGrant: grant,
				SenderDID:         identity.DID(),
				Signature:         signature,
				PublicKeyID:       identity.PublicKeyID(),
				Nonce:             nonce,
			},
		}, nil
	})
}

// revokeSubgroveKeyRequest is the internal request body for the RevokeSubgroveKey transaction.
type revokeSubgroveKeyRequest struct {
	SubgroveID  string              `json:"subgrove_id"`
	RevokeeDID  string              `json:"revokee_did"`
	SenderDID   string              `json:"sender_did"`
	Signature   consensus.ByteArray `json:"signature"`
	PublicKeyID string              `json:"public_key_id"`
	Nonce       uint64              `json:"nonce"`
}

// RevokeSubgroveKey broadcasts a RevokeSubgroveKey transaction, revoking
// the specified DID's access to the subgrove's encryption key. It returns once
// CheckTx accepts the transaction, with the nonce and transaction hash.
func (p *PrivacyOperations) RevokeSubgroveKey(ctx context.Context, subgroveID, revokeeDID string) (*WriteResult, error) {
	if err := p.client.RequireAuth(); err != nil {
		return nil, err
	}

	identity := p.client.GetIdentity()
	return p.client.signedWrite(ctx, identity.DID(), func(nonce uint64) (interface{}, error) {
		message := fmt.Sprintf("RevokeSubgroveKey:%s:%s:%s:%d",
			subgroveID, revokeeDID, identity.DID(), nonce)
		signature, err := identity.Sign([]byte(message))
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{
			"RevokeSubgroveKey": revokeSubgroveKeyRequest{
				SubgroveID:  subgroveID,
				RevokeeDID:  revokeeDID,
				SenderDID:   identity.DID(),
				Signature:   signature,
				PublicKeyID: identity.PublicKeyID(),
				Nonce:       nonce,
			},
		}, nil
	})
}

// rotateSubgroveKeyRequest is the internal request body for the RotateSubgroveKey transaction.
type rotateSubgroveKeyRequest struct {
	SubgroveID  string              `json:"subgrove_id"`
	NewEpoch    uint32              `json:"new_epoch"`
	NewGrants   []EncryptedKeyGrant `json:"new_grants"`
	SenderDID   string              `json:"sender_did"`
	Signature   consensus.ByteArray `json:"signature"`
	PublicKeyID string              `json:"public_key_id"`
	Nonce       uint64              `json:"nonce"`
}

// RotateSubgroveKey broadcasts a RotateSubgroveKey transaction, rotating the
// subgrove encryption key to a new epoch and re-granting access to the
// specified DIDs with newly encrypted keys. It is signed over
// FormatRotateSubgroveKeyMessage, which binds every grant, their order and
// count, and the transaction's nonce. It returns once CheckTx accepts the
// transaction, with the nonce and transaction hash.
func (p *PrivacyOperations) RotateSubgroveKey(ctx context.Context, subgroveID string, newEpoch uint32, newGrants []EncryptedKeyGrant) (*WriteResult, error) {
	if err := p.client.RequireAuth(); err != nil {
		return nil, err
	}

	identity := p.client.GetIdentity()
	if newGrants == nil {
		// Sent as an empty list: the chain reads new_grants as a list.
		newGrants = []EncryptedKeyGrant{}
	}
	return p.client.signedWrite(ctx, identity.DID(), func(nonce uint64) (interface{}, error) {
		message, err := FormatRotateSubgroveKeyMessage(subgroveID, identity.DID(), newEpoch, newGrants, nonce)
		if err != nil {
			return nil, err
		}
		signature, err := identity.Sign([]byte(message))
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{
			"RotateSubgroveKey": rotateSubgroveKeyRequest{
				SubgroveID:  subgroveID,
				NewEpoch:    newEpoch,
				NewGrants:   newGrants,
				SenderDID:   identity.DID(),
				Signature:   signature,
				PublicKeyID: identity.PublicKeyID(),
				Nonce:       nonce,
			},
		}, nil
	})
}
