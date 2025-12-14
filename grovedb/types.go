package grovedb

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// HashLength is the length of a cryptographic hash in bytes.
const HashLength = 32

// CryptoHash represents a 32-byte cryptographic hash.
type CryptoHash [HashLength]byte

// String returns the hex representation of the hash.
func (h CryptoHash) String() string {
	return hex.EncodeToString(h[:])
}

// IsZero returns true if the hash is all zeros.
func (h CryptoHash) IsZero() bool {
	for _, b := range h {
		if b != 0 {
			return false
		}
	}
	return true
}

// Equals checks if two hashes are equal.
func (h CryptoHash) Equals(other CryptoHash) bool {
	return h == other
}

// NullHash is an all-zeros hash.
var NullHash = CryptoHash{}

// HashFromBytes creates a CryptoHash from a byte slice.
func HashFromBytes(b []byte) CryptoHash {
	var h CryptoHash
	copy(h[:], b)
	return h
}

// HashFromHex creates a CryptoHash from a hex string.
func HashFromHex(s string) (CryptoHash, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return CryptoHash{}, err
	}
	if len(b) != HashLength {
		return CryptoHash{}, errors.New("invalid hash length")
	}
	return HashFromBytes(b), nil
}

// ComputeHash computes the SHA256 hash of data.
func ComputeHash(data []byte) CryptoHash {
	return sha256.Sum256(data)
}

// ValueHash computes the hash of a value (for Merk tree).
func ValueHash(value []byte) CryptoHash {
	return ComputeHash(value)
}

// ComputeNodeHash computes the hash of a Merk tree node.
// node_hash = H(kv_hash || left_hash || right_hash)
func ComputeNodeHash(kvHash, leftHash, rightHash CryptoHash) CryptoHash {
	combined := make([]byte, HashLength*3)
	copy(combined[0:HashLength], kvHash[:])
	copy(combined[HashLength:HashLength*2], leftHash[:])
	copy(combined[HashLength*2:HashLength*3], rightHash[:])
	return ComputeHash(combined)
}

// KVHash computes the key-value hash for a Merk tree node.
// kv_hash = H(key || value_hash)
func KVHash(key, value []byte) CryptoHash {
	valueH := ValueHash(value)
	combined := make([]byte, len(key)+HashLength)
	copy(combined[:len(key)], key)
	copy(combined[len(key):], valueH[:])
	return ComputeHash(combined)
}

// CombineHash combines two hashes using SHA256.
// Used for combining value_hash with subtree root hash.
func CombineHash(left, right CryptoHash) CryptoHash {
	combined := make([]byte, HashLength*2)
	copy(combined[:HashLength], left[:])
	copy(combined[HashLength:], right[:])
	return ComputeHash(combined)
}

// MerkOpType represents the type of a Merk operation.
type MerkOpType int

const (
	OpPush MerkOpType = iota
	OpPushInverted
	OpParent
	OpChild
	OpParentInverted
	OpChildInverted
)

// MerkNodeType represents the type of a Merk node.
type MerkNodeType int

const (
	NodeHash MerkNodeType = iota
	NodeKVHash
	NodeKV
	NodeKVValueHash
	NodeKVDigest
	NodeKVRefValueHash
	NodeKVValueHashFeatureType
)

// MerkNode represents a node in a Merk proof.
type MerkNode struct {
	Type        MerkNodeType
	Hash        CryptoHash // For Hash type
	KVHashVal   CryptoHash // For KVHash type
	Key         []byte     // For KV, KVValueHash, KVDigest, etc.
	Value       []byte     // For KV, KVValueHash, KVRefValueHash
	ValueHash   CryptoHash // For KVValueHash, KVDigest, KVRefValueHash
	FeatureType TreeFeatureType
}

// TreeFeatureType represents the feature type for sum/count trees.
type TreeFeatureType struct {
	Type  string
	Sum   int64
	Count int64
}

// MerkOp represents a Merk proof operation.
type MerkOp struct {
	Type MerkOpType
	Node *MerkNode // Only for Push/PushInverted
}

// ProveOptions contains options for proof generation.
type ProveOptions struct {
	DecreaseLimitOnEmptySubQueryResult bool
}

// LayerProof represents a proof for a single layer in the GroveDB tree.
type LayerProof struct {
	MerkProof   []byte
	LowerLayers map[string]*LayerProof // Keyed by hex-encoded key
}

// GroveDBProofV0 represents a version 0 GroveDB proof.
type GroveDBProofV0 struct {
	RootLayer    *LayerProof
	ProveOptions ProveOptions
}

// GroveDBProof represents a versioned GroveDB proof.
type GroveDBProof struct {
	Version int
	Proof   *GroveDBProofV0
}

// ProvedKeyValue represents a proven key-value pair.
type ProvedKeyValue struct {
	Key       []byte
	Value     []byte
	ProofHash CryptoHash
}

// VerificationResult represents the result of proof verification.
type VerificationResult struct {
	RootHash string
	Results  []QueryResult
}

// QueryResult represents a single result from verification.
type QueryResult struct {
	Path    [][]byte
	Key     []byte
	Value   []byte
	Element *Element
}

// ElementType represents the type of a GroveDB element.
type ElementType int

const (
	ElementItem ElementType = iota
	ElementReference
	ElementTree
	ElementSumTree
	ElementSumItem
	ElementBigSumTree
	ElementCountTree
	ElementCountSumTree
)

// Element represents a GroveDB element.
type Element struct {
	Type     ElementType
	Value    []byte
	RootKey  []byte
	SumValue int64
	Count    int64
	Flags    []byte
}

// IsTree returns true if the element is a tree type.
func (e *Element) IsTree() bool {
	switch e.Type {
	case ElementTree, ElementSumTree, ElementBigSumTree, ElementCountTree, ElementCountSumTree:
		return true
	default:
		return false
	}
}

// HasRootKey returns true if the element has a root key.
func (e *Element) HasRootKey() bool {
	return e.IsTree() && len(e.RootKey) > 0
}

// GroveDBVerificationError represents a verification error.
type GroveDBVerificationError struct {
	Message string
}

func (e *GroveDBVerificationError) Error() string {
	return e.Message
}

// NewVerificationError creates a new verification error.
func NewVerificationError(message string) *GroveDBVerificationError {
	return &GroveDBVerificationError{Message: message}
}
