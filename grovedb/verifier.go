package grovedb

import (
	"bytes"
	"encoding/hex"
	"fmt"
)

// Merk operation codes
const (
	opPushHash                           = 0x01
	opPushKVHash                         = 0x02
	opPushKV                             = 0x03
	opPushKVValueHash                    = 0x04
	opPushKVDigest                       = 0x05
	opPushKVRefValueHash                 = 0x06
	opPushKVValueHashFeatureType         = 0x07
	opPushInvertedHash                   = 0x08
	opPushInvertedKVHash                 = 0x09
	opPushInvertedKV                     = 0x0a
	opPushInvertedKVValueHash            = 0x0b
	opPushInvertedKVDigest               = 0x0c
	opPushInvertedKVRefValueHash         = 0x0d
	opPushInvertedKVValueHashFeatureType = 0x0e
	opParent                             = 0x10
	opChild                              = 0x11
	opParentInverted                     = 0x12
	opChildInverted                      = 0x13
)

// Tree represents a node in the Merk AVL tree.
type Tree struct {
	node         *MerkNode
	left         *Tree
	right        *Tree
	childHeights [2]int // [left, right]
}

// NewTree creates a new tree node.
func NewTree(node *MerkNode) *Tree {
	return &Tree{
		node:         node,
		childHeights: [2]int{0, 0},
	}
}

// Height returns the height of this tree.
func (t *Tree) Height() int {
	leftH := t.childHeights[0]
	rightH := t.childHeights[1]
	if leftH > rightH {
		return leftH + 1
	}
	return rightH + 1
}

// Hash computes the hash of this tree node.
func (t *Tree) Hash() CryptoHash {
	if t.node == nil {
		return NullHash
	}

	// Get KV hash
	var kvHash CryptoHash
	switch t.node.Type {
	case NodeHash:
		return t.node.Hash
	case NodeKVHash:
		kvHash = t.node.KVHashVal
	case NodeKV:
		kvHash = KVHash(t.node.Key, t.node.Value)
	case NodeKVValueHash, NodeKVRefValueHash, NodeKVValueHashFeatureType:
		// kv_hash = H(key || value_hash)
		combined := make([]byte, len(t.node.Key)+HashLength)
		copy(combined[:len(t.node.Key)], t.node.Key)
		copy(combined[len(t.node.Key):], t.node.ValueHash[:])
		kvHash = ComputeHash(combined)
	case NodeKVDigest:
		combined := make([]byte, len(t.node.Key)+HashLength)
		copy(combined[:len(t.node.Key)], t.node.Key)
		copy(combined[len(t.node.Key):], t.node.ValueHash[:])
		kvHash = ComputeHash(combined)
	}

	// Get child hashes
	var leftHash, rightHash CryptoHash
	if t.left != nil {
		leftHash = t.left.Hash()
	}
	if t.right != nil {
		rightHash = t.right.Hash()
	}

	return ComputeNodeHash(kvHash, leftHash, rightHash)
}

// IntoHash converts this tree to a hash-only tree.
func (t *Tree) IntoHash() *Tree {
	h := t.Hash()
	return &Tree{
		node: &MerkNode{
			Type: NodeHash,
			Hash: h,
		},
		childHeights: t.childHeights,
	}
}

// AttachWithHeight attaches a child tree with its height.
func (t *Tree) AttachWithHeight(isLeft bool, child *Tree, height int) {
	if isLeft {
		t.left = child
		t.childHeights[0] = height
	} else {
		t.right = child
		t.childHeights[1] = height
	}
}

// MerkDecoder decodes Merk proof operations from bytes.
type MerkDecoder struct {
	data   []byte
	offset int
}

// NewMerkDecoder creates a new decoder.
func NewMerkDecoder(data []byte) *MerkDecoder {
	return &MerkDecoder{data: data, offset: 0}
}

// HasMore returns true if there are more operations to decode.
func (d *MerkDecoder) HasMore() bool {
	return d.offset < len(d.data)
}

// Next decodes the next operation.
func (d *MerkDecoder) Next() (*MerkOp, error) {
	if !d.HasMore() {
		return nil, nil
	}

	opCode := d.data[d.offset]
	d.offset++

	switch opCode {
	// Push variants
	case opPushHash:
		node, err := d.decodeHash()
		if err != nil {
			return nil, err
		}
		return &MerkOp{Type: OpPush, Node: node}, nil
	case opPushKVHash:
		node, err := d.decodeKVHash()
		if err != nil {
			return nil, err
		}
		return &MerkOp{Type: OpPush, Node: node}, nil
	case opPushKV:
		node, err := d.decodeKV()
		if err != nil {
			return nil, err
		}
		return &MerkOp{Type: OpPush, Node: node}, nil
	case opPushKVValueHash:
		node, err := d.decodeKVValueHash()
		if err != nil {
			return nil, err
		}
		return &MerkOp{Type: OpPush, Node: node}, nil
	case opPushKVDigest:
		node, err := d.decodeKVDigest()
		if err != nil {
			return nil, err
		}
		return &MerkOp{Type: OpPush, Node: node}, nil
	case opPushKVRefValueHash:
		node, err := d.decodeKVRefValueHash()
		if err != nil {
			return nil, err
		}
		return &MerkOp{Type: OpPush, Node: node}, nil

	// Push inverted variants
	case opPushInvertedHash:
		node, err := d.decodeHash()
		if err != nil {
			return nil, err
		}
		return &MerkOp{Type: OpPushInverted, Node: node}, nil
	case opPushInvertedKVHash:
		node, err := d.decodeKVHash()
		if err != nil {
			return nil, err
		}
		return &MerkOp{Type: OpPushInverted, Node: node}, nil
	case opPushInvertedKV:
		node, err := d.decodeKV()
		if err != nil {
			return nil, err
		}
		return &MerkOp{Type: OpPushInverted, Node: node}, nil
	case opPushInvertedKVValueHash:
		node, err := d.decodeKVValueHash()
		if err != nil {
			return nil, err
		}
		return &MerkOp{Type: OpPushInverted, Node: node}, nil
	case opPushInvertedKVDigest:
		node, err := d.decodeKVDigest()
		if err != nil {
			return nil, err
		}
		return &MerkOp{Type: OpPushInverted, Node: node}, nil
	case opPushInvertedKVRefValueHash:
		node, err := d.decodeKVRefValueHash()
		if err != nil {
			return nil, err
		}
		return &MerkOp{Type: OpPushInverted, Node: node}, nil

	// Tree operations
	case opParent:
		return &MerkOp{Type: OpParent}, nil
	case opChild:
		return &MerkOp{Type: OpChild}, nil
	case opParentInverted:
		return &MerkOp{Type: OpParentInverted}, nil
	case opChildInverted:
		return &MerkOp{Type: OpChildInverted}, nil

	default:
		return nil, NewVerificationError(fmt.Sprintf("unknown op code: 0x%02x", opCode))
	}
}

func (d *MerkDecoder) decodeHash() (*MerkNode, error) {
	hash, err := d.readBytes(HashLength)
	if err != nil {
		return nil, err
	}
	return &MerkNode{Type: NodeHash, Hash: HashFromBytes(hash)}, nil
}

func (d *MerkDecoder) decodeKVHash() (*MerkNode, error) {
	hash, err := d.readBytes(HashLength)
	if err != nil {
		return nil, err
	}
	return &MerkNode{Type: NodeKVHash, KVHashVal: HashFromBytes(hash)}, nil
}

func (d *MerkDecoder) decodeKV() (*MerkNode, error) {
	if d.offset >= len(d.data) {
		return nil, NewVerificationError("unexpected end of data reading key length")
	}
	keyLen := int(d.data[d.offset])
	d.offset++

	key, err := d.readBytes(keyLen)
	if err != nil {
		return nil, err
	}

	valueLen, err := d.readU16()
	if err != nil {
		return nil, err
	}

	value, err := d.readBytes(int(valueLen))
	if err != nil {
		return nil, err
	}

	return &MerkNode{Type: NodeKV, Key: key, Value: value}, nil
}

func (d *MerkDecoder) decodeKVValueHash() (*MerkNode, error) {
	if d.offset >= len(d.data) {
		return nil, NewVerificationError("unexpected end of data reading key length")
	}
	keyLen := int(d.data[d.offset])
	d.offset++

	key, err := d.readBytes(keyLen)
	if err != nil {
		return nil, err
	}

	valueLen, err := d.readU16()
	if err != nil {
		return nil, err
	}

	value, err := d.readBytes(int(valueLen))
	if err != nil {
		return nil, err
	}

	valueHash, err := d.readBytes(HashLength)
	if err != nil {
		return nil, err
	}

	return &MerkNode{
		Type:      NodeKVValueHash,
		Key:       key,
		Value:     value,
		ValueHash: HashFromBytes(valueHash),
	}, nil
}

func (d *MerkDecoder) decodeKVDigest() (*MerkNode, error) {
	if d.offset >= len(d.data) {
		return nil, NewVerificationError("unexpected end of data reading key length")
	}
	keyLen := int(d.data[d.offset])
	d.offset++

	key, err := d.readBytes(keyLen)
	if err != nil {
		return nil, err
	}

	valueHash, err := d.readBytes(HashLength)
	if err != nil {
		return nil, err
	}

	return &MerkNode{
		Type:      NodeKVDigest,
		Key:       key,
		ValueHash: HashFromBytes(valueHash),
	}, nil
}

func (d *MerkDecoder) decodeKVRefValueHash() (*MerkNode, error) {
	if d.offset >= len(d.data) {
		return nil, NewVerificationError("unexpected end of data reading key length")
	}
	keyLen := int(d.data[d.offset])
	d.offset++

	key, err := d.readBytes(keyLen)
	if err != nil {
		return nil, err
	}

	valueLen, err := d.readU16()
	if err != nil {
		return nil, err
	}

	value, err := d.readBytes(int(valueLen))
	if err != nil {
		return nil, err
	}

	valueHash, err := d.readBytes(HashLength)
	if err != nil {
		return nil, err
	}

	return &MerkNode{
		Type:      NodeKVRefValueHash,
		Key:       key,
		Value:     value,
		ValueHash: HashFromBytes(valueHash),
	}, nil
}

func (d *MerkDecoder) readU16() (uint16, error) {
	if d.offset+2 > len(d.data) {
		return 0, NewVerificationError("unexpected end of data reading u16")
	}
	// Big-endian u16
	value := uint16(d.data[d.offset])<<8 | uint16(d.data[d.offset+1])
	d.offset += 2
	return value, nil
}

func (d *MerkDecoder) readBytes(n int) ([]byte, error) {
	if d.offset+n > len(d.data) {
		return nil, NewVerificationError(fmt.Sprintf("unexpected end of data reading %d bytes", n))
	}
	result := make([]byte, n)
	copy(result, d.data[d.offset:d.offset+n])
	d.offset += n
	return result, nil
}

// MerkExecutionResult holds the result of executing a Merk proof.
type MerkExecutionResult struct {
	RootHash  CryptoHash
	ResultSet []ProvedKeyValue
}

// ExecuteMerkProof executes a Merk proof and returns the result.
func ExecuteMerkProof(proofBytes []byte) (*MerkExecutionResult, error) {
	decoder := NewMerkDecoder(proofBytes)
	stack := make([]*Tree, 0)
	resultSet := make([]ProvedKeyValue, 0)

	for decoder.HasMore() {
		op, err := decoder.Next()
		if err != nil {
			return nil, err
		}
		if op == nil {
			break
		}

		switch op.Type {
		case OpPush, OpPushInverted:
			// Collect key-value pairs
			if op.Node != nil {
				switch op.Node.Type {
				case NodeKV:
					resultSet = append(resultSet, ProvedKeyValue{
						Key:       op.Node.Key,
						Value:     op.Node.Value,
						ProofHash: ValueHash(op.Node.Value),
					})
				case NodeKVValueHash, NodeKVRefValueHash, NodeKVValueHashFeatureType:
					resultSet = append(resultSet, ProvedKeyValue{
						Key:       op.Node.Key,
						Value:     op.Node.Value,
						ProofHash: op.Node.ValueHash,
					})
				case NodeKVDigest:
					resultSet = append(resultSet, ProvedKeyValue{
						Key:       op.Node.Key,
						Value:     nil,
						ProofHash: op.Node.ValueHash,
					})
				}
			}
			stack = append(stack, NewTree(op.Node))

		case OpParent:
			// Pop parent and child, attach child as LEFT of parent
			if len(stack) < 2 {
				return nil, NewVerificationError("stack underflow on Parent")
			}
			parent := stack[len(stack)-1]
			child := stack[len(stack)-2]
			stack = stack[:len(stack)-2]

			childHeight := child.Height()
			childHash := child.IntoHash()
			parent.AttachWithHeight(true, childHash, childHeight)
			stack = append(stack, parent)

		case OpChild:
			// Pop child and parent, attach child as RIGHT of parent
			if len(stack) < 2 {
				return nil, NewVerificationError("stack underflow on Child")
			}
			child := stack[len(stack)-1]
			parent := stack[len(stack)-2]
			stack = stack[:len(stack)-2]

			childHeight := child.Height()
			childHash := child.IntoHash()
			parent.AttachWithHeight(false, childHash, childHeight)
			stack = append(stack, parent)

		case OpParentInverted:
			// Pop parent and child, attach child as RIGHT of parent
			if len(stack) < 2 {
				return nil, NewVerificationError("stack underflow on ParentInverted")
			}
			parent := stack[len(stack)-1]
			child := stack[len(stack)-2]
			stack = stack[:len(stack)-2]

			childHeight := child.Height()
			childHash := child.IntoHash()
			parent.AttachWithHeight(false, childHash, childHeight)
			stack = append(stack, parent)

		case OpChildInverted:
			// Pop child and parent, attach child as LEFT of parent
			if len(stack) < 2 {
				return nil, NewVerificationError("stack underflow on ChildInverted")
			}
			child := stack[len(stack)-1]
			parent := stack[len(stack)-2]
			stack = stack[:len(stack)-2]

			childHeight := child.Height()
			childHash := child.IntoHash()
			parent.AttachWithHeight(true, childHash, childHeight)
			stack = append(stack, parent)
		}
	}

	if len(stack) != 1 {
		return nil, NewVerificationError(fmt.Sprintf("expected proof to result in exactly one stack item, got %d", len(stack)))
	}

	tree := stack[0]

	// Verify AVL tree property
	heightDiff := tree.childHeights[0] - tree.childHeights[1]
	if heightDiff < 0 {
		heightDiff = -heightDiff
	}
	if heightDiff > 1 {
		return nil, NewVerificationError("expected proof to result in a valid AVL tree")
	}

	return &MerkExecutionResult{
		RootHash:  tree.Hash(),
		ResultSet: resultSet,
	}, nil
}

// bincodeReader reads the bincode-2 "standard" encoding grovedb uses for
// GroveDBProof: big-endian, varint integers (tag < 251 literal; 251 = u16,
// 252 = u32, 253 = u64 follow), length-prefixed byte vectors, one-byte bools.
type bincodeReader struct {
	data []byte
	off  int
}

func (r *bincodeReader) varint() (uint64, error) {
	if r.off >= len(r.data) {
		return 0, NewVerificationError("proof truncated (varint)")
	}
	tag := r.data[r.off]
	r.off++
	var n int
	switch {
	case tag < 251:
		return uint64(tag), nil
	case tag == 251:
		n = 2
	case tag == 252:
		n = 4
	case tag == 253:
		n = 8
	default:
		return 0, NewVerificationError("proof: unsupported varint width")
	}
	if r.off+n > len(r.data) {
		return 0, NewVerificationError("proof truncated (varint body)")
	}
	var v uint64
	for i := 0; i < n; i++ {
		v = v<<8 | uint64(r.data[r.off+i])
	}
	r.off += n
	return v, nil
}

func (r *bincodeReader) byteVec() ([]byte, error) {
	n, err := r.varint()
	if err != nil {
		return nil, err
	}
	if n > uint64(len(r.data)-r.off) {
		return nil, NewVerificationError("proof truncated (byte vector)")
	}
	out := make([]byte, n)
	copy(out, r.data[r.off:r.off+int(n)])
	r.off += int(n)
	return out, nil
}

// maxLayerDepth bounds the recursive envelope decode; a real path is a few
// segments deep.
const maxLayerDepth = 64

// DecodeGroveDBProof decodes a bincode-encoded grovedb `GroveDBProof` (only
// the V0 variant exists) and rejects trailing bytes.
func DecodeGroveDBProof(proofBytes []byte) (*GroveDBProof, error) {
	r := &bincodeReader{data: proofBytes}
	variant, err := r.varint()
	if err != nil {
		return nil, err
	}
	if variant != 0 {
		return nil, NewVerificationError(fmt.Sprintf("unsupported proof version: %d", variant))
	}
	rootLayer, err := decodeLayerProof(r, 0)
	if err != nil {
		return nil, err
	}
	if r.off >= len(r.data) {
		return nil, NewVerificationError("proof truncated (prove_options)")
	}
	opts := ProveOptions{DecreaseLimitOnEmptySubQueryResult: r.data[r.off] != 0}
	r.off++
	if r.off != len(r.data) {
		return nil, NewVerificationError(fmt.Sprintf("proof has %d trailing bytes", len(r.data)-r.off))
	}
	return &GroveDBProof{
		Version: 0,
		Proof: &GroveDBProofV0{
			RootLayer:    rootLayer,
			ProveOptions: opts,
		},
	}, nil
}

func decodeLayerProof(r *bincodeReader, depth int) (*LayerProof, error) {
	if depth > maxLayerDepth {
		return nil, NewVerificationError("layer proof nesting too deep")
	}
	merkProof, err := r.byteVec()
	if err != nil {
		return nil, err
	}
	count, err := r.varint()
	if err != nil {
		return nil, err
	}
	lowerLayers := make(map[string]*LayerProof)
	for i := uint64(0); i < count; i++ {
		key, err := r.byteVec()
		if err != nil {
			return nil, err
		}
		nested, err := decodeLayerProof(r, depth+1)
		if err != nil {
			return nil, err
		}
		lowerLayers[hex.EncodeToString(key)] = nested
	}
	return &LayerProof{
		MerkProof:   merkProof,
		LowerLayers: lowerLayers,
	}, nil
}

// CheckEnvelope is the check grovedb's own verifier does not make. The
// verifier finds the next layer by the envelope's `lower_layers` map KEY,
// which is not hash-bound: a prover who renames or drops the entry for a
// subtree on the query path gets the same root hash with that subtree's
// results silently gone, so a proof of "K = V" verifies as "K is absent".
// Requiring a layer for every path segment closes it (once a layer is
// present its root is hash-bound to the parent). `prove_options` is
// prover-chosen bytes that steer limit accounting, so it is pinned to the
// default the chain's prover uses.
func CheckEnvelope(proof *GroveDBProof, expectedPath [][]byte) error {
	if proof == nil || proof.Proof == nil || proof.Proof.RootLayer == nil {
		return NewVerificationError("envelope: missing root layer")
	}
	if !proof.Proof.ProveOptions.DecreaseLimitOnEmptySubQueryResult {
		return NewVerificationError("envelope: non-default prove_options")
	}
	layer := proof.Proof.RootLayer
	for i, seg := range expectedPath {
		next, ok := layer.LowerLayers[hex.EncodeToString(seg)]
		if !ok {
			return NewVerificationError(fmt.Sprintf(
				"envelope: no lower layer for path segment %d (%q); the proof does not descend to the query path", i, seg))
		}
		layer = next
	}
	if len(layer.LowerLayers) != 0 {
		return NewVerificationError("envelope: unexpected lower layers below the query path")
	}
	return nil
}

// VerifyProofAtPath verifies a proof and requires that it descends to
// `expectedPath` (see CheckEnvelope). Use it whenever the query path is
// known; a result set that is empty at this path is then a proven absence.
func VerifyProofAtPath(proofBytes []byte, expectedPath [][]byte) (*VerificationResult, error) {
	proof, err := DecodeGroveDBProof(proofBytes)
	if err != nil {
		return nil, err
	}
	if err := CheckEnvelope(proof, expectedPath); err != nil {
		return nil, err
	}
	return verifyDecoded(proof)
}

// VerifyProofAgainstRootAtPath is VerifyProofAtPath plus the root compare.
func VerifyProofAgainstRootAtPath(proofBytes []byte, expectedPath [][]byte, expectedRootHash string) (*VerificationResult, error) {
	result, err := VerifyProofAtPath(proofBytes, expectedPath)
	if err != nil {
		return nil, err
	}
	if result.RootHash != expectedRootHash {
		return nil, NewVerificationError(fmt.Sprintf(
			"root hash mismatch: expected %s, got %s",
			expectedRootHash, result.RootHash))
	}
	return result, nil
}

func verifyDecoded(proof *GroveDBProof) (*VerificationResult, error) {
	results := make([]QueryResult, 0)
	rootHash, err := verifyLayerProof(proof.Proof.RootLayer, [][]byte{}, &results)
	if err != nil {
		return nil, err
	}
	return &VerificationResult{
		RootHash: rootHash.String(),
		Results:  results,
	}, nil
}

// VerifyProof verifies a GroveDB proof and returns the verification result.
func VerifyProof(proofBytes []byte) (*VerificationResult, error) {
	proof, err := DecodeGroveDBProof(proofBytes)
	if err != nil {
		return nil, err
	}
	if !proof.Proof.ProveOptions.DecreaseLimitOnEmptySubQueryResult {
		return nil, NewVerificationError("envelope: non-default prove_options")
	}
	return verifyDecoded(proof)
}

func verifyLayerProof(layer *LayerProof, currentPath [][]byte, results *[]QueryResult) (CryptoHash, error) {
	// Execute the Merk proof
	merkResult, err := ExecuteMerkProof(layer.MerkProof)
	if err != nil {
		return CryptoHash{}, err
	}

	// Process each proven value
	for _, proved := range merkResult.ResultSet {
		keyHex := hex.EncodeToString(proved.Key)
		lowerLayer, hasLower := layer.LowerLayers[keyHex]

		if hasLower && proved.Value != nil {
			// This is a subtree - verify the lower layer
			newPath := append(append([][]byte{}, currentPath...), proved.Key)
			lowerHash, err := verifyLayerProof(lowerLayer, newPath, results)
			if err != nil {
				return CryptoHash{}, err
			}

			// Verify the combined hash
			elementValueHash := ValueHash(proved.Value)
			combinedHash := CombineHash(elementValueHash, lowerHash)

			if !combinedHash.Equals(proved.ProofHash) {
				return CryptoHash{}, NewVerificationError(fmt.Sprintf(
					"lower layer hash mismatch at key %s: expected %s, got %s",
					keyHex, proved.ProofHash.String(), combinedHash.String()))
			}
		} else if proved.Value != nil {
			// Leaf value - add to results
			*results = append(*results, QueryResult{
				Path:  currentPath,
				Key:   proved.Key,
				Value: proved.Value,
			})
		}
	}

	return merkResult.RootHash, nil
}

// VerifyProofAgainstRoot verifies a proof against an expected root hash.
func VerifyProofAgainstRoot(proofBytes []byte, expectedRootHash string) (*VerificationResult, error) {
	result, err := VerifyProof(proofBytes)
	if err != nil {
		return nil, err
	}

	if result.RootHash != expectedRootHash {
		return nil, NewVerificationError(fmt.Sprintf(
			"root hash mismatch: expected %s, got %s",
			expectedRootHash, result.RootHash))
	}

	return result, nil
}

// QuickVerify quickly verifies a proof and returns just the root hash.
func QuickVerify(proofBytes []byte) (CryptoHash, error) {
	result, err := VerifyProof(proofBytes)
	if err != nil {
		return CryptoHash{}, err
	}
	return HashFromHex(result.RootHash)
}

// Verifier provides stateful proof verification.
type Verifier struct {
	trustedRootHash string
}

// NewVerifier creates a new verifier.
func NewVerifier() *Verifier {
	return &Verifier{}
}

// SetTrustedRoot sets the trusted root hash.
func (v *Verifier) SetTrustedRoot(rootHash string) error {
	// Validate the hash format
	if len(rootHash) != HashLength*2 {
		return NewVerificationError("invalid root hash length")
	}
	_, err := hex.DecodeString(rootHash)
	if err != nil {
		return NewVerificationError(fmt.Sprintf("invalid root hash format: %v", err))
	}
	v.trustedRootHash = rootHash
	return nil
}

// Verify verifies a proof against the trusted root.
func (v *Verifier) Verify(proofBytes []byte) (*VerificationResult, error) {
	if v.trustedRootHash == "" {
		return nil, NewVerificationError("no trusted root hash set")
	}
	return VerifyProofAgainstRoot(proofBytes, v.trustedRootHash)
}

// BytesCompare compares two byte slices.
func BytesCompare(a, b []byte) int {
	return bytes.Compare(a, b)
}
