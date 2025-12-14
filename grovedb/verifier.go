package grovedb

import (
	"bytes"
	"encoding/binary"
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

// DecodeGroveDBProof decodes a GroveDB proof from bytes.
func DecodeGroveDBProof(proofBytes []byte) (*GroveDBProof, error) {
	if len(proofBytes) < 4 {
		return nil, NewVerificationError("proof too short")
	}

	// Version is first 4 bytes (little-endian u32)
	version := binary.LittleEndian.Uint32(proofBytes[:4])
	if version != 0 {
		return nil, NewVerificationError(fmt.Sprintf("unsupported proof version: %d", version))
	}

	rootLayer, remaining, err := decodeLayerProof(proofBytes[4:])
	if err != nil {
		return nil, err
	}

	proveOptions := ProveOptions{}
	if len(remaining) >= 1 {
		proveOptions.DecreaseLimitOnEmptySubQueryResult = remaining[0] != 0
	}

	return &GroveDBProof{
		Version: int(version),
		Proof: &GroveDBProofV0{
			RootLayer:    rootLayer,
			ProveOptions: proveOptions,
		},
	}, nil
}

func decodeLayerProof(data []byte) (*LayerProof, []byte, error) {
	if len(data) < 4 {
		return nil, nil, NewVerificationError("layer proof too short")
	}

	// Merk proof length (little-endian u32)
	merkProofLen := binary.LittleEndian.Uint32(data[:4])
	offset := 4

	if len(data) < offset+int(merkProofLen) {
		return nil, nil, NewVerificationError("incomplete merk proof data")
	}

	merkProof := make([]byte, merkProofLen)
	copy(merkProof, data[offset:offset+int(merkProofLen)])
	offset += int(merkProofLen)

	lowerLayers := make(map[string]*LayerProof)

	// Check if there are lower layers
	if len(data) >= offset+4 {
		lowerLayersCount := binary.LittleEndian.Uint32(data[offset:])
		offset += 4

		for i := uint32(0); i < lowerLayersCount; i++ {
			if len(data) < offset+4 {
				break
			}

			// Key length
			keyLen := binary.LittleEndian.Uint32(data[offset:])
			offset += 4

			if len(data) < offset+int(keyLen) {
				break
			}

			// Key
			key := make([]byte, keyLen)
			copy(key, data[offset:offset+int(keyLen)])
			offset += int(keyLen)

			// Nested layer proof
			nestedProof, remaining, err := decodeLayerProof(data[offset:])
			if err != nil {
				return nil, nil, err
			}
			offset = len(data) - len(remaining)

			keyHex := hex.EncodeToString(key)
			lowerLayers[keyHex] = nestedProof
		}
	}

	return &LayerProof{
		MerkProof:   merkProof,
		LowerLayers: lowerLayers,
	}, data[offset:], nil
}

// VerifyProof verifies a GroveDB proof and returns the verification result.
func VerifyProof(proofBytes []byte) (*VerificationResult, error) {
	proof, err := DecodeGroveDBProof(proofBytes)
	if err != nil {
		return nil, err
	}

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
