package grovedb

import (
	"bytes"
	"testing"
)

func TestTreeCreation(t *testing.T) {
	node := &MerkNode{
		Type: NodeHash,
		Hash: ComputeHash([]byte("test")),
	}
	tree := NewTree(node)

	if tree.node != node {
		t.Error("Tree node mismatch")
	}
	if tree.left != nil {
		t.Error("Left should be nil")
	}
	if tree.right != nil {
		t.Error("Right should be nil")
	}
}

func TestTreeHashOfHashNode(t *testing.T) {
	h := ComputeHash([]byte("test"))
	node := &MerkNode{
		Type: NodeHash,
		Hash: h,
	}
	tree := NewTree(node)

	treeHash := tree.Hash()
	if !treeHash.Equals(h) {
		t.Error("Hash of hash node should return stored hash")
	}
}

func TestTreeHashOfKVNode(t *testing.T) {
	node := &MerkNode{
		Type:  NodeKV,
		Key:   []byte("key"),
		Value: []byte("value"),
	}
	tree := NewTree(node)

	h := tree.Hash()
	if h.IsZero() {
		t.Error("Hash should not be zero")
	}

	// Should be consistent
	h2 := tree.Hash()
	if !h.Equals(h2) {
		t.Error("Hash should be consistent")
	}
}

func TestTreeAttachWithHeight(t *testing.T) {
	parentNode := &MerkNode{
		Type:  NodeKV,
		Key:   []byte("parent"),
		Value: []byte("pval"),
	}
	childNode := &MerkNode{
		Type: NodeHash,
		Hash: NullHash,
	}

	parent := NewTree(parentNode)
	child := NewTree(childNode)

	// Attach as left child
	parent.AttachWithHeight(true, child, 1)

	if parent.left == nil {
		t.Error("Left child should be attached")
	}
	if parent.right != nil {
		t.Error("Right child should still be nil")
	}
	if parent.childHeights[0] != 1 {
		t.Errorf("Left child height should be 1, got %d", parent.childHeights[0])
	}
}

func TestTreeAttachRight(t *testing.T) {
	parentNode := &MerkNode{
		Type:  NodeKV,
		Key:   []byte("parent"),
		Value: []byte("pval"),
	}
	childNode := &MerkNode{
		Type: NodeHash,
		Hash: NullHash,
	}

	parent := NewTree(parentNode)
	child := NewTree(childNode)

	// Attach as right child
	parent.AttachWithHeight(false, child, 2)

	if parent.right == nil {
		t.Error("Right child should be attached")
	}
	if parent.left != nil {
		t.Error("Left child should still be nil")
	}
	if parent.childHeights[1] != 2 {
		t.Errorf("Right child height should be 2, got %d", parent.childHeights[1])
	}
}

func TestTreeIntoHash(t *testing.T) {
	node := &MerkNode{
		Type:  NodeKV,
		Key:   []byte("key"),
		Value: []byte("value"),
	}
	tree := NewTree(node)
	originalHash := tree.Hash()

	hashTree := tree.IntoHash()

	if hashTree.node.Type != NodeHash {
		t.Error("IntoHash should produce hash node")
	}
	if !hashTree.node.Hash.Equals(originalHash) {
		t.Error("Hash should match original tree hash")
	}
}

func TestTreeHeight(t *testing.T) {
	node := &MerkNode{Type: NodeKV, Key: []byte("k"), Value: []byte("v")}
	tree := NewTree(node)

	// Initial height should be 1 (no children)
	if tree.Height() != 1 {
		t.Errorf("Expected height 1, got %d", tree.Height())
	}

	// Attach left child with height 3
	tree.AttachWithHeight(true, NewTree(&MerkNode{Type: NodeHash, Hash: NullHash}), 3)
	if tree.Height() != 4 { // max(3, 0) + 1
		t.Errorf("Expected height 4, got %d", tree.Height())
	}

	// Attach right child with height 5
	tree.AttachWithHeight(false, NewTree(&MerkNode{Type: NodeHash, Hash: NullHash}), 5)
	if tree.Height() != 6 { // max(3, 5) + 1
		t.Errorf("Expected height 6, got %d", tree.Height())
	}
}

func TestMerkNodeKey(t *testing.T) {
	// KV node has key
	kvNode := &MerkNode{
		Type:  NodeKV,
		Key:   []byte("testkey"),
		Value: []byte("val"),
	}
	if !bytes.Equal(kvNode.Key, []byte("testkey")) {
		t.Error("Key mismatch")
	}

	// Hash node has no key
	hashNode := &MerkNode{
		Type: NodeHash,
		Hash: NullHash,
	}
	if hashNode.Key != nil {
		t.Error("Hash node should have nil key")
	}
}

func TestMerkNodeValue(t *testing.T) {
	// KV node has value
	kvNode := &MerkNode{
		Type:  NodeKV,
		Key:   []byte("key"),
		Value: []byte("testvalue"),
	}
	if !bytes.Equal(kvNode.Value, []byte("testvalue")) {
		t.Error("Value mismatch")
	}

	// Hash node has no value
	hashNode := &MerkNode{
		Type: NodeHash,
		Hash: NullHash,
	}
	if hashNode.Value != nil {
		t.Error("Hash node should have nil value")
	}
}

func TestMerkDecoderPushHash(t *testing.T) {
	// Op code 0x01 + 32 byte hash
	data := make([]byte, 33)
	data[0] = opPushHash
	hash := ComputeHash([]byte("test"))
	copy(data[1:], hash[:])

	decoder := NewMerkDecoder(data)
	op, err := decoder.Next()
	if err != nil {
		t.Fatalf("Decoder failed: %v", err)
	}

	if op.Type != OpPush {
		t.Errorf("Expected OpPush, got %d", op.Type)
	}
	if op.Node.Type != NodeHash {
		t.Errorf("Expected NodeHash, got %d", op.Node.Type)
	}
}

func TestMerkDecoderParentOp(t *testing.T) {
	data := []byte{opParent}
	decoder := NewMerkDecoder(data)
	op, err := decoder.Next()
	if err != nil {
		t.Fatalf("Decoder failed: %v", err)
	}

	if op.Type != OpParent {
		t.Errorf("Expected OpParent, got %d", op.Type)
	}
}

func TestMerkDecoderChildOp(t *testing.T) {
	data := []byte{opChild}
	decoder := NewMerkDecoder(data)
	op, err := decoder.Next()
	if err != nil {
		t.Fatalf("Decoder failed: %v", err)
	}

	if op.Type != OpChild {
		t.Errorf("Expected OpChild, got %d", op.Type)
	}
}

func TestMerkDecoderParentInvertedOp(t *testing.T) {
	data := []byte{opParentInverted}
	decoder := NewMerkDecoder(data)
	op, err := decoder.Next()
	if err != nil {
		t.Fatalf("Decoder failed: %v", err)
	}

	if op.Type != OpParentInverted {
		t.Errorf("Expected OpParentInverted, got %d", op.Type)
	}
}

func TestMerkDecoderChildInvertedOp(t *testing.T) {
	data := []byte{opChildInverted}
	decoder := NewMerkDecoder(data)
	op, err := decoder.Next()
	if err != nil {
		t.Fatalf("Decoder failed: %v", err)
	}

	if op.Type != OpChildInverted {
		t.Errorf("Expected OpChildInverted, got %d", op.Type)
	}
}

func TestMerkDecoderHasMore(t *testing.T) {
	data := []byte{opParent, opChild}
	decoder := NewMerkDecoder(data)

	if !decoder.HasMore() {
		t.Error("HasMore should be true initially")
	}

	decoder.Next()
	if !decoder.HasMore() {
		t.Error("HasMore should be true after first op")
	}

	decoder.Next()
	if decoder.HasMore() {
		t.Error("HasMore should be false after all ops")
	}
}

func TestMerkDecoderReturnsNilAtEnd(t *testing.T) {
	decoder := NewMerkDecoder([]byte{})
	op, err := decoder.Next()

	if err != nil {
		t.Errorf("Expected no error at end, got: %v", err)
	}
	if op != nil {
		t.Error("Expected nil at end of data")
	}
}

func TestMerkDecoderUnknownOpCode(t *testing.T) {
	data := []byte{0xff} // Invalid op code
	decoder := NewMerkDecoder(data)
	_, err := decoder.Next()

	if err == nil {
		t.Error("Expected error for unknown op code")
	}
}

func TestMerkDecoderMultipleOps(t *testing.T) {
	data := []byte{opParent, opChild, opParentInverted}
	decoder := NewMerkDecoder(data)

	expectedOps := []MerkOpType{OpParent, OpChild, OpParentInverted}

	for i, expected := range expectedOps {
		op, err := decoder.Next()
		if err != nil {
			t.Fatalf("Op %d failed: %v", i, err)
		}
		if op.Type != expected {
			t.Errorf("Op %d: expected %d, got %d", i, expected, op.Type)
		}
	}

	// Should be done
	op, _ := decoder.Next()
	if op != nil {
		t.Error("Should be no more ops")
	}
}

func TestExecuteMerkProofSingleHash(t *testing.T) {
	// Create a simple proof with just a hash
	hash := ComputeHash([]byte("test"))
	data := make([]byte, 33)
	data[0] = opPushHash
	copy(data[1:], hash[:])

	result, err := ExecuteMerkProof(data)
	if err != nil {
		t.Fatalf("ExecuteMerkProof failed: %v", err)
	}

	if !result.RootHash.Equals(hash) {
		t.Error("Root hash mismatch")
	}
}

func TestVerifyProofInvalid(t *testing.T) {
	_, err := VerifyProof([]byte("invalid proof data"))
	if err == nil {
		t.Error("VerifyProof should fail with invalid data")
	}
}

func TestVerifyProofAgainstRootInvalid(t *testing.T) {
	_, err := VerifyProofAgainstRoot([]byte("invalid"), NullHash.String())
	if err == nil {
		t.Error("VerifyProofAgainstRoot should fail with invalid data")
	}
}

func TestQuickVerifyInvalid(t *testing.T) {
	_, err := QuickVerify([]byte("invalid"))
	if err == nil {
		t.Error("QuickVerify should fail with invalid data")
	}
}

func TestBytesCompare(t *testing.T) {
	tests := []struct {
		a, b     []byte
		expected int
	}{
		{[]byte("abc"), []byte("abc"), 0},
		{[]byte("abc"), []byte("abd"), -1},
		{[]byte("abd"), []byte("abc"), 1},
		{[]byte("ab"), []byte("abc"), -1},
		{[]byte("abc"), []byte("ab"), 1},
		{[]byte{}, []byte{}, 0},
		{[]byte{}, []byte("a"), -1},
		{[]byte("a"), []byte{}, 1},
	}

	for _, tt := range tests {
		result := BytesCompare(tt.a, tt.b)
		// Just check sign
		if (result < 0 && tt.expected >= 0) || (result > 0 && tt.expected <= 0) || (result == 0 && tt.expected != 0) {
			t.Errorf("BytesCompare(%v, %v) = %d, expected sign of %d", tt.a, tt.b, result, tt.expected)
		}
	}
}

func TestMerkDecoderPushInvertedHash(t *testing.T) {
	// Op code 0x08 + 32 byte hash
	data := make([]byte, 33)
	data[0] = opPushInvertedHash
	hash := ComputeHash([]byte("test"))
	copy(data[1:], hash[:])

	decoder := NewMerkDecoder(data)
	op, err := decoder.Next()
	if err != nil {
		t.Fatalf("Decoder failed: %v", err)
	}

	if op.Type != OpPushInverted {
		t.Errorf("Expected OpPushInverted, got %d", op.Type)
	}
	if op.Node.Type != NodeHash {
		t.Errorf("Expected NodeHash, got %d", op.Node.Type)
	}
}

func TestMerkDecoderPushKVHash(t *testing.T) {
	// Op code 0x02 + 32 byte hash
	data := make([]byte, 33)
	data[0] = opPushKVHash
	hash := ComputeHash([]byte("test"))
	copy(data[1:], hash[:])

	decoder := NewMerkDecoder(data)
	op, err := decoder.Next()
	if err != nil {
		t.Fatalf("Decoder failed: %v", err)
	}

	if op.Type != OpPush {
		t.Errorf("Expected OpPush, got %d", op.Type)
	}
	if op.Node.Type != NodeKVHash {
		t.Errorf("Expected NodeKVHash, got %d", op.Node.Type)
	}
}

func TestMerkDecoderPushKV(t *testing.T) {
	// Op code 0x03 + key_len(1) + key + value_len(2, big-endian) + value
	key := []byte("key")
	value := []byte("value")
	data := make([]byte, 1+1+len(key)+2+len(value))
	data[0] = opPushKV
	data[1] = byte(len(key))
	copy(data[2:], key)
	data[2+len(key)] = 0
	data[3+len(key)] = byte(len(value))
	copy(data[4+len(key):], value)

	decoder := NewMerkDecoder(data)
	op, err := decoder.Next()
	if err != nil {
		t.Fatalf("Decoder failed: %v", err)
	}

	if op.Type != OpPush {
		t.Errorf("Expected OpPush, got %d", op.Type)
	}
	if op.Node.Type != NodeKV {
		t.Errorf("Expected NodeKV, got %d", op.Node.Type)
	}
	if !bytes.Equal(op.Node.Key, key) {
		t.Errorf("Key mismatch: expected %v, got %v", key, op.Node.Key)
	}
	if !bytes.Equal(op.Node.Value, value) {
		t.Errorf("Value mismatch: expected %v, got %v", value, op.Node.Value)
	}
}
