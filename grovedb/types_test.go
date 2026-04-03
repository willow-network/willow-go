package grovedb

import (
	"bytes"
	"testing"
)

func TestHashLength(t *testing.T) {
	if HashLength != 32 {
		t.Errorf("Expected HashLength 32, got %d", HashLength)
	}
}

func TestNullHash(t *testing.T) {
	if len(NullHash) != 32 {
		t.Errorf("Expected NullHash length 32, got %d", len(NullHash))
	}
	for i, b := range NullHash {
		if b != 0 {
			t.Errorf("NullHash byte %d should be 0, got %d", i, b)
		}
	}
}

func TestCryptoHashString(t *testing.T) {
	h := CryptoHash{}
	expected := "0000000000000000000000000000000000000000000000000000000000000000"
	if h.String() != expected {
		t.Errorf("Expected %s, got %s", expected, h.String())
	}

	h[0] = 0xab
	h[1] = 0xcd
	if h.String()[:4] != "abcd" {
		t.Errorf("Expected string to start with 'abcd', got %s", h.String()[:4])
	}
}

func TestCryptoHashIsZero(t *testing.T) {
	var h CryptoHash
	if !h.IsZero() {
		t.Error("Empty hash should be zero")
	}

	h[0] = 1
	if h.IsZero() {
		t.Error("Non-zero hash should not be zero")
	}
}

func TestCryptoHashEquals(t *testing.T) {
	h1 := CryptoHash{}
	h2 := CryptoHash{}
	if !h1.Equals(h2) {
		t.Error("Equal hashes should be equal")
	}

	h1[0] = 1
	if h1.Equals(h2) {
		t.Error("Different hashes should not be equal")
	}
}

func TestHashFromBytes(t *testing.T) {
	data := make([]byte, 32)
	data[0] = 0xaa
	data[31] = 0xbb

	h := HashFromBytes(data)
	if h[0] != 0xaa || h[31] != 0xbb {
		t.Error("HashFromBytes should copy data correctly")
	}
}

func TestHashFromBytesShort(t *testing.T) {
	data := []byte{0xaa, 0xbb}
	h := HashFromBytes(data)
	if h[0] != 0xaa || h[1] != 0xbb {
		t.Error("HashFromBytes should handle short data")
	}
	if h[2] != 0 {
		t.Error("Remaining bytes should be zero")
	}
}

func TestHashFromHex(t *testing.T) {
	hexStr := "abcd" + "00000000000000000000000000000000000000000000000000000000" + "1234"
	h, err := HashFromHex(hexStr)
	if err != nil {
		t.Fatalf("HashFromHex failed: %v", err)
	}
	if h[0] != 0xab || h[1] != 0xcd {
		t.Errorf("Expected first bytes to be 0xab, 0xcd, got %x, %x", h[0], h[1])
	}
}

func TestHashFromHexInvalidLength(t *testing.T) {
	_, err := HashFromHex("abcd")
	if err == nil {
		t.Error("HashFromHex should fail with invalid length")
	}
}

func TestHashFromHexInvalidHex(t *testing.T) {
	_, err := HashFromHex("xyz" + "0000000000000000000000000000000000000000000000000000000000000")
	if err == nil {
		t.Error("HashFromHex should fail with invalid hex")
	}
}

func TestComputeHash(t *testing.T) {
	h1 := ComputeHash([]byte("test"))
	h2 := ComputeHash([]byte("test"))
	h3 := ComputeHash([]byte("different"))

	if !h1.Equals(h2) {
		t.Error("Same input should produce same hash")
	}
	if h1.Equals(h3) {
		t.Error("Different input should produce different hash")
	}
	if h1.IsZero() {
		t.Error("Hash should not be zero")
	}
}

func TestValueHash(t *testing.T) {
	h := ValueHash([]byte("test value"))
	if h.IsZero() {
		t.Error("ValueHash should not be zero")
	}
}

func TestComputeNodeHash(t *testing.T) {
	kvHash := ComputeHash([]byte("kv"))
	leftHash := ComputeHash([]byte("left"))
	rightHash := ComputeHash([]byte("right"))

	h := ComputeNodeHash(kvHash, leftHash, rightHash)
	if h.IsZero() {
		t.Error("NodeHash should not be zero")
	}

	// Should be deterministic
	h2 := ComputeNodeHash(kvHash, leftHash, rightHash)
	if !h.Equals(h2) {
		t.Error("NodeHash should be deterministic")
	}

	// Different inputs should produce different hash
	h3 := ComputeNodeHash(leftHash, kvHash, rightHash)
	if h.Equals(h3) {
		t.Error("Different inputs should produce different hash")
	}
}

func TestKVHash(t *testing.T) {
	h := KVHash([]byte("key"), []byte("value"))
	if h.IsZero() {
		t.Error("KVHash should not be zero")
	}

	// Should be deterministic
	h2 := KVHash([]byte("key"), []byte("value"))
	if !h.Equals(h2) {
		t.Error("KVHash should be deterministic")
	}

	// Different key should produce different hash
	h3 := KVHash([]byte("different-key"), []byte("value"))
	if h.Equals(h3) {
		t.Error("Different key should produce different hash")
	}

	// Different value should produce different hash
	h4 := KVHash([]byte("key"), []byte("different-value"))
	if h.Equals(h4) {
		t.Error("Different value should produce different hash")
	}
}

func TestCombineHash(t *testing.T) {
	h1 := ComputeHash([]byte("a"))
	h2 := ComputeHash([]byte("b"))

	combined := CombineHash(h1, h2)
	if combined.IsZero() {
		t.Error("CombineHash should not be zero")
	}

	// Order matters
	combined2 := CombineHash(h2, h1)
	if combined.Equals(combined2) {
		t.Error("CombineHash should be order-dependent")
	}
}

func TestMerkNodeTypes(t *testing.T) {
	tests := []struct {
		nodeType MerkNodeType
		expected int
	}{
		{NodeHash, 0},
		{NodeKVHash, 1},
		{NodeKV, 2},
		{NodeKVValueHash, 3},
		{NodeKVDigest, 4},
		{NodeKVRefValueHash, 5},
		{NodeKVValueHashFeatureType, 6},
	}

	for _, tt := range tests {
		if int(tt.nodeType) != tt.expected {
			t.Errorf("Expected %d, got %d", tt.expected, int(tt.nodeType))
		}
	}
}

func TestMerkOpTypes(t *testing.T) {
	tests := []struct {
		opType   MerkOpType
		expected int
	}{
		{OpPush, 0},
		{OpPushInverted, 1},
		{OpParent, 2},
		{OpChild, 3},
		{OpParentInverted, 4},
		{OpChildInverted, 5},
	}

	for _, tt := range tests {
		if int(tt.opType) != tt.expected {
			t.Errorf("Expected %d, got %d", tt.expected, int(tt.opType))
		}
	}
}

func TestMerkNode(t *testing.T) {
	// Hash node
	hashNode := MerkNode{
		Type: NodeHash,
		Hash: ComputeHash([]byte("test")),
	}
	if hashNode.Type != NodeHash {
		t.Error("Wrong node type")
	}

	// KV node
	kvNode := MerkNode{
		Type:  NodeKV,
		Key:   []byte("key"),
		Value: []byte("value"),
	}
	if !bytes.Equal(kvNode.Key, []byte("key")) {
		t.Error("Key mismatch")
	}
	if !bytes.Equal(kvNode.Value, []byte("value")) {
		t.Error("Value mismatch")
	}

	// KVValueHash node
	kvvhNode := MerkNode{
		Type:      NodeKVValueHash,
		Key:       []byte("key"),
		Value:     []byte("value"),
		ValueHash: ComputeHash([]byte("value")),
	}
	if kvvhNode.ValueHash.IsZero() {
		t.Error("ValueHash should not be zero")
	}
}

func TestElementTypes(t *testing.T) {
	tests := []struct {
		elemType ElementType
		expected int
	}{
		{ElementItem, 0},
		{ElementReference, 1},
		{ElementTree, 2},
		{ElementSumTree, 3},
		{ElementSumItem, 4},
		{ElementBigSumTree, 5},
		{ElementCountTree, 6},
		{ElementCountSumTree, 7},
	}

	for _, tt := range tests {
		if int(tt.elemType) != tt.expected {
			t.Errorf("Expected %d, got %d", tt.expected, int(tt.elemType))
		}
	}
}

func TestElementIsTree(t *testing.T) {
	treeTypes := []ElementType{
		ElementTree,
		ElementSumTree,
		ElementBigSumTree,
		ElementCountTree,
		ElementCountSumTree,
	}

	nonTreeTypes := []ElementType{
		ElementItem,
		ElementReference,
		ElementSumItem,
	}

	for _, et := range treeTypes {
		elem := Element{Type: et}
		if !elem.IsTree() {
			t.Errorf("ElementType %d should be tree", et)
		}
	}

	for _, et := range nonTreeTypes {
		elem := Element{Type: et}
		if elem.IsTree() {
			t.Errorf("ElementType %d should not be tree", et)
		}
	}
}

func TestElementHasRootKey(t *testing.T) {
	// Tree with root key
	elem := Element{
		Type:    ElementTree,
		RootKey: []byte("root"),
	}
	if !elem.HasRootKey() {
		t.Error("Tree with root key should have root key")
	}

	// Tree without root key
	elem2 := Element{
		Type:    ElementTree,
		RootKey: nil,
	}
	if elem2.HasRootKey() {
		t.Error("Tree without root key should not have root key")
	}

	// Non-tree with root key set (should still return false)
	elem3 := Element{
		Type:    ElementItem,
		RootKey: []byte("root"),
	}
	if elem3.HasRootKey() {
		t.Error("Non-tree should not have root key")
	}
}

func TestGroveDBVerificationError(t *testing.T) {
	err := NewVerificationError("test error")
	if err.Error() != "test error" {
		t.Errorf("Expected 'test error', got '%s'", err.Error())
	}
}

func TestLayerProof(t *testing.T) {
	proof := LayerProof{
		MerkProof:   []byte("proof data"),
		LowerLayers: make(map[string]*LayerProof),
	}

	if !bytes.Equal(proof.MerkProof, []byte("proof data")) {
		t.Error("MerkProof mismatch")
	}

	// Add a lower layer
	proof.LowerLayers["key1"] = &LayerProof{
		MerkProof: []byte("nested proof"),
	}

	if len(proof.LowerLayers) != 1 {
		t.Error("LowerLayers should have 1 entry")
	}
}

func TestGroveDBProof(t *testing.T) {
	proof := GroveDBProof{
		Version: 0,
		Proof: &GroveDBProofV0{
			RootLayer: &LayerProof{
				MerkProof: []byte("root proof"),
			},
			ProveOptions: ProveOptions{
				DecreaseLimitOnEmptySubQueryResult: true,
			},
		},
	}

	if proof.Version != 0 {
		t.Errorf("Expected version 0, got %d", proof.Version)
	}
	if proof.Proof == nil {
		t.Error("Proof should not be nil")
	}
	if !proof.Proof.ProveOptions.DecreaseLimitOnEmptySubQueryResult {
		t.Error("ProveOptions should have DecreaseLimitOnEmptySubQueryResult true")
	}
}

func TestProvedKeyValue(t *testing.T) {
	pkv := ProvedKeyValue{
		Key:       []byte("key"),
		Value:     []byte("value"),
		ProofHash: ComputeHash([]byte("proof")),
	}

	if !bytes.Equal(pkv.Key, []byte("key")) {
		t.Error("Key mismatch")
	}
	if !bytes.Equal(pkv.Value, []byte("value")) {
		t.Error("Value mismatch")
	}
	if pkv.ProofHash.IsZero() {
		t.Error("ProofHash should not be zero")
	}
}

func TestVerificationResult(t *testing.T) {
	result := VerificationResult{
		RootHash: "abcd1234",
		Results: []QueryResult{
			{
				Path:  [][]byte{[]byte("subgroves"), []byte("my-subgrove")},
				Key:   []byte("key1"),
				Value: []byte("value1"),
			},
		},
	}

	if result.RootHash != "abcd1234" {
		t.Error("RootHash mismatch")
	}
	if len(result.Results) != 1 {
		t.Error("Results should have 1 entry")
	}
	if !bytes.Equal(result.Results[0].Key, []byte("key1")) {
		t.Error("Result key mismatch")
	}
}
