package willow

import (
	"bytes"
	"testing"
)

func TestMptRejectsShortRoot(t *testing.T) {
	err := verifyMptProof(bytes.Repeat([]byte{0}, 16), bytes.Repeat([]byte{0}, 32), nil, [][]byte{{0xc0}})
	if err == nil || !contains(err.Error(), "root must be 32 bytes") {
		t.Fatalf("want short-root error, got %v", err)
	}
}

func TestMptRejectsEmptyProof(t *testing.T) {
	err := verifyMptProof(bytes.Repeat([]byte{0}, 32), bytes.Repeat([]byte{0}, 32), nil, nil)
	if err == nil || !contains(err.Error(), "proof is empty") {
		t.Fatalf("want empty-proof error, got %v", err)
	}
}

func TestMptRejectsMismatchedRootHash(t *testing.T) {
	err := verifyMptProof(bytes.Repeat([]byte{0}, 32), bytes.Repeat([]byte{0}, 32), []byte{0x80}, [][]byte{{0xc0}})
	if err == nil || !contains(err.Error(), "hash mismatch") {
		t.Fatalf("want hash-mismatch error, got %v", err)
	}
}

func TestMptVerifiesSingleLeafTrie(t *testing.T) {
	// Build a tiny one-leaf trie and confirm our verifier walks it.
	keyHash := keccak256([]byte("hello"))
	// Compact-encoded path: 0x20 prefix (leaf, even nibble count) + key.
	encodedPath := append([]byte{0x20}, keyHash...)
	value := []byte{0xab, 0xcd, 0xef}
	// RLP-encode the leaf node: [encodedPath, value].
	leafNode := rlpEncodeList([][]byte{
		rlpEncodeBytes(encodedPath),
		rlpEncodeBytes(value),
	})
	root := keccak256(leafNode)
	if err := verifyMptProof(root, keyHash, value, [][]byte{leafNode}); err != nil {
		t.Fatalf("verifier rejected valid leaf: %v", err)
	}
}

func TestVerifyStateProofRejectsTamperedBalance(t *testing.T) {
	proof := &wireStateProof{
		Address:     make([]int, 20),
		BlockNumber: 1,
		BlockHash:   make([]int, 32),
		StateRoot:   make([]int, 32),
		AccountProof: wireMptProofInts{
			Key:        make([]int, 32),
			Value:      []int{},
			ProofNodes: [][]int{},
		},
		AccountState: wireAccountState{
			Nonce:       0,
			Balance:     repeatInt(0xff, 32), // tampered
			StorageHash: make([]int, 32),
			CodeHash:    make([]int, 32),
		},
	}
	if err := VerifyStateProof(proof); err == nil {
		t.Fatal("expected verification to fail for tampered balance with empty proof")
	}
}

func TestRlpDecodeRoundTrips(t *testing.T) {
	// rlpEncodeList expects already-encoded items, so encode each byte-string
	// first via rlpEncodeBytes; rlpDecodeList strips the length prefix and
	// returns the inner bytes.
	raw := [][]byte{{0x01}, {0xab, 0xcd}, bytes.Repeat([]byte{0x77}, 60)}
	encoded := make([][]byte, len(raw))
	for i, b := range raw {
		encoded[i] = rlpEncodeBytes(b)
	}
	list := rlpEncodeList(encoded)
	dec, err := rlpDecodeList(list)
	if err != nil {
		t.Fatal(err)
	}
	if len(dec) != len(raw) {
		t.Fatalf("len %d != %d", len(dec), len(raw))
	}
	for i := range raw {
		if !bytes.Equal(dec[i], raw[i]) {
			t.Fatalf("item %d: got %x want %x", i, dec[i], raw[i])
		}
	}
}

// helpers --------------------------------------------------------------------

func contains(s, sub string) bool {
	return bytes.Contains([]byte(s), []byte(sub))
}

func repeatInt(v, n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = v
	}
	return out
}
