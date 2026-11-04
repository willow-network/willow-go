package willow

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestWalkStateProofRejectsTamperedBalance(t *testing.T) {
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
	if err := walkStateProof(proof); err == nil {
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

// oneSlotProof builds a state proof whose account and storage tries each hold
// one leaf: address's account, and slot holding value, at block.
func oneSlotProof(address, slot []byte, value byte, block uint64) wireStateProof {
	leaf := func(key, value []byte) []byte {
		path := append([]byte{0x20}, keccak256(key)...) // leaf, even nibble count
		return rlpEncodeList([][]byte{rlpEncodeBytes(path), rlpEncodeBytes(value)})
	}
	storageLeaf := leaf(slot, rlpEncodeBytes([]byte{value}))
	storageHash := keccak256(storageLeaf)
	codeHash := keccak256(nil)
	balance := big.NewInt(1000)
	accountLeaf := leaf(address, rlpEncodeAccount(7, balance, storageHash, codeHash))
	ints := func(b []byte) []int {
		out := make([]int, len(b))
		for i, x := range b {
			out[i] = int(x)
		}
		return out
	}
	balance32 := make([]byte, 32)
	balance.FillBytes(balance32)
	value32 := make([]byte, 32)
	value32[31] = value
	return wireStateProof{
		Address:      ints(address),
		BlockNumber:  block,
		BlockHash:    ints(bytes.Repeat([]byte{0xbb}, 32)),
		StateRoot:    ints(keccak256(accountLeaf)),
		AccountProof: wireMptProofInts{Key: ints(keccak256(address)), ProofNodes: [][]int{ints(accountLeaf)}},
		AccountState: wireAccountState{Nonce: 7, Balance: ints(balance32), StorageHash: ints(storageHash), CodeHash: ints(codeHash)},
		StorageProofs: []wireStorageSlot{{
			Slot:  ints(slot),
			Value: ints(value32),
			Proof: wireMptProofInts{Key: ints(keccak256(slot)), ProofNodes: [][]int{ints(storageLeaf)}},
		}},
	}
}

// ethServer answers every state or call request with envelope, recording the
// bodies sent.
func ethServer(t *testing.T, envelope *wireEnvelope) (*EthOperations, *[]map[string]interface{}) {
	t.Helper()
	var bodies []map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		bodies = append(bodies, body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(envelope)
	}))
	t.Cleanup(srv.Close)
	return NewEthOperations(srv.URL, srv.Client()), &bodies
}

// A state read returns the slot asked for, and refuses an answer about another
// address, block, or slot (or another number or order of slots) in every
// mode; in EthWalkProofs mode it also refuses a proof that doesn't walk.
func TestGetStateAnswersTheRequest(t *testing.T) {
	ctx := context.Background()
	token := bytes.Repeat([]byte{0x11}, 20)
	holder := bytes.Repeat([]byte{0x22}, 20)
	slot := mappingSlotForAddress(holder, 0)
	tokenHex := "0x" + hex.EncodeToString(token)
	holderHex := "0x" + hex.EncodeToString(holder)

	good := oneSlotProof(token, slot, 42, 9)
	eth, bodies := ethServer(t, &wireEnvelope{StateRoot: good.StateRoot, BlockRange: [2]uint64{9, 9}, StateProofs: []wireStateProof{good}})
	balance, err := eth.Erc20Balance(ctx, tokenHex, holderHex, 0, 9)
	if err != nil || balance.Int64() != 42 {
		t.Fatalf("Erc20Balance = %v, %v; want 42", balance, err)
	}
	if got := (*bodies)[0]["slots"].([]interface{})[0]; got != "0x"+hex.EncodeToString(slot) {
		t.Fatalf("sent slot %v", got)
	}

	// The proof is for the holder's slot; asking for another holder's (or
	// another slot) is refused, as are another address and block.
	other := "0x" + strings.Repeat("33", 20)
	for name, call := range map[string]func(*EthOperations) error{
		"another holder's slot": func(e *EthOperations) error { _, err := e.Erc20Balance(ctx, tokenHex, other, 0, 9); return err },
		"another slot":          func(e *EthOperations) error { _, err := e.GetState(ctx, tokenHex, []string{"0x1"}, 9); return err },
		"no slot":               func(e *EthOperations) error { _, err := e.GetState(ctx, tokenHex, nil, 9); return err },
		"two slots": func(e *EthOperations) error {
			_, err := e.GetState(ctx, tokenHex, []string{"0x" + hex.EncodeToString(slot), "0x1"}, 9)
			return err
		},
		"another address": func(e *EthOperations) error { _, err := e.Erc20Balance(ctx, other, holderHex, 0, 9); return err },
		"another block":   func(e *EthOperations) error { _, err := e.Erc20Balance(ctx, tokenHex, holderHex, 0, 10); return err },
	} {
		for _, mode := range []EthProofMode{EthWalkProofs, EthSkipProofs} {
			eth.Mode = mode
			if err := call(eth); err == nil {
				t.Errorf("%s (mode %d): answered", name, mode)
			}
		}
	}

	// Walking the proofs catches a value the proof doesn't carry; skipping
	// them doesn't.
	tampered := oneSlotProof(token, slot, 42, 9)
	tampered.StorageProofs[0].Value[31] = 43
	eth, _ = ethServer(t, &wireEnvelope{StateRoot: tampered.StateRoot, BlockRange: [2]uint64{9, 9}, StateProofs: []wireStateProof{tampered}})
	if _, err := eth.Erc20Balance(ctx, tokenHex, holderHex, 0, 9); err == nil {
		t.Fatal("a tampered value walked")
	}
	eth.Mode = EthSkipProofs
	if balance, err := eth.Erc20Balance(ctx, tokenHex, holderHex, 0, 9); err != nil || balance.Int64() != 43 {
		t.Fatalf("skipping proofs: %v, %v", balance, err)
	}

	// A slot is a big-endian number, sent as 32 bytes; more is refused.
	low := oneSlotProof(token, make([]byte, 32), 5, 9)
	eth, bodies = ethServer(t, &wireEnvelope{StateRoot: low.StateRoot, BlockRange: [2]uint64{9, 9}, StateProofs: []wireStateProof{low}})
	if state, err := eth.GetState(ctx, tokenHex, []string{"0x0"}, 9); err != nil || state.Storage[0].Value.Int64() != 5 {
		t.Fatalf("slot 0x0: %+v, %v", state, err)
	}
	if got := (*bodies)[0]["slots"].([]interface{})[0]; got != "0x"+strings.Repeat("00", 32) {
		t.Fatalf("sent slot %v", got)
	}
	if _, err := eth.GetState(ctx, tokenHex, []string{"0x" + strings.Repeat("00", 33)}, 9); !IsValidationError(err) {
		t.Fatalf("a 33-byte slot: %v", err)
	}
	if len(*bodies) != 1 {
		t.Fatalf("sent %d requests, want 1", len(*bodies))
	}
}

// A call's state proofs must be for the block asked for, under the answer's
// state root.
func TestGetCallStateProofsAreForTheRequest(t *testing.T) {
	ctx := context.Background()
	proof := oneSlotProof(bytes.Repeat([]byte{0x11}, 20), make([]byte, 32), 1, 9)
	eth, _ := ethServer(t, &wireEnvelope{Answer: "AQI", StateRoot: proof.StateRoot, BlockRange: [2]uint64{9, 9}, StateProofs: []wireStateProof{proof}})
	call, err := eth.GetCall(ctx, map[string]interface{}{}, 9)
	if err != nil || !bytes.Equal(call.Result, []byte{1, 2}) || len(call.AccessStateReads) != 1 {
		t.Fatalf("GetCall = %+v, %v", call, err)
	}
	if _, err := eth.GetCall(ctx, map[string]interface{}{}, 10); err == nil {
		t.Fatal("an answer for block 9 returned for block 10")
	}

	otherRoot := make([]int, 32)
	eth, _ = ethServer(t, &wireEnvelope{Answer: "AQI", StateRoot: otherRoot, BlockRange: [2]uint64{9, 9}, StateProofs: []wireStateProof{proof}})
	eth.Mode = EthSkipProofs
	if _, err := eth.GetCall(ctx, map[string]interface{}{}, 9); err == nil {
		t.Fatal("a state proof under another root than the answer's was accepted")
	}

	stale := oneSlotProof(bytes.Repeat([]byte{0x11}, 20), make([]byte, 32), 1, 8)
	eth, _ = ethServer(t, &wireEnvelope{Answer: "AQI", StateRoot: stale.StateRoot, BlockRange: [2]uint64{9, 9}, StateProofs: []wireStateProof{stale}})
	if _, err := eth.GetCall(ctx, map[string]interface{}{}, 9); err == nil {
		t.Fatal("a state proof for block 8 accepted for block 9")
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
