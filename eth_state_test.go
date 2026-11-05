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
// one leaf: address's account (a contract's), and slot holding value, at block.
func oneSlotProof(address, slot []byte, value byte, block uint64) wireStateProof {
	leaf := func(key, value []byte) []byte {
		path := append([]byte{0x20}, keccak256(key)...) // leaf, even nibble count
		return rlpEncodeList([][]byte{rlpEncodeBytes(path), rlpEncodeBytes(value)})
	}
	storageLeaf := leaf(slot, rlpEncodeBytes([]byte{value}))
	storageHash := keccak256(storageLeaf)
	codeHash := keccak256([]byte{0x60, 0x80})
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

// Unset storage slots and accounts that don't exist have no leaf: their proofs
// show the key absent, at an empty branch child or where the path diverges
// from a leaf's or an extension's. The walk accepts such a proof for a zero
// value or an empty account, and nothing else.
func TestWalkProvesZeroSlotsAndAbsentAccounts(t *testing.T) {
	// Slots chosen by their hashed keys' leading nibbles: a and b differ in
	// the first nibble; c in neither's first nibble; d shares a's first; e and
	// f share a first nibble and differ in the second; g differs from e's first.
	first := func(s []byte) int { return bytesToNibbles(keccak256(s))[0] }
	second := func(s []byte) int { return bytesToNibbles(keccak256(s))[1] }
	a := testSlot(func(s []byte) bool { return true })
	b := testSlot(func(s []byte) bool { return first(s) != first(a) })
	c := testSlot(func(s []byte) bool { return first(s) != first(a) && first(s) != first(b) })
	d := testSlot(func(s []byte) bool { return first(s) == first(a) && !bytes.Equal(s, a) })
	e := testSlot(func(s []byte) bool { return true })
	f := testSlot(func(s []byte) bool { return first(s) == first(e) && second(s) != second(e) })
	g := testSlot(func(s []byte) bool { return first(s) != first(e) })

	branchy := newTestTrie([][]byte{a, b}, [][]byte{storageValue(7), storageValue(9)})
	extension := newTestTrie([][]byte{e, f}, [][]byte{storageValue(7), storageValue(9)})
	if node, _ := rlpDecodeList(extension.prove(g)[0]); len(node) != 2 {
		t.Fatal("the e/f trie's root isn't an extension")
	}
	empty := newTestTrie(nil, nil)

	slotCases := []struct {
		name    string
		storage *testTrie
		slot    []byte
		value   int64
		proof   [][]byte // nil: the trie's own
		ok      bool
	}{
		{"unset slot at an empty branch child, zero", branchy, c, 0, nil, true},
		{"unset slot at an empty branch child, nonzero", branchy, c, 5, nil, false},
		{"unset slot diverging from a leaf, zero", branchy, d, 0, nil, true},
		{"unset slot diverging from a leaf, nonzero", branchy, d, 5, nil, false},
		{"unset slot diverging from an extension, zero", extension, g, 0, nil, true},
		{"unset slot diverging from an extension, nonzero", extension, g, 5, nil, false},
		{"set slot, its value", branchy, a, 7, nil, true},
		{"set slot, zero", branchy, a, 0, nil, false},
		{"set slot, another value", branchy, b, 7, nil, false},
		{"no storage, zero", empty, a, 0, nil, true},
		{"no storage, the empty node, zero", empty, a, 0, [][]byte{{0x80}}, true},
		{"no storage, nonzero", empty, a, 5, nil, false},
		{"an empty proof under a storage root", branchy, c, 0, [][]byte{}, false},
	}
	token := bytes.Repeat([]byte{0x11}, 20)
	for _, tc := range slotCases {
		state := newTestTrie([][]byte{token, bytes.Repeat([]byte{0x44}, 20)},
			[][]byte{rlpEncodeAccount(1, big.NewInt(5), tc.storage.root(), emptyCodeHash), rlpEncodeAccount(0, big.NewInt(1), emptyTrieRoot, emptyCodeHash)})
		p := testStateProof(state, token, wireAccountState{Nonce: 1, Balance: toInts(word(5)), StorageHash: toInts(tc.storage.root()), CodeHash: toInts(emptyCodeHash)},
			tc.storage, [][]byte{tc.slot}, []int64{tc.value})
		if tc.proof != nil {
			p.StorageProofs[0].Proof.ProofNodes = intsOf(tc.proof)
		}
		if err := walkStateProof(&p); (err == nil) != tc.ok {
			t.Errorf("%s: walk = %v, want ok %v", tc.name, err, tc.ok)
		}
	}

	// Accounts: p and q exist; r doesn't.
	p, q, r := bytes.Repeat([]byte{0x44}, 20), bytes.Repeat([]byte{0x55}, 20), bytes.Repeat([]byte{0x66}, 20)
	state := newTestTrie([][]byte{p, q}, [][]byte{
		rlpEncodeAccount(3, big.NewInt(100), branchy.root(), keccak256([]byte{0x60})),
		rlpEncodeAccount(0, big.NewInt(1), emptyTrieRoot, emptyCodeHash),
	})
	emptyAccount := wireAccountState{Balance: make([]int, 32), StorageHash: toInts(emptyTrieRoot), CodeHash: toInts(emptyCodeHash)}
	gethEmpty := wireAccountState{Balance: make([]int, 32), StorageHash: make([]int, 32), CodeHash: make([]int, 32)}
	with := func(acct wireAccountState, change func(*wireAccountState)) wireAccountState {
		acct.Balance = append([]int(nil), acct.Balance...)
		change(&acct)
		return acct
	}
	accountCases := []struct {
		name    string
		address []byte
		claim   wireAccountState
		value   int64
		ok      bool
	}{
		{"absent, empty", r, emptyAccount, 0, true},
		{"absent, empty with zero hashes", r, gethEmpty, 0, true},
		{"absent, a slot nonzero", r, emptyAccount, 5, false},
		{"absent, a nonce", r, with(emptyAccount, func(a *wireAccountState) { a.Nonce = 1 }), 0, false},
		{"absent, a balance", r, with(emptyAccount, func(a *wireAccountState) { a.Balance[31] = 1 }), 0, false},
		{"absent, code", r, with(emptyAccount, func(a *wireAccountState) { a.CodeHash = toInts(keccak256([]byte{0x60})) }), 0, false},
		{"absent, storage", r, with(emptyAccount, func(a *wireAccountState) { a.StorageHash = toInts(branchy.root()) }), 0, false},
		{"present, claimed empty", q, emptyAccount, 0, false},
	}
	for _, tc := range accountCases {
		proof := testStateProof(state, tc.address, tc.claim, empty, [][]byte{a}, []int64{tc.value})
		if err := walkStateProof(&proof); (err == nil) != tc.ok {
			t.Errorf("%s: walk = %v, want ok %v", tc.name, err, tc.ok)
		}
	}
	present := testStateProof(state, p, wireAccountState{Nonce: 3, Balance: toInts(word(100)), StorageHash: toInts(branchy.root()), CodeHash: toInts(keccak256([]byte{0x60}))},
		branchy, [][]byte{a, c}, []int64{7, 0})
	if err := walkStateProof(&present); err != nil {
		t.Errorf("present, a set and an unset slot: %v", err)
	}
}

// Through EthOperations, in the default EthWalkProofs mode: a zero ERC-20
// balance, an account that doesn't exist, and a call reading an unset slot of
// an account that doesn't exist are answered; a nonzero balance claimed for an
// unset slot is refused.
func TestEthReadsOfZeroValuesAndAbsentAccounts(t *testing.T) {
	ctx := context.Background()
	token := bytes.Repeat([]byte{0x11}, 20)
	holder := bytes.Repeat([]byte{0x22}, 20)
	other := bytes.Repeat([]byte{0x33}, 20)
	tokenHex, holderHex := "0x"+hex.EncodeToString(token), "0x"+hex.EncodeToString(holder)

	// The token's storage holds another holder's balance; this holder's is unset.
	storage := newTestTrie([][]byte{mappingSlotForAddress(other, 0)}, [][]byte{storageValue(1000)})
	codeHash := keccak256([]byte{0x60, 0x80})
	state := newTestTrie([][]byte{token, other}, [][]byte{
		rlpEncodeAccount(1, big.NewInt(0), storage.root(), codeHash),
		rlpEncodeAccount(4, big.NewInt(50), emptyTrieRoot, emptyCodeHash),
	})
	tokenState := wireAccountState{Nonce: 1, Balance: make([]int, 32), StorageHash: toInts(storage.root()), CodeHash: toInts(codeHash)}
	slot := mappingSlotForAddress(holder, 0)
	zero := testStateProof(state, token, tokenState, storage, [][]byte{slot}, []int64{0})
	eth, _ := ethServer(t, &wireEnvelope{StateRoot: zero.StateRoot, BlockRange: [2]uint64{9, 9}, StateProofs: []wireStateProof{zero}})
	if balance, err := eth.Erc20Balance(ctx, tokenHex, holderHex, 0, 9); err != nil || balance.Sign() != 0 {
		t.Fatalf("a zero balance: %v, %v", balance, err)
	}

	claimed := testStateProof(state, token, tokenState, storage, [][]byte{slot}, []int64{1000})
	eth, _ = ethServer(t, &wireEnvelope{StateRoot: claimed.StateRoot, BlockRange: [2]uint64{9, 9}, StateProofs: []wireStateProof{claimed}})
	if balance, err := eth.Erc20Balance(ctx, tokenHex, holderHex, 0, 9); err == nil {
		t.Fatalf("a balance of %v claimed for an unset slot was returned", balance)
	}

	// The holder has no account.
	absent := wireAccountState{Balance: make([]int, 32), StorageHash: toInts(emptyTrieRoot), CodeHash: toInts(emptyCodeHash)}
	none := testStateProof(state, holder, absent, newTestTrie(nil, nil), [][]byte{make([]byte, 32)}, []int64{0})
	eth, _ = ethServer(t, &wireEnvelope{StateRoot: none.StateRoot, BlockRange: [2]uint64{9, 9}, StateProofs: []wireStateProof{none}})
	read, err := eth.GetState(ctx, holderHex, []string{"0x0"}, 9)
	if err != nil || read.Nonce != 0 || read.Balance.Sign() != 0 || read.Storage[0].Value.Sign() != 0 {
		t.Fatalf("an absent account: %+v, %v", read, err)
	}

	// A call that read the token's unset slot and touched the absent holder.
	eth, _ = ethServer(t, &wireEnvelope{Answer: "AA", StateRoot: zero.StateRoot, BlockRange: [2]uint64{9, 9}, StateProofs: []wireStateProof{zero, none}})
	if call, err := eth.GetCall(ctx, map[string]interface{}{}, 9); err != nil || len(call.AccessStateReads) != 2 {
		t.Fatalf("a call reading an unset slot: %+v, %v", call, err)
	}
}

// An address is 20 bytes and a slot 32. A key of another length hashes to
// another path in the trie, so its absence says nothing about the 20- or
// 32-byte key it would be read as: the walk refuses it, in a call's state
// proofs as in a state read's.
func TestWalkRefusesKeysOfAnotherLength(t *testing.T) {
	ctx := context.Background()
	funded := append(make([]byte, 4), bytes.Repeat([]byte{0x77}, 16)...)
	token := bytes.Repeat([]byte{0x11}, 20)
	storage := newTestTrie([][]byte{word(2)}, [][]byte{storageValue(1000000)})
	codeHash := keccak256([]byte{0x60, 0x80})
	state := newTestTrie([][]byte{funded, token}, [][]byte{
		rlpEncodeAccount(1, big.NewInt(1000), emptyTrieRoot, codeHash),
		rlpEncodeAccount(1, big.NewInt(0), storage.root(), codeHash),
	})
	gethEmpty := wireAccountState{Balance: make([]int, 32), StorageHash: make([]int, 32), CodeHash: make([]int, 32)}
	tokenState := wireAccountState{Nonce: 1, Balance: make([]int, 32), StorageHash: toInts(storage.root()), CodeHash: toInts(codeHash)}

	honest := testStateProof(state, token, tokenState, storage, [][]byte{word(2)}, []int64{1000000})
	if err := walkStateProof(&honest); err != nil {
		t.Fatalf("the honest proof: %v", err)
	}

	// The funded account claimed empty, and the token's slot 2 claimed zero,
	// each under a key of another length that the trie doesn't hold.
	cases := map[string]wireStateProof{
		"a 16-byte address": testStateProof(state, funded[4:], gethEmpty, newTestTrie(nil, nil), nil, nil),
		"a 21-byte address": testStateProof(state, append([]byte{0}, funded...), gethEmpty, newTestTrie(nil, nil), nil, nil),
		"a 1-byte slot":     testStateProof(state, token, tokenState, storage, [][]byte{{0x02}}, []int64{0}),
		"a 31-byte slot":    testStateProof(state, token, tokenState, storage, [][]byte{word(2)[1:]}, []int64{0}),
		"a 33-byte slot":    testStateProof(state, token, tokenState, storage, [][]byte{append([]byte{0}, word(2)...)}, []int64{0}),
	}
	for name, p := range cases {
		if err := walkStateProof(&p); err == nil || !contains(err.Error(), "bytes, not") {
			t.Errorf("%s: walk = %v, want a length refusal", name, err)
		}
		eth, _ := ethServer(t, &wireEnvelope{Answer: "AA", StateRoot: p.StateRoot, BlockRange: [2]uint64{9, 9}, StateProofs: []wireStateProof{honest, p}})
		if call, err := eth.GetCall(ctx, map[string]interface{}{}, 9); err == nil {
			t.Errorf("%s: a call's state proof was accepted: %+v", name, call.AccessStateReads)
		}
	}
}

// Erc20Balance refuses a token address with no contract: an account that
// doesn't exist, or one without code. A wrong balance slot reads as zero.
func TestErc20BalanceNeedsAContract(t *testing.T) {
	ctx := context.Background()
	token := bytes.Repeat([]byte{0x11}, 20)
	holder := bytes.Repeat([]byte{0x22}, 20)
	eoa := bytes.Repeat([]byte{0x44}, 20)
	nobody := bytes.Repeat([]byte{0x66}, 20)
	storage := newTestTrie([][]byte{mappingSlotForAddress(holder, 0)}, [][]byte{storageValue(1000)})
	codeHash := keccak256([]byte{0x60, 0x80})
	state := newTestTrie([][]byte{token, eoa}, [][]byte{
		rlpEncodeAccount(1, big.NewInt(0), storage.root(), codeHash),
		rlpEncodeAccount(4, big.NewInt(50), emptyTrieRoot, emptyCodeHash),
	})
	tokenState := wireAccountState{Nonce: 1, Balance: make([]int, 32), StorageHash: toInts(storage.root()), CodeHash: toInts(codeHash)}
	eoaState := wireAccountState{Nonce: 4, Balance: toInts(word(50)), StorageHash: toInts(emptyTrieRoot), CodeHash: toInts(emptyCodeHash)}
	absent := wireAccountState{Balance: make([]int, 32), StorageHash: toInts(emptyTrieRoot), CodeHash: toInts(emptyCodeHash)}
	gethEmpty := wireAccountState{Balance: make([]int, 32), StorageHash: make([]int, 32), CodeHash: make([]int, 32)}
	empty := newTestTrie(nil, nil)

	balance := func(address []byte, claim wireAccountState, storage *testTrie, balanceSlot byte, value int64, mode EthProofMode) (*big.Int, error) {
		p := testStateProof(state, address, claim, storage, [][]byte{mappingSlotForAddress(holder, balanceSlot)}, []int64{value})
		eth, _ := ethServer(t, &wireEnvelope{StateRoot: p.StateRoot, BlockRange: [2]uint64{9, 9}, StateProofs: []wireStateProof{p}})
		eth.Mode = mode
		return eth.Erc20Balance(ctx, "0x"+hex.EncodeToString(address), "0x"+hex.EncodeToString(holder), balanceSlot, 9)
	}

	if got, err := balance(token, tokenState, storage, 0, 1000, EthWalkProofs); err != nil || got.Int64() != 1000 {
		t.Fatalf("the token's balance: %v, %v", got, err)
	}
	if got, err := balance(token, tokenState, storage, 1, 0, EthWalkProofs); err != nil || got.Sign() != 0 {
		t.Fatalf("a wrong balance slot: %v, %v; want zero", got, err)
	}
	for name, read := range map[string]func() (*big.Int, error){
		"an account without code":           func() (*big.Int, error) { return balance(eoa, eoaState, empty, 0, 0, EthWalkProofs) },
		"an account without code, unwalked": func() (*big.Int, error) { return balance(eoa, eoaState, empty, 0, 0, EthSkipProofs) },
		"no account":                        func() (*big.Int, error) { return balance(nobody, absent, empty, 0, 0, EthWalkProofs) },
		"no account, zero hashes":           func() (*big.Int, error) { return balance(nobody, gethEmpty, empty, 0, 0, EthWalkProofs) },
	} {
		if got, err := read(); err == nil || !contains(err.Error(), "no contract") {
			t.Errorf("%s: %v, %v; want a refusal", name, got, err)
		}
	}
}

// A proof node whose RLP length doesn't fit in the node, however large, is
// refused, in every read that walks it: a length of eight 0xff bytes, or one
// past the largest int, must not wrap around and pass the bounds check. The
// node is the proof's only one, under a state root that is its hash.
func TestEthReadsRefuseAnRlpLengthPastTheNode(t *testing.T) {
	ctx := context.Background()
	token := bytes.Repeat([]byte{0x11}, 20)
	holder := bytes.Repeat([]byte{0x22}, 20)
	tokenHex := "0x" + hex.EncodeToString(token)
	holderHex := "0x" + hex.EncodeToString(holder)
	slot := mappingSlotForAddress(holder, 0)
	allOnes := bytes.Repeat([]byte{0xff}, 8)
	maxInt := append([]byte{0x7f}, bytes.Repeat([]byte{0xff}, 7)...)
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	nodes := map[string][]byte{
		"a list of length 2^64-1":     cat([]byte{0xff}, allOnes, []byte{0x00}),
		"a list of length 2^63-1":     cat([]byte{0xff}, maxInt, []byte{0x00}),
		"a string of length 2^64-1":   cat([]byte{0xca, 0xbf}, allOnes, []byte{0x00}),
		"a string of length 2^63-1":   cat([]byte{0xca, 0xbf}, maxInt, []byte{0x00}),
		"a list one byte past":        cat([]byte{0xf8, 0x39}, bytes.Repeat([]byte{0x01}, 56)),
		"a string one byte past":      cat([]byte{0xf8, 0x39, 0xb8, 0x38}, bytes.Repeat([]byte{0x01}, 55)),
		"a list's length cut short":   {0xf9, 0x01},
		"a string's length cut short": {0xc2, 0xb9, 0x01},
	}
	for name, node := range nodes {
		proof := oneSlotProof(token, slot, 42, 9)
		proof.StateRoot = toInts(keccak256(node))
		proof.AccountProof.ProofNodes = [][]int{toInts(node)}
		eth, _ := ethServer(t, &wireEnvelope{Answer: "AQI", StateRoot: proof.StateRoot, BlockRange: [2]uint64{9, 9}, StateProofs: []wireStateProof{proof}})
		reads := map[string]func() error{
			"GetState": func() error {
				_, err := eth.GetState(ctx, tokenHex, []string{"0x" + hex.EncodeToString(slot)}, 9)
				return err
			},
			"Erc20Balance": func() error { _, err := eth.Erc20Balance(ctx, tokenHex, holderHex, 0, 9); return err },
			"GetCall":      func() error { _, err := eth.GetCall(ctx, map[string]interface{}{}, 9); return err },
		}
		for read, call := range reads {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("%s, %s: panicked: %v", name, read, r)
					}
				}()
				if err := call(); err == nil || !contains(err.Error(), "rlp") {
					t.Errorf("%s, %s: %v; want an RLP refusal", name, read, err)
				}
			}()
		}
	}
}

// The tests' tries are Ethereum's: testTrie gives the root of the secure-trie
// vector "emptyValues" in Ethereum's trie tests, and its proofs walk.
func TestTestTrieIsEthereums(t *testing.T) {
	keys := [][]byte{[]byte("do"), []byte("horse"), []byte("doge"), []byte("dog")}
	values := [][]byte{[]byte("verb"), []byte("stallion"), []byte("coin"), []byte("puppy")}
	tr := newTestTrie(keys, values)
	if got := hex.EncodeToString(tr.root()); got != "29b235a58c3c25ab83010c327d5932bcf05324b7d6b1185e650798034783ca9d" {
		t.Fatalf("root %s", got)
	}
	for i, k := range keys {
		if err := verifyMptProof(tr.root(), keccak256(k), values[i], tr.prove(k)); err != nil {
			t.Fatalf("%s: %v", k, err)
		}
	}
	if err := verifyMptProof(tr.root(), keccak256([]byte("ether")), nil, tr.prove([]byte("ether"))); err != nil {
		t.Fatalf("an absent key: %v", err)
	}
	if hex.EncodeToString(emptyTrieRoot) != "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421" ||
		hex.EncodeToString(emptyCodeHash) != "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470" {
		t.Fatalf("empty trie root %x, empty code hash %x", emptyTrieRoot, emptyCodeHash)
	}
}

// helpers --------------------------------------------------------------------

// testTrie is a Merkle Patricia trie keyed by keccak256 of its keys, as
// Ethereum's state and storage tries are. Each child is referenced by its
// hash: with 32-byte hashed keys a node is inlined only far deeper than these
// tries go.
type testTrie struct{ entries []trieEntry }

type trieEntry struct {
	path  []int
	value []byte
}

func newTestTrie(keys, values [][]byte) *testTrie {
	tr := &testTrie{}
	for i, k := range keys {
		tr.entries = append(tr.entries, trieEntry{bytesToNibbles(keccak256(k)), values[i]})
	}
	return tr
}

func (tr *testTrie) root() []byte {
	if len(tr.entries) == 0 {
		return emptyTrieRoot
	}
	return keccak256(trieNode(tr.entries, 0))
}

// prove returns the nodes from the root along key's path, as eth_getProof
// does: through the key's leaf, or to where the path shows it absent.
func (tr *testTrie) prove(key []byte) [][]byte {
	if len(tr.entries) == 0 {
		return [][]byte{}
	}
	return trieProof(tr.entries, 0, bytesToNibbles(keccak256(key)))
}

func trieNode(entries []trieEntry, depth int) []byte {
	if len(entries) == 1 {
		return rlpEncodeList([][]byte{rlpEncodeBytes(compactPath(entries[0].path[depth:], true)), rlpEncodeBytes(entries[0].value)})
	}
	if n := commonPrefix(entries, depth); n > 0 {
		child := trieNode(entries, depth+n)
		return rlpEncodeList([][]byte{rlpEncodeBytes(compactPath(entries[0].path[depth:depth+n], false)), rlpEncodeBytes(keccak256(child))})
	}
	items := make([][]byte, 17)
	for nib := range 16 {
		items[nib] = rlpEncodeBytes(nil)
		if sub := entriesAt(entries, depth, nib); len(sub) > 0 {
			items[nib] = rlpEncodeBytes(keccak256(trieNode(sub, depth+1)))
		}
	}
	items[16] = rlpEncodeBytes(nil)
	return rlpEncodeList(items)
}

func trieProof(entries []trieEntry, depth int, path []int) [][]byte {
	proof := [][]byte{trieNode(entries, depth)}
	if len(entries) == 1 {
		return proof
	}
	if n := commonPrefix(entries, depth); n > 0 {
		if !nibblesEqual(path[depth:depth+n], entries[0].path[depth:depth+n]) {
			return proof
		}
		return append(proof, trieProof(entries, depth+n, path)...)
	}
	sub := entriesAt(entries, depth, path[depth])
	if len(sub) == 0 {
		return proof
	}
	return append(proof, trieProof(sub, depth+1, path)...)
}

func commonPrefix(entries []trieEntry, depth int) int {
	n := 0
	for ; depth+n < len(entries[0].path); n++ {
		for _, e := range entries[1:] {
			if e.path[depth+n] != entries[0].path[depth+n] {
				return n
			}
		}
	}
	return n
}

func entriesAt(entries []trieEntry, depth, nib int) []trieEntry {
	var sub []trieEntry
	for _, e := range entries {
		if e.path[depth] == nib {
			sub = append(sub, e)
		}
	}
	return sub
}

// compactPath is the hex-prefix encoding of nibbles, for a leaf or an extension.
func compactPath(nibs []int, leaf bool) []byte {
	flag := byte(0)
	if leaf {
		flag = 2
	}
	out := []byte{flag << 4}
	if len(nibs)%2 == 1 {
		out[0] = (flag+1)<<4 | byte(nibs[0])
		nibs = nibs[1:]
	}
	for i := 0; i < len(nibs); i += 2 {
		out = append(out, byte(nibs[i])<<4|byte(nibs[i+1]))
	}
	return out
}

// testStateProof is a state proof of address in state, claiming claim, with
// each slot proved in storage and claimed to hold values[i].
func testStateProof(state *testTrie, address []byte, claim wireAccountState, storage *testTrie, slots [][]byte, values []int64) wireStateProof {
	proof := wireStateProof{
		Address:      toInts(address),
		BlockNumber:  9,
		BlockHash:    toInts(bytes.Repeat([]byte{0xbb}, 32)),
		StateRoot:    toInts(state.root()),
		AccountProof: wireMptProofInts{Key: toInts(keccak256(address)), ProofNodes: intsOf(state.prove(address))},
		AccountState: claim,
	}
	for i, slot := range slots {
		proof.StorageProofs = append(proof.StorageProofs, wireStorageSlot{
			Slot:  toInts(slot),
			Value: toInts(word(values[i])),
			Proof: wireMptProofInts{Key: toInts(keccak256(slot)), ProofNodes: intsOf(storage.prove(slot))},
		})
	}
	return proof
}

// testSlot returns the first slot, counting from 1, that ok accepts.
func testSlot(ok func(slot []byte) bool) []byte {
	for i := int64(1); ; i++ {
		if s := word(i); ok(s) {
			return s
		}
	}
}

// storageValue is a storage leaf's value: the RLP of the value's minimal bytes.
func storageValue(v int64) []byte {
	return rlpEncodeBytes(big.NewInt(v).Bytes())
}

// word is v as 32 big-endian bytes.
func word(v int64) []byte {
	return big.NewInt(v).FillBytes(make([]byte, 32))
}

func toInts(b []byte) []int {
	out := make([]int, len(b))
	for i, x := range b {
		out[i] = int(x)
	}
	return out
}

func intsOf(nodes [][]byte) [][]int {
	out := make([][]int, len(nodes))
	for i, n := range nodes {
		out[i] = toInts(n)
	}
	return out
}

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
