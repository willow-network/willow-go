// Package willow — Ethereum state reads served by an indexer.
//
// Counterpart to the indexer's POST /verifiable-rpc/eth/state and
// /verifiable-rpc/eth/call routes. Walks EIP-1186 MPT proofs locally
// and exposes a storage-layout helper (ERC-20 balance).
//
// The SDK doesn't verify these reads against Ethereum (see EthOperations).
package willow

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"

	"github.com/willow-network/willow-go/internal/httpbody"
	"golang.org/x/crypto/sha3"
)

// EthProofMode selects how much of an indexer's Ethereum state answer
// EthOperations checks. No mode verifies the answer against Ethereum (see
// EthOperations).
type EthProofMode int

const (
	// EthWalkProofs (the default) walks the account proof and every storage
	// proof against the state root the answer itself carries.
	EthWalkProofs EthProofMode = iota
	// EthSkipProofs returns the answer's values without walking its proofs.
	EthSkipProofs
)

// StateVerifyMode is EthProofMode.
//
// Deprecated: no mode verifies a read against Ethereum; use EthProofMode.
type StateVerifyMode = EthProofMode

const (
	// Deprecated: use EthWalkProofs, which walks the proofs against the
	// answer's own state root; the SDK doesn't verify that root.
	StateVerifyModeStrict = EthWalkProofs
	// Deprecated: use EthSkipProofs; no root is anchored to anything trusted.
	StateVerifyModeAnchorOnly = EthSkipProofs
	// Deprecated: use EthSkipProofs, which it acts as: no proof is walked. It
	// keeps its own value, 2, so a switch over the three older modes still
	// compiles.
	StateVerifyModeDisabled EthProofMode = 2
)

// wire types -----------------------------------------------------------------

type wireAccountState struct {
	Nonce       uint64 `json:"nonce"`
	Balance     []int  `json:"balance"`
	StorageHash []int  `json:"storage_hash"`
	CodeHash    []int  `json:"code_hash"`
}

type wireStorageSlot struct {
	Slot  []int            `json:"slot"`
	Value []int            `json:"value"`
	Proof wireMptProofInts `json:"proof"`
}

type wireStateProof struct {
	Address       []int             `json:"address"`
	BlockNumber   uint64            `json:"block_number"`
	BlockHash     []int             `json:"block_hash"`
	StateRoot     []int             `json:"state_root"`
	AccountProof  wireMptProofInts  `json:"account_proof"`
	AccountState  wireAccountState  `json:"account_state"`
	StorageProofs []wireStorageSlot `json:"storage_proofs"`
}

// MptProof in the wire envelope serializes key/value/proof_nodes from the
// Rust server as JSON arrays of numbers (default serde for Vec<u8>).
type wireMptProofInts struct {
	Key        []int   `json:"key"`
	Value      []int   `json:"value"`
	ProofNodes [][]int `json:"proof_nodes"`
}

type wireEnvelope struct {
	SubgroveID   string           `json:"subgrove_id"`
	Key          string           `json:"key"`
	Answer       string           `json:"answer"`
	AnswerExists bool             `json:"answer_exists"`
	StateRoot    []int            `json:"state_root"`
	BlockRange   [2]uint64        `json:"block_range"`
	StateProofs  []wireStateProof `json:"state_proofs"`
}

// public types ---------------------------------------------------------------

// EthStorageSlot is a storage slot's value as an indexer's answer carries it.
type EthStorageSlot struct {
	Slot  string
	Value *big.Int
}

// EthStateRead is an account's state (and asked storage slots) at a block, as
// an indexer's answer carries it, unverified against Ethereum (see
// EthOperations). Mode says whether its proofs were walked against StateRoot.
type EthStateRead struct {
	Address     string
	BlockNumber uint64
	BlockHash   string
	StateRoot   string
	Nonce       uint64
	Balance     *big.Int
	StorageHash string
	CodeHash    string
	Storage     []EthStorageSlot
	Mode        EthProofMode
}

// EthCallResult is an eth_call as an indexer ran it: its result, and the
// state of every account the call touched, unverified against Ethereum (see
// EthOperations). No proof binds Result: the SDK doesn't run the call.
type EthCallResult struct {
	BlockNumber      uint64
	BlockHash        string
	StateRoot        string
	Result           []byte
	AccessStateReads []EthStateRead
	Mode             EthProofMode
}

// VerifiedStorage is EthStorageSlot.
//
// Deprecated: the value isn't verified against Ethereum; use EthStorageSlot.
type VerifiedStorage = EthStorageSlot

// VerifiedStateRead is EthStateRead.
//
// Deprecated: the state isn't verified against Ethereum; use EthStateRead.
type VerifiedStateRead = EthStateRead

// VerifiedCall is EthCallResult.
//
// Deprecated: the call isn't verified against Ethereum; use EthCallResult.
type VerifiedCall = EthCallResult

// EthOperations reads Ethereum state through an indexer.
//
// Nothing it returns is verified against Ethereum. Each answer carries the
// block's state root, and its MPT proofs bind the account and slot values to
// that root, but the SDK has no trusted source of Ethereum block headers (it
// runs no Ethereum light client; the block hash and state root it has are the
// indexer's), so it can't check that the root is the state root of the block
// asked for. Treat every result as the indexer's claim. In EthWalkProofs mode
// (the default) the SDK walks the proofs, so a result is at least consistent
// with the root the answer names; in EthSkipProofs mode it doesn't.
//
// A zero storage value is proved by the slot's absence from the account's
// storage trie, and an account that doesn't exist by its absence from the
// state trie. Such an account reads as nonce and balance zero, every slot
// asked of it zero, and the storage root and code hash the answer carries:
// the empty ones, or zero hashes (as geth names them).
//
// In every mode an answer must be about what was asked: a state read's proof
// must be for the address, block, and slots requested, in order, and a call's
// state proofs for the block requested, under the answer's state root.
type EthOperations struct {
	indexerBaseURL string
	http           *http.Client
	Mode           EthProofMode
}

// NewEthOperations reads Ethereum state through the indexer at
// indexerBaseURL with httpClient, or, when it is nil, a client with a 30 s
// timeout.
func NewEthOperations(indexerBaseURL string, httpClient *http.Client) *EthOperations {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultTimeout}
	}
	return &EthOperations{
		indexerBaseURL: strings.TrimRight(indexerBaseURL, "/"),
		http:           httpClient,
		Mode:           EthWalkProofs,
	}
}

// GetState reads an account's state, and the storage slots asked for, at
// blockNumber, as the indexer reports it (see EthOperations). address is 20
// bytes of hex; each slot is up to 32 bytes of hex, read as a big-endian
// number and sent as 32 bytes. It returns an error, rather than the answer,
// when the answer's proof isn't for that address, block, and those slots in
// that order, or carries a balance or value longer than 32 bytes, or, in
// EthWalkProofs mode, when a proof doesn't walk.
func (e *EthOperations) GetState(
	ctx context.Context,
	address string,
	slots []string,
	blockNumber uint64,
) (*EthStateRead, error) {
	addr, err := hexDecode20(address)
	if err != nil {
		return nil, NewValidationError(fmt.Sprintf("address: %v", err))
	}
	keys := make([][]byte, len(slots))
	sent := make([]string, len(slots))
	for i, s := range slots {
		if keys[i], err = slotKey(s); err != nil {
			return nil, NewValidationError(fmt.Sprintf("slot %d: %v", i, err))
		}
		sent[i] = "0x" + hex.EncodeToString(keys[i])
	}
	body := map[string]interface{}{
		"address": "0x" + hex.EncodeToString(addr),
		"slots":   sent,
		"block":   blockNumber,
	}
	envelope, err := e.post(ctx, "/verifiable-rpc/eth/state", body)
	if err != nil {
		return nil, err
	}
	if len(envelope.StateProofs) != 1 {
		return nil, fmt.Errorf("the answer carried %d state proofs, not 1", len(envelope.StateProofs))
	}
	proof := &envelope.StateProofs[0]
	if err := checkStateAnswer(proof, addr, keys, blockNumber); err != nil {
		return nil, err
	}
	if e.Mode == EthWalkProofs {
		if err := walkStateProof(proof); err != nil {
			return nil, err
		}
	}
	return toEthStateRead(proof, e.Mode), nil
}

// GetCall asks the indexer to run tx at blockNumber and returns the
// ABI-encoded result it reports, with its state proofs for every account the
// call touched (see EthOperations). No proof binds the result. It returns an
// error, rather than the answer, when a state proof isn't for blockNumber,
// isn't under the answer's state root, or carries a balance or value longer
// than 32 bytes, or, in EthWalkProofs mode, when a proof doesn't walk or its
// address isn't 20 bytes or a slot 32 bytes.
func (e *EthOperations) GetCall(
	ctx context.Context,
	tx map[string]interface{},
	blockNumber uint64,
) (*EthCallResult, error) {
	body := map[string]interface{}{"tx": tx, "block": blockNumber}
	envelope, err := e.post(ctx, "/verifiable-rpc/eth/call", body)
	if err != nil {
		return nil, err
	}
	if envelope.BlockRange[0] != blockNumber {
		return nil, fmt.Errorf("the answer is for block %d, not %d", envelope.BlockRange[0], blockNumber)
	}
	stateRoot, err := wireBytes(envelope.StateRoot, 32, "state root")
	if err != nil {
		return nil, err
	}
	for i := range envelope.StateProofs {
		p := &envelope.StateProofs[i]
		if p.BlockNumber != blockNumber {
			return nil, fmt.Errorf("state proof %d is for block %d, not %d", i, p.BlockNumber, blockNumber)
		}
		if err := checkWords(p); err != nil {
			return nil, fmt.Errorf("state proof %d: %w", i, err)
		}
		root, err := wireBytes(p.StateRoot, 32, fmt.Sprintf("state proof %d's state root", i))
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(root, stateRoot) {
			return nil, fmt.Errorf("state proof %d is under another state root than the answer's", i)
		}
	}
	if e.Mode == EthWalkProofs {
		for i := range envelope.StateProofs {
			if err := walkStateProof(&envelope.StateProofs[i]); err != nil {
				return nil, err
			}
		}
	}
	// envelope.Answer is base64-encoded ABI result.
	result, err := base64Decode(envelope.Answer)
	if err != nil {
		return nil, fmt.Errorf("decode result: %w", err)
	}
	var blockHash string
	if len(envelope.StateProofs) > 0 {
		blockHash = bytesIntsToHex(envelope.StateProofs[0].BlockHash, 32)
	} else {
		blockHash = "0x" + strings.Repeat("00", 32)
	}
	reads := make([]EthStateRead, len(envelope.StateProofs))
	for i := range envelope.StateProofs {
		reads[i] = *toEthStateRead(&envelope.StateProofs[i], e.Mode)
	}
	return &EthCallResult{
		BlockNumber:      envelope.BlockRange[0],
		BlockHash:        blockHash,
		StateRoot:        bytesIntsToHex(envelope.StateRoot, 32),
		Result:           result,
		AccessStateReads: reads,
		Mode:             e.Mode,
	}, nil
}

// Erc20Balance returns balanceOf(holder) for a token whose balance
// mapping lives at slot balanceSlot, as the indexer reports it (see
// EthOperations): the value of the slot GetState asked for. It returns an
// error when there is no contract at token: its account doesn't exist, or
// has no code. It can't tell whether balanceSlot is the token's balance
// mapping: a wrong balanceSlot reads a slot the token never set, which reads
// as zero.
func (e *EthOperations) Erc20Balance(
	ctx context.Context,
	token, holder string,
	balanceSlot byte,
	blockNumber uint64,
) (*big.Int, error) {
	addr, err := hexDecode20(holder)
	if err != nil {
		return nil, fmt.Errorf("holder: %w", err)
	}
	slot := mappingSlotForAddress(addr, balanceSlot)
	state, err := e.GetState(ctx, token, []string{"0x" + hex.EncodeToString(slot)}, blockNumber)
	if err != nil {
		return nil, err
	}
	// An account that doesn't exist reads with the empty code hash or the
	// zero hash, as one without code does.
	if state.CodeHash == "0x"+hex.EncodeToString(emptyCodeHash) || state.CodeHash == "0x"+strings.Repeat("00", 32) {
		return nil, fmt.Errorf("erc20Balance: no contract at %s: its account doesn't exist or has no code", state.Address)
	}
	if len(state.Storage) != 1 {
		return nil, errors.New("erc20Balance: no storage value for the balance slot")
	}
	return state.Storage[0].Value, nil
}

// slotKey reads a storage slot given as up to 32 bytes of hex (with or without
// 0x) as a big-endian number, left-padded to 32 bytes.
func slotKey(s string) ([]byte, error) {
	digits := strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	if digits == "" || len(digits) > 64 {
		return nil, fmt.Errorf("%q isn't 1 to 64 hex digits", s)
	}
	if len(digits)%2 == 1 {
		digits = "0" + digits
	}
	b, err := hex.DecodeString(digits)
	if err != nil {
		return nil, fmt.Errorf("%q isn't hex: %w", s, err)
	}
	key := make([]byte, 32)
	copy(key[32-len(b):], b)
	return key, nil
}

// wireBytes returns ints as bytes, refusing a length other than n or a value
// outside 0..255. what names the field.
func wireBytes(ints []int, n int, what string) ([]byte, error) {
	if len(ints) != n {
		return nil, fmt.Errorf("%s is %d bytes, not %d", what, len(ints), n)
	}
	b := make([]byte, n)
	for i, v := range ints {
		if v < 0 || v > 255 {
			return nil, fmt.Errorf("%s holds %d, which isn't a byte", what, v)
		}
		b[i] = byte(v)
	}
	return b, nil
}

// checkWords refuses a state proof whose account balance or a storage value
// is longer than 32 bytes: both are Ethereum uint256s, and a longer one would
// be read into a number of any size.
func checkWords(p *wireStateProof) error {
	if len(p.AccountState.Balance) > 32 {
		return fmt.Errorf("the proof's balance is %d bytes, more than a uint256's 32 bytes", len(p.AccountState.Balance))
	}
	for i, sp := range p.StorageProofs {
		if len(sp.Value) > 32 {
			return fmt.Errorf("storage proof %d's value is %d bytes, more than a uint256's 32 bytes", i, len(sp.Value))
		}
	}
	return nil
}

// checkStateAnswer refuses a state proof that isn't for address at
// blockNumber with exactly the storage slots keys, in order, or whose balance
// or a value is longer than 32 bytes.
func checkStateAnswer(p *wireStateProof, address []byte, keys [][]byte, blockNumber uint64) error {
	if err := checkWords(p); err != nil {
		return err
	}
	got, err := wireBytes(p.Address, 20, "the proof's address")
	if err != nil {
		return err
	}
	if !bytes.Equal(got, address) {
		return fmt.Errorf("the proof is for address 0x%x, not 0x%x", got, address)
	}
	if p.BlockNumber != blockNumber {
		return fmt.Errorf("the proof is for block %d, not %d", p.BlockNumber, blockNumber)
	}
	if len(p.StorageProofs) != len(keys) {
		return fmt.Errorf("the proof carries %d storage slots, not the %d asked for", len(p.StorageProofs), len(keys))
	}
	for i, sp := range p.StorageProofs {
		slot, err := wireBytes(sp.Slot, 32, fmt.Sprintf("storage proof %d's slot", i))
		if err != nil {
			return err
		}
		if !bytes.Equal(slot, keys[i]) {
			return fmt.Errorf("storage proof %d is for slot 0x%x, not 0x%x", i, slot, keys[i])
		}
	}
	return nil
}

func (e *EthOperations) post(ctx context.Context, path string, body interface{}) (*wireEnvelope, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	url := e.indexerBaseURL + path
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	rb, err := httpbody.ReadAll(resp.Body, httpbody.Large)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, string(rb))
	}
	var env wireEnvelope
	if err := json.Unmarshal(rb, &env); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &env, nil
}

// emptyTrieRoot is the root of a Merkle Patricia trie with no keys,
// keccak256(rlp("")): an account without storage has it as its storage hash.
var emptyTrieRoot = keccak256([]byte{0x80})

// emptyCodeHash is keccak256(""), the code hash of an account without code.
var emptyCodeHash = keccak256(nil)

// walkStateProof walks the account MPT proof against the proof's own state
// root, and every storage proof against the account's storage hash. Returns an
// error on the first mismatch. It checks the proof is consistent with that
// root, not that the root is Ethereum's.
//
// A key the trie doesn't hold has no leaf, so its proof shows it absent (the
// path ends at an empty branch child or diverges from the key's): that proves
// a zero storage value, or an absent account. An absent account must be
// claimed empty, with nonce and balance zero and the empty storage root and
// code hash (or zero hashes, as geth names them), and every slot asked of it
// zero. A zero value is never stored, so it must be proved absent.
//
// The address must be 20 bytes and every slot 32: a key of another length
// hashes to another path, so its absence says nothing about the address or
// slot it would be read as.
func walkStateProof(proof *wireStateProof) error {
	stateRoot := intsToBytes(proof.StateRoot)
	address, err := wireBytes(proof.Address, 20, "the proof's address")
	if err != nil {
		return err
	}
	addrHash := keccak256(address)

	nonce := proof.AccountState.Nonce
	balance := new(big.Int).SetBytes(intsToBytes(proof.AccountState.Balance))
	storageHash := intsToBytes(proof.AccountState.StorageHash)
	codeHash := intsToBytes(proof.AccountState.CodeHash)

	nodes := intsToBytesSlices(proof.AccountProof.ProofNodes)
	leaf, found, err := mptLookup(stateRoot, addrHash, nodes)
	if err != nil {
		return fmt.Errorf("account proof: %w", err)
	}
	if found {
		if !bytes.Equal(leaf, rlpEncodeAccount(nonce, balance, storageHash, codeHash)) {
			return errors.New("account proof: the account the proof holds isn't the one the answer claims")
		}
	} else {
		if nonce != 0 || balance.Sign() != 0 ||
			!(bytes.Equal(storageHash, emptyTrieRoot) || isZeroHash(storageHash)) ||
			!(bytes.Equal(codeHash, emptyCodeHash) || isZeroHash(codeHash)) {
			return errors.New("account proof: the proof shows the account absent, but the answer claims a nonce, balance, storage, or code")
		}
		// An absent account has no storage.
		storageHash = emptyTrieRoot
	}

	for i, sp := range proof.StorageProofs {
		slot, err := wireBytes(sp.Slot, 32, fmt.Sprintf("storage proof %d's slot", i))
		if err != nil {
			return err
		}
		value := new(big.Int).SetBytes(intsToBytes(sp.Value))
		nodes := intsToBytesSlices(sp.Proof.ProofNodes)
		leaf, found, err := mptLookup(storageHash, keccak256(slot), nodes)
		if err != nil {
			return fmt.Errorf("storage proof %d: %w", i, err)
		}
		switch {
		case !found && value.Sign() != 0:
			return fmt.Errorf("storage proof %d: the proof shows the slot unset (zero), but the answer claims %s", i, value)
		case found && value.Sign() == 0:
			return fmt.Errorf("storage proof %d: the proof shows the slot set, but the answer claims zero", i)
		case found && !bytes.Equal(leaf, rlpEncodeBytes(value.Bytes())):
			return fmt.Errorf("storage proof %d: leaf value mismatch", i)
		}
	}
	return nil
}

func isZeroHash(b []byte) bool {
	return len(b) == 32 && bytes.Equal(b, make([]byte, 32))
}

// MPT verifier ---------------------------------------------------------------

// verifyMptProof checks that proofNodes show keyHash holding expectedValue
// under root, or, with expectedValue nil, absent from it.
func verifyMptProof(root, keyHash, expectedValue []byte, proofNodes [][]byte) error {
	value, found, err := mptLookup(root, keyHash, proofNodes)
	switch {
	case err != nil:
		return err
	case !found && expectedValue != nil:
		return errors.New("the proof shows the key absent, not holding the value claimed")
	case found && expectedValue == nil:
		return errors.New("the proof shows the key holding a value, not absent")
	case found && !bytes.Equal(value, expectedValue):
		return errors.New("leaf value mismatch")
	}
	return nil
}

// mptLookup walks proofNodes from root along keyHash. It returns the value
// the proof shows under keyHash (found), or found false when the proof shows
// keyHash absent: its path ends at an empty branch child, or diverges from
// an extension's or a leaf's. A proof with no nodes (or only the empty node)
// shows every key absent from the empty trie, and from no other root.
func mptLookup(root, keyHash []byte, proofNodes [][]byte) (value []byte, found bool, err error) {
	if len(root) != 32 {
		return nil, false, fmt.Errorf("root must be 32 bytes, got %d", len(root))
	}
	if len(keyHash) != 32 {
		return nil, false, fmt.Errorf("key must be 32 bytes, got %d", len(keyHash))
	}
	if len(proofNodes) == 0 || (len(proofNodes) == 1 && bytes.Equal(proofNodes[0], []byte{0x80})) {
		if bytes.Equal(root, emptyTrieRoot) {
			return nil, false, nil
		}
		return nil, false, errors.New("proof is empty, and the root isn't the empty trie's")
	}
	nibs := bytesToNibbles(keyHash)
	expected := root
	idx := 0

	for i, node := range proofNodes {
		if !bytes.Equal(keccak256(node), expected) {
			return nil, false, fmt.Errorf("node %d: hash mismatch", i)
		}
		decoded, err := rlpDecodeList(node)
		if err != nil {
			return nil, false, fmt.Errorf("node %d: rlp decode: %w", i, err)
		}
		switch len(decoded) {
		case 17:
			if idx == len(nibs) {
				if len(decoded[16]) == 0 {
					return nil, false, nil
				}
				return decoded[16], true, nil
			}
			next := decoded[nibs[idx]]
			idx++
			if len(next) == 0 {
				return nil, false, nil
			}
			if len(next) != 32 {
				return nil, false, fmt.Errorf("node %d: inline-embedded child not supported (len %d)", i, len(next))
			}
			expected = next
		case 2:
			path, isLeaf := decodeCompactPath(decoded[0])
			remaining := nibs[idx:]
			if len(path) > len(remaining) || !nibblesEqual(path, remaining[:len(path)]) {
				return nil, false, nil
			}
			idx += len(path)
			if isLeaf {
				if idx != len(nibs) {
					return nil, false, nil
				}
				return decoded[1], true, nil
			}
			ref := decoded[1]
			if len(ref) != 32 {
				return nil, false, fmt.Errorf("node %d: inline-embedded extension child not supported (len %d)", i, len(ref))
			}
			expected = ref
		default:
			return nil, false, fmt.Errorf("node %d: unexpected RLP shape (len %d)", i, len(decoded))
		}
	}
	return nil, false, errors.New("proof exhausted without reaching leaf")
}

// minimal RLP -----------------------------------------------------------------
//
// We implement a tiny RLP encoder + decoder rather than pull in
// go-ethereum, which would multiply the SDK's binary surface area
// for this single use case. Spec: github.com/ethereum/devp2p (RLP).

// rlpDecodeList decodes an RLP list of byte-strings (the shape MPT
// nodes always take). Nested lists return an error — MPT proofs never
// contain them at the depths we walk.
func rlpDecodeList(data []byte) ([][]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("rlp: empty input")
	}
	first := data[0]
	if first < 0xc0 {
		return nil, errors.New("rlp: expected list")
	}
	var payloadStart, payloadLen int
	if first <= 0xf7 {
		payloadStart = 1
		payloadLen = int(first - 0xc0)
		if payloadStart+payloadLen > len(data) {
			return nil, errors.New("rlp: list payload truncated")
		}
	} else {
		lenOfLen := int(first - 0xf7)
		var err error
		if payloadLen, err = rlpLongLength(data, lenOfLen, "list"); err != nil {
			return nil, err
		}
		payloadStart = 1 + lenOfLen
	}
	payload := data[payloadStart : payloadStart+payloadLen]
	out := make([][]byte, 0, 17)
	pos := 0
	for pos < len(payload) {
		item, advance, err := rlpDecodeItem(payload[pos:])
		if err != nil {
			return nil, err
		}
		out = append(out, item)
		pos += advance
	}
	return out, nil
}

// rlpDecodeItem returns the byte-string at the start of data plus the
// number of bytes consumed. Returns an error for nested lists.
func rlpDecodeItem(data []byte) ([]byte, int, error) {
	if len(data) == 0 {
		return nil, 0, errors.New("rlp: item empty")
	}
	first := data[0]
	switch {
	case first <= 0x7f:
		return data[0:1], 1, nil
	case first <= 0xb7:
		l := int(first - 0x80)
		if 1+l > len(data) {
			return nil, 0, errors.New("rlp: item truncated")
		}
		return data[1 : 1+l], 1 + l, nil
	case first <= 0xbf:
		lenOfLen := int(first - 0xb7)
		l, err := rlpLongLength(data, lenOfLen, "item")
		if err != nil {
			return nil, 0, err
		}
		return data[1+lenOfLen : 1+lenOfLen+l], 1 + lenOfLen + l, nil
	default:
		// Nested list — not used in well-formed MPT nodes at the
		// granularity we verify. Reject explicitly.
		return nil, 0, errors.New("rlp: nested list not supported in MPT verifier")
	}
}

// rlpLongLength reads the length of a long-form RLP list or string: the
// lenOfLen (1 to 8) big-endian bytes after its first byte, data[0]. It reads
// them as a uint64 and refuses a length longer than the bytes that follow
// them, so the length fits in an int and the caller can slice
// data[1+lenOfLen:1+lenOfLen+length]. what names the list or item.
func rlpLongLength(data []byte, lenOfLen int, what string) (int, error) {
	if lenOfLen < 1 || lenOfLen > 8 {
		return 0, fmt.Errorf("rlp: %s length of %d bytes", what, lenOfLen)
	}
	if 1+lenOfLen > len(data) {
		return 0, fmt.Errorf("rlp: %s length truncated", what)
	}
	var length uint64
	for _, b := range data[1 : 1+lenOfLen] {
		length = length<<8 | uint64(b)
	}
	if length > uint64(len(data)-1-lenOfLen) {
		return 0, fmt.Errorf("rlp: %s of %d bytes truncated", what, length)
	}
	return int(length), nil
}

func rlpEncodeBytes(b []byte) []byte {
	if len(b) == 1 && b[0] < 0x80 {
		return []byte{b[0]}
	}
	if len(b) <= 55 {
		return append([]byte{0x80 + byte(len(b))}, b...)
	}
	lenBytes := uintToMinBE(uint64(len(b)))
	return append(append([]byte{0xb7 + byte(len(lenBytes))}, lenBytes...), b...)
}

func rlpEncodeList(items [][]byte) []byte {
	var payload []byte
	for _, it := range items {
		payload = append(payload, it...)
	}
	if len(payload) <= 55 {
		return append([]byte{0xc0 + byte(len(payload))}, payload...)
	}
	lenBytes := uintToMinBE(uint64(len(payload)))
	return append(append([]byte{0xf7 + byte(len(lenBytes))}, lenBytes...), payload...)
}

func rlpEncodeAccount(nonce uint64, balance *big.Int, storageHash, codeHash []byte) []byte {
	return rlpEncodeList([][]byte{
		rlpEncodeBytes(uintToMinBE(nonce)),
		rlpEncodeBytes(trimLeadingZeros(balance.Bytes())),
		rlpEncodeBytes(storageHash),
		rlpEncodeBytes(codeHash),
	})
}

// helpers ---------------------------------------------------------------------

func keccak256(b []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(b)
	return h.Sum(nil)
}

func bytesToNibbles(b []byte) []int {
	out := make([]int, len(b)*2)
	for i, by := range b {
		out[2*i] = int(by>>4) & 0x0f
		out[2*i+1] = int(by) & 0x0f
	}
	return out
}

func decodeCompactPath(encoded []byte) ([]int, bool) {
	if len(encoded) == 0 {
		return nil, false
	}
	first := encoded[0]
	flag := (first >> 4) & 0x0f
	isLeaf := flag >= 2
	odd := (flag & 1) == 1
	var nibs []int
	if odd {
		nibs = append(nibs, int(first&0x0f))
	}
	for _, b := range encoded[1:] {
		nibs = append(nibs, int(b>>4)&0x0f, int(b)&0x0f)
	}
	return nibs, isLeaf
}

func nibblesEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func intsToBytes(ints []int) []byte {
	b := make([]byte, len(ints))
	for i, n := range ints {
		b[i] = byte(n)
	}
	return b
}

func intsToBytesSlices(s [][]int) [][]byte {
	out := make([][]byte, len(s))
	for i, ints := range s {
		out[i] = intsToBytes(ints)
	}
	return out
}

func bytesIntsToHex(ints []int, width int) string {
	b := intsToBytes(ints)
	if len(b) < width {
		pad := make([]byte, width-len(b))
		b = append(pad, b...)
	}
	return "0x" + hex.EncodeToString(b)
}

func trimLeadingZeros(b []byte) []byte {
	i := 0
	for i < len(b) && b[i] == 0 {
		i++
	}
	return b[i:]
}

func uintToMinBE(n uint64) []byte {
	if n == 0 {
		return nil
	}
	var b [8]byte
	binaryPutUint64BE(b[:], n)
	return trimLeadingZeros(b[:])
}

func binaryPutUint64BE(buf []byte, n uint64) {
	buf[0] = byte(n >> 56)
	buf[1] = byte(n >> 48)
	buf[2] = byte(n >> 40)
	buf[3] = byte(n >> 32)
	buf[4] = byte(n >> 24)
	buf[5] = byte(n >> 16)
	buf[6] = byte(n >> 8)
	buf[7] = byte(n)
}

func mappingSlotForAddress(addr []byte, slotIndex byte) []byte {
	buf := make([]byte, 64)
	copy(buf[12:32], addr)
	buf[63] = slotIndex
	return keccak256(buf)
}

func hexDecode20(s string) ([]byte, error) {
	s = strings.TrimPrefix(strings.ToLower(s), "0x")
	if len(s) != 40 {
		return nil, fmt.Errorf("expected 20-byte hex, got %d chars", len(s))
	}
	return hex.DecodeString(s)
}

func toEthStateRead(p *wireStateProof, mode EthProofMode) *EthStateRead {
	storage := make([]EthStorageSlot, len(p.StorageProofs))
	for i, sp := range p.StorageProofs {
		storage[i] = EthStorageSlot{
			Slot:  bytesIntsToHex(sp.Slot, 32),
			Value: new(big.Int).SetBytes(intsToBytes(sp.Value)),
		}
	}
	return &EthStateRead{
		Address:     bytesIntsToHex(p.Address, 20),
		BlockNumber: p.BlockNumber,
		BlockHash:   bytesIntsToHex(p.BlockHash, 32),
		StateRoot:   bytesIntsToHex(p.StateRoot, 32),
		Nonce:       p.AccountState.Nonce,
		Balance:     new(big.Int).SetBytes(intsToBytes(p.AccountState.Balance)),
		StorageHash: bytesIntsToHex(p.AccountState.StorageHash, 32),
		CodeHash:    bytesIntsToHex(p.AccountState.CodeHash, 32),
		Storage:     storage,
		Mode:        mode,
	}
}

func base64Decode(s string) ([]byte, error) {
	// Server uses STANDARD_NO_PAD base64 (per crate::serde_helpers::bytes_base64).
	// stdlib StdEncoding requires padding; use RawStdEncoding for unpadded.
	return base64StdNoPadDecode(s)
}

// Tiny base64 wrapper that handles both padded and unpadded variants —
// stdlib's RawStdEncoding works for unpadded, StdEncoding for padded.
func base64StdNoPadDecode(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	// Try unpadded first (server default), then padded.
	if dec, err := base64RawStd().DecodeString(s); err == nil {
		return dec, nil
	}
	return base64Std().DecodeString(s)
}
