// Package willow — verifiable Ethereum state reads.
//
// Counterpart to the indexer's POST /verifiable-rpc/eth/state and
// /verifiable-rpc/eth/call routes. Walks EIP-1186 MPT proofs locally
// and exposes ergonomic storage-layout helpers (ERC-20 balance,
// allowance, ERC-721 owner, Uniswap V2 reserves).
//
// Three trust modes follow the Rust/TS/Python SDK conventions:
//   - StateVerifyModeStrict     (default): verify every MPT proof.
//   - StateVerifyModeAnchorOnly         : skip walks, trust the root.
//   - StateVerifyModeDisabled           : passthrough.
package willow

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"

	"golang.org/x/crypto/sha3"
)

type StateVerifyMode int

const (
	StateVerifyModeStrict StateVerifyMode = iota
	StateVerifyModeAnchorOnly
	StateVerifyModeDisabled
)

// wire types -----------------------------------------------------------------

type wireAccountState struct {
	Nonce       uint64  `json:"nonce"`
	Balance     []int   `json:"balance"`
	StorageHash []int   `json:"storage_hash"`
	CodeHash    []int   `json:"code_hash"`
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

type VerifiedStorage struct {
	Slot  string
	Value *big.Int
}

type VerifiedStateRead struct {
	Address     string
	BlockNumber uint64
	BlockHash   string
	StateRoot   string
	Nonce       uint64
	Balance     *big.Int
	StorageHash string
	CodeHash    string
	Storage     []VerifiedStorage
	Mode        StateVerifyMode
}

type VerifiedCall struct {
	BlockNumber      uint64
	BlockHash        string
	StateRoot        string
	Result           []byte
	AccessStateReads []VerifiedStateRead
	Mode             StateVerifyMode
}

// EthOperations is the SDK entry point for verifiable Ethereum state reads.
type EthOperations struct {
	indexerBaseURL string
	http           *http.Client
	Mode           StateVerifyMode
}

func NewEthOperations(indexerBaseURL string, httpClient *http.Client) *EthOperations {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &EthOperations{
		indexerBaseURL: strings.TrimRight(indexerBaseURL, "/"),
		http:           httpClient,
		Mode:           StateVerifyModeStrict,
	}
}

// GetState fetches verified account state (+ optional storage slots) at blockNumber.
func (e *EthOperations) GetState(
	ctx context.Context,
	address string,
	slots []string,
	blockNumber uint64,
) (*VerifiedStateRead, error) {
	body := map[string]interface{}{
		"address": address,
		"slots":   slots,
		"block":   blockNumber,
	}
	envelope, err := e.post(ctx, "/verifiable-rpc/eth/state", body)
	if err != nil {
		return nil, err
	}
	if len(envelope.StateProofs) == 0 {
		return nil, errors.New("response carried no state proof")
	}
	proof := &envelope.StateProofs[0]
	if e.Mode == StateVerifyModeStrict {
		if err := VerifyStateProof(proof); err != nil {
			return nil, err
		}
	}
	return toVerifiedStateRead(proof, e.Mode), nil
}

// GetCall executes tx via the indexer's verified REVM and returns the
// ABI-encoded result plus state proofs for every touched account.
func (e *EthOperations) GetCall(
	ctx context.Context,
	tx map[string]interface{},
	blockNumber uint64,
) (*VerifiedCall, error) {
	body := map[string]interface{}{"tx": tx, "block": blockNumber}
	envelope, err := e.post(ctx, "/verifiable-rpc/eth/call", body)
	if err != nil {
		return nil, err
	}
	if e.Mode == StateVerifyModeStrict {
		for i := range envelope.StateProofs {
			if err := VerifyStateProof(&envelope.StateProofs[i]); err != nil {
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
	reads := make([]VerifiedStateRead, len(envelope.StateProofs))
	for i := range envelope.StateProofs {
		reads[i] = *toVerifiedStateRead(&envelope.StateProofs[i], e.Mode)
	}
	return &VerifiedCall{
		BlockNumber:      envelope.BlockRange[0],
		BlockHash:        blockHash,
		StateRoot:        bytesIntsToHex(envelope.StateRoot, 32),
		Result:           result,
		AccessStateReads: reads,
		Mode:             e.Mode,
	}, nil
}

// Erc20Balance returns balanceOf(holder) for a token whose balance
// mapping lives at slot balanceSlot.
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
	if len(state.Storage) == 0 {
		return nil, errors.New("erc20Balance: empty storage proofs")
	}
	return state.Storage[0].Value, nil
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
	rb, err := io.ReadAll(resp.Body)
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

// VerifyStateProof walks the account MPT proof and every storage proof.
// Returns an error on the first mismatch.
func VerifyStateProof(proof *wireStateProof) error {
	stateRoot := intsToBytes(proof.StateRoot)
	address := intsToBytes(proof.Address)
	addrHash := keccak256(address)

	nonce := proof.AccountState.Nonce
	balance := new(big.Int).SetBytes(intsToBytes(proof.AccountState.Balance))
	storageHash := intsToBytes(proof.AccountState.StorageHash)
	codeHash := intsToBytes(proof.AccountState.CodeHash)
	accountLeaf := rlpEncodeAccount(nonce, balance, storageHash, codeHash)

	nodes := intsToBytesSlices(proof.AccountProof.ProofNodes)
	if err := verifyMptProof(stateRoot, addrHash, accountLeaf, nodes); err != nil {
		return fmt.Errorf("account proof: %w", err)
	}

	for i, sp := range proof.StorageProofs {
		slot := intsToBytes(sp.Slot)
		value := new(big.Int).SetBytes(intsToBytes(sp.Value))
		var valueRlp []byte
		if value.Sign() == 0 {
			valueRlp = rlpEncodeBytes(nil)
		} else {
			valueRlp = rlpEncodeBytes(trimLeadingZeros(value.Bytes()))
		}
		nodes := intsToBytesSlices(sp.Proof.ProofNodes)
		if err := verifyMptProof(storageHash, keccak256(slot), valueRlp, nodes); err != nil {
			return fmt.Errorf("storage proof %d: %w", i, err)
		}
	}
	return nil
}

// MPT verifier ---------------------------------------------------------------

func verifyMptProof(root, keyHash, expectedValue []byte, proofNodes [][]byte) error {
	if len(root) != 32 {
		return fmt.Errorf("root must be 32 bytes, got %d", len(root))
	}
	if len(keyHash) != 32 {
		return fmt.Errorf("key must be 32 bytes, got %d", len(keyHash))
	}
	if len(proofNodes) == 0 {
		return errors.New("proof is empty")
	}
	nibs := bytesToNibbles(keyHash)
	expected := root
	idx := 0

	for i, node := range proofNodes {
		if !bytes.Equal(keccak256(node), expected) {
			return fmt.Errorf("node %d: hash mismatch", i)
		}
		decoded, err := rlpDecodeList(node)
		if err != nil {
			return fmt.Errorf("node %d: rlp decode: %w", i, err)
		}
		switch len(decoded) {
		case 17:
			if idx == len(nibs) {
				return checkValue(decoded[16], expectedValue)
			}
			next := decoded[nibs[idx]]
			idx++
			if len(next) == 0 {
				return checkValue(nil, expectedValue)
			}
			if len(next) != 32 {
				return fmt.Errorf("node %d: inline-embedded child not supported (len %d)", i, len(next))
			}
			expected = next
		case 2:
			path, isLeaf := decodeCompactPath(decoded[0])
			remaining := nibs[idx:]
			if len(path) > len(remaining) || !nibblesEqual(path, remaining[:len(path)]) {
				return checkValue(nil, expectedValue)
			}
			idx += len(path)
			if isLeaf {
				if idx != len(nibs) {
					return checkValue(nil, expectedValue)
				}
				return checkValue(decoded[1], expectedValue)
			}
			ref := decoded[1]
			if len(ref) != 32 {
				return fmt.Errorf("node %d: inline-embedded extension child not supported (len %d)", i, len(ref))
			}
			expected = ref
		default:
			return fmt.Errorf("node %d: unexpected RLP shape (len %d)", i, len(decoded))
		}
	}
	return errors.New("proof exhausted without reaching leaf")
}

func checkValue(actual, expected []byte) error {
	if bytes.Equal(actual, expected) {
		return nil
	}
	return fmt.Errorf("leaf value mismatch")
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
	} else {
		lenOfLen := int(first - 0xf7)
		if 1+lenOfLen > len(data) {
			return nil, errors.New("rlp: list length overflow")
		}
		payloadStart = 1 + lenOfLen
		payloadLen = 0
		for _, b := range data[1 : 1+lenOfLen] {
			payloadLen = (payloadLen << 8) | int(b)
		}
	}
	if payloadStart+payloadLen > len(data) {
		return nil, errors.New("rlp: list payload truncated")
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
		if 1+lenOfLen > len(data) {
			return nil, 0, errors.New("rlp: item length overflow")
		}
		l := 0
		for _, b := range data[1 : 1+lenOfLen] {
			l = (l << 8) | int(b)
		}
		if 1+lenOfLen+l > len(data) {
			return nil, 0, errors.New("rlp: long item truncated")
		}
		return data[1+lenOfLen : 1+lenOfLen+l], 1 + lenOfLen + l, nil
	default:
		// Nested list — not used in well-formed MPT nodes at the
		// granularity we verify. Reject explicitly.
		return nil, 0, errors.New("rlp: nested list not supported in MPT verifier")
	}
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

func toVerifiedStateRead(p *wireStateProof, mode StateVerifyMode) *VerifiedStateRead {
	storage := make([]VerifiedStorage, len(p.StorageProofs))
	for i, sp := range p.StorageProofs {
		storage[i] = VerifiedStorage{
			Slot:  bytesIntsToHex(sp.Slot, 32),
			Value: new(big.Int).SetBytes(intsToBytes(sp.Value)),
		}
	}
	return &VerifiedStateRead{
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
