package willow

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Transaction nonces.
//
// The chain accepts a transaction under a nonce in base+1 … base+24 that it
// hasn't used, where base, the account nonce, advances only over used nonces
// with no gap below them. Signing base+1 for every write gives two writes in
// flight the same nonce, and a nonce taken and never used (its transaction
// refused at CheckTx or dropped from the mempool) blocks the window until
// something uses it. So a Client keeps, per signing DID, the nonces it has
// handed out that haven't landed, each with when it was handed out, and the
// nonces it has seen used above the base, and hands out the lowest nonce in
// the window that is neither.

const (
	// NonceWindow is how many nonces above the account nonce the chain
	// accepts.
	NonceWindow = 24
	// NonceHold is how long a nonce handed out and not seen to land stays
	// taken. The node holds a pending transaction's nonce for 3 blocks or
	// 120 s, whichever ends first, so 120 s is the conservative bound.
	NonceHold = 120 * time.Second
)

// ErrNonceWindowFull is the cause of the error a write returns when every
// nonce the chain accepts for its DID is used or held by a write in flight
// (errors.Is(err, ErrNonceWindowFull)). Wait for earlier writes to land (see
// Client.WaitUntilLanded) and send it again.
var ErrNonceWindowFull = errors.New("nonce window full")

// AccountNonceState is an account's nonce state as the chain reports it.
type AccountNonceState struct {
	// Base is the account nonce: every nonce at or below it is used.
	Base uint64
	// Used has bit i set when nonce Base+1+i is used (24 bits). Only the
	// ABCI query /store/account_nonce_state/{did} reports it; read from the
	// API's /account/{did}/nonce it is 0.
	Used uint32
}

// IsUsed reports whether the state shows nonce used.
func (s AccountNonceState) IsUsed(nonce uint64) bool {
	if nonce <= s.Base {
		return true
	}
	offset := nonce - s.Base - 1
	return offset < NonceWindow && s.Used&(1<<offset) != 0
}

// ParseAccountNonceState reads the value of the ABCI query
// /store/account_nonce_state/{did}: the base as a big-endian u64, then 3
// bytes in which bit i%8 of byte i/8 marks Base+1+i used. 8 bytes is the base
// alone, and none an account with no transactions.
func ParseAccountNonceState(value []byte) (AccountNonceState, error) {
	switch len(value) {
	case 0:
		return AccountNonceState{}, nil
	case 8, 11:
	default:
		return AccountNonceState{}, NewSerializationError(fmt.Sprintf("an account nonce state is 11 bytes, not %d", len(value)), nil)
	}
	state := AccountNonceState{Base: binary.BigEndian.Uint64(value[:8])}
	if len(value) == 11 {
		state.Used = uint32(value[8]) | uint32(value[9])<<8 | uint32(value[10])<<16
	}
	return state, nil
}

// WriteResult is a write the chain's CheckTx accepted: the DID that signed
// it, the nonce it was signed under, and its transaction hash. It is applied,
// or refused, in its block; Client.WaitUntilLanded waits for that.
type WriteResult struct {
	DID    string
	Nonce  uint64
	TxHash string
}

// WriteError is a write that failed after it was signed under Nonce.
//
// When MayLand is true its submission failed in transit (a network error or
// a 5xx answer), so it may have reached the node and may still land. Before
// sending it again, wait for the nonce with Client.WaitUntilLanded and read
// what it wrote: a write sent again under a fresh nonce while the first is
// valid can run twice. Otherwise the write was refused before it reached the
// mempool and will not run.
type WriteError struct {
	DID     string
	Nonce   uint64
	MayLand bool
	Err     error
}

// Error implements the error interface.
func (e *WriteError) Error() string {
	return fmt.Sprintf("write signed by %s under nonce %d: %v", e.DID, e.Nonce, e.Err)
}

// Unwrap returns the submission's error.
func (e *WriteError) Unwrap() error {
	return e.Err
}

// nonceOutcome is what a submission leaves the nonce it was signed under as.
type nonceOutcome int

const (
	// nonceAccepted: CheckTx accepted it; taken until it lands or its hold lapses.
	nonceAccepted nonceOutcome = iota
	// nonceFree: never reached CheckTx, or refused without the nonce being
	// held or used; given back.
	nonceFree
	// nonceHeld: refused because another pending transaction holds the
	// nonce; taken until its hold lapses.
	nonceHeld
	// nonceUsed: refused because the chain has used or spent the nonce.
	nonceUsed
	// nonceUnknown: may have reached the node; taken until its hold lapses.
	nonceUnknown
)

// refusalOutcome is what a CheckTx refusal whose log is log leaves did's
// nonce as. It matches the node's own texts for that nonce (not another
// number in the log): "Nonce N of DID is held by a pending transaction",
// "Invalid nonce: N already used", "Invalid nonce: N <= base nonce", and a
// block refusal's "(nonce N spent)". Any other refusal gives the nonce back.
func refusalOutcome(log, did string, nonce uint64) nonceOutcome {
	n := strconv.FormatUint(nonce, 10)
	switch {
	case strings.Contains(log, "Nonce "+n+" of "+did+" is held by a pending transaction"):
		return nonceHeld
	case strings.Contains(log, "Invalid nonce: "+n+" already used"),
		strings.Contains(log, "Invalid nonce: "+n+" <= base nonce "),
		strings.Contains(log, "(nonce "+n+" spent)"):
		return nonceUsed
	}
	return nonceFree
}

// nonceAccount is one DID's nonces as a Client knows them.
type nonceAccount struct {
	// base is the highest base the chain has reported.
	base uint64
	// used holds nonces above base seen used: in the chain's bitmap, or named
	// by a refusal.
	used map[uint64]bool
	// handed holds each nonce handed out and not seen used, with when its
	// hold began.
	handed map[uint64]time.Time
}

// nonceAllocator hands out transaction nonces so that no two writes in flight
// from one DID share one. It is safe for concurrent use.
type nonceAllocator struct {
	mu       sync.Mutex
	now      func() time.Time
	accounts map[string]*nonceAccount
}

func newNonceAllocator(now func() time.Time) *nonceAllocator {
	return &nonceAllocator{now: now, accounts: map[string]*nonceAccount{}}
}

// account returns did's account; the caller holds mu.
func (a *nonceAllocator) account(did string) *nonceAccount {
	acct := a.accounts[did]
	if acct == nil {
		acct = &nonceAccount{used: map[uint64]bool{}, handed: map[uint64]time.Time{}}
		a.accounts[did] = acct
	}
	return acct
}

// merge folds a state the chain reported into acct (a slower, older answer
// can't lower the base or clear a nonce seen used), then drops what the base
// passed and the holds that lapsed. The caller holds mu.
func (a *nonceAllocator) merge(acct *nonceAccount, state AccountNonceState, now time.Time) {
	if state.Base > acct.base {
		acct.base = state.Base
	}
	for i := uint64(0); i < NonceWindow; i++ {
		if state.Used&(1<<i) != 0 && state.Base+1+i > acct.base {
			acct.used[state.Base+1+i] = true
		}
	}
	for n := range acct.used {
		if n <= acct.base {
			delete(acct.used, n)
		}
	}
	for n, at := range acct.handed {
		if n <= acct.base || acct.used[n] || now.Sub(at) >= NonceHold {
			delete(acct.handed, n)
		}
	}
}

// view is acct as an AccountNonceState. The caller holds mu.
func (acct *nonceAccount) view() AccountNonceState {
	state := AccountNonceState{Base: acct.base}
	for n := range acct.used {
		if offset := n - acct.base - 1; offset < NonceWindow {
			state.Used |= 1 << offset
		}
	}
	return state
}

// observe records a state the chain reported for did and returns everything
// known of it.
func (a *nonceAllocator) observe(did string, state AccountNonceState) AccountNonceState {
	a.mu.Lock()
	defer a.mu.Unlock()
	acct := a.account(did)
	a.merge(acct, state, a.now())
	return acct.view()
}

// take hands out the lowest nonce in did's window that isn't used, seen
// used, or handed out within NonceHold, given the state the chain just
// reported.
func (a *nonceAllocator) take(did string, state AccountNonceState) (uint64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	acct := a.account(did)
	a.merge(acct, state, now)
	// The chain refuses a nonce at or above MaxUint64-NonceWindow.
	if acct.base >= math.MaxUint64-NonceWindow-1 {
		return 0, &WillowError{
			Type:    ErrorTypeTransaction,
			Message: fmt.Sprintf("the account nonce of %s is %d, which leaves no nonce the chain accepts", did, acct.base),
			Cause:   ErrNonceWindowFull,
		}
	}
	for i := uint64(1); i <= NonceWindow; i++ {
		n := acct.base + i
		if n >= math.MaxUint64-NonceWindow {
			break
		}
		if _, handed := acct.handed[n]; !handed && !acct.used[n] {
			acct.handed[n] = now
			return n, nil
		}
	}
	return 0, &WillowError{
		Type: ErrorTypeTransaction,
		Message: fmt.Sprintf("every nonce the chain accepts for %s (%d to %d) is used or held by a write in flight; "+
			"send more once earlier writes land (see WaitUntilLanded)", did, acct.base+1, acct.base+NonceWindow),
		Cause: ErrNonceWindowFull,
	}
}

// settle records what a submission signed by did under nonce left the nonce
// as. Accepted, unknown, and held nonces are taken for NonceHold from now, as
// the node's hold runs from admission.
func (a *nonceAllocator) settle(did string, nonce uint64, outcome nonceOutcome) {
	a.mu.Lock()
	defer a.mu.Unlock()
	acct := a.account(did)
	switch outcome {
	case nonceAccepted, nonceUnknown, nonceHeld:
		if nonce > acct.base && !acct.used[nonce] {
			acct.handed[nonce] = a.now()
		}
	case nonceFree:
		delete(acct.handed, nonce)
	case nonceUsed:
		delete(acct.handed, nonce)
		if nonce > acct.base {
			acct.used[nonce] = true
		}
	}
}

// GetAccountNonce reads did's nonce state. With an RPC URL set (WithRPCURL)
// it is the base and which of the 24 nonces above it are used, from the ABCI
// query /store/account_nonce_state/{did}; otherwise, or if that query fails,
// the base alone, from the API's /account/{did}/nonce.
func (c *Client) GetAccountNonce(ctx context.Context, did string) (*AccountNonceState, error) {
	if c.rpcURL != nil {
		if state, err := c.queryAccountNonceState(ctx, did); err == nil {
			return state, nil
		}
	}
	var account *struct {
		Nonce *uint64 `json:"nonce"`
	}
	if err := c.getData(ctx, fmt.Sprintf("/account/%s/nonce", did), &account); err != nil {
		return nil, err
	}
	if account == nil || account.Nonce == nil {
		return nil, NewSerializationError("the API answered no nonce for "+did, nil)
	}
	return &AccountNonceState{Base: *account.Nonce}, nil
}

// queryAccountNonceState reads did's nonce state by the ABCI query
// /store/account_nonce_state/{did} on the RPC endpoint.
func (c *Client) queryAccountNonceState(ctx context.Context, did string) (*AccountNonceState, error) {
	body, err := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "abci_query",
		"params": map[string]interface{}{
			"path":   "/store/account_nonce_state/" + did,
			"data":   "",
			"height": "0",
			"prove":  false,
		},
	})
	if err != nil {
		return nil, NewSerializationError("failed to marshal abci_query request", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.RPCEndpoint(), bytes.NewReader(body))
	if err != nil {
		return nil, NewNetworkError("failed to create abci_query request", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, NewNetworkError("abci_query request failed", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, NewHTTPError(resp.StatusCode, "abci_query request failed")
	}
	var answer struct {
		Result *struct {
			Response struct {
				Code  int    `json:"code"`
				Log   string `json:"log"`
				Value string `json:"value"`
			} `json:"response"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&answer); err != nil {
		return nil, NewSerializationError("failed to decode abci_query response", err)
	}
	if answer.Error != nil {
		return nil, NewConsensusError("abci_query RPC error: "+answer.Error.Message, nil)
	}
	if answer.Result == nil {
		return nil, NewConsensusError("abci_query answered no result", nil)
	}
	if answer.Result.Response.Code != 0 {
		return nil, NewConsensusError("failed to read the account nonce state: "+answer.Result.Response.Log, nil)
	}
	value, err := decodeBase64(answer.Result.Response.Value)
	if err != nil {
		return nil, NewSerializationError("failed to base64-decode abci_query value", err)
	}
	state, err := ParseAccountNonceState(value)
	if err != nil {
		return nil, err
	}
	return &state, nil
}

// NextNonce hands out a nonce for a transaction signed by did: the lowest in
// the account's window that the chain doesn't show used and that this client
// hasn't handed out within NonceHold. The client's write methods take theirs
// here; take one here for a transaction the client doesn't choose the nonce
// of (a file write's FileSigningOptions.Nonce), so that no other write from
// this client takes it while it is in flight. A nonce handed out and never
// sent is free again after NonceHold.
//
// It returns an error wrapping ErrNonceWindowFull when every nonce in the
// window is used or held: wait for earlier writes to land.
func (c *Client) NextNonce(ctx context.Context, did string) (uint64, error) {
	state, err := c.GetAccountNonce(ctx, did)
	if err != nil {
		return 0, fmt.Errorf("failed to read the account nonce: %w", err)
	}
	return c.nonces.take(did, *state)
}

// WaitUntilLanded waits until the chain shows did's nonce used, polling its
// nonce state (see GetAccountNonce) until then or until ctx is done.
//
// A write returns once CheckTx accepts it; send a write that depends on it
// (an update of a key being stored, a store into a subgrove being
// registered) only after it lands, since writes in flight may land in any
// order. A write refused in its block also uses its nonce (every kind the
// SDK sends except DeregisterSubgrove, whose refusal leaves it unused): read
// what it wrote, or look its TxHash up (consensus.Client.GetTx), to know it
// took effect. Without an RPC URL only the base is known, and the base advances
// only over used nonces with no gap below them, so this also waits for every
// earlier nonce of did.
func (c *Client) WaitUntilLanded(ctx context.Context, did string, nonce uint64) error {
	notLanded := func(base uint64) error {
		return &WillowError{
			Type:    ErrorTypeTransaction,
			Message: fmt.Sprintf("nonce %d of %s has not landed: the account nonce is %d", nonce, did, base),
			Cause:   ctx.Err(),
		}
	}
	var base uint64
	for {
		state, err := c.GetAccountNonce(ctx, did)
		if err != nil {
			if ctx.Err() != nil {
				return notLanded(base)
			}
			return fmt.Errorf("failed to read the account nonce: %w", err)
		}
		known := c.nonces.observe(did, *state)
		if known.IsUsed(nonce) {
			return nil
		}
		base = known.Base
		select {
		case <-ctx.Done():
			return notLanded(base)
		case <-time.After(c.noncePollInterval):
		}
	}
}

// signedWrite hands out a nonce for did, builds the transaction under it with
// build, and submits it to POST /tx/submit once, recording the outcome for
// the nonce. A refusal that says the nonce is already used or spent means no
// transaction under it can run, so the write is built again under the next
// free nonce; any other failure after the transaction was built returns a
// *WriteError naming its nonce.
func (c *Client) signedWrite(ctx context.Context, did string, build func(nonce uint64) (interface{}, error)) (*WriteResult, error) {
	var refused error
	for attempt := 0; attempt < NonceWindow; attempt++ {
		nonce, err := c.NextNonce(ctx, did)
		if err != nil {
			return nil, err
		}
		tx, err := build(nonce)
		if err != nil {
			c.nonces.settle(did, nonce, nonceFree)
			return nil, err
		}
		body, err := json.Marshal(tx)
		if err != nil {
			c.nonces.settle(did, nonce, nonceFree)
			return nil, NewSerializationError("failed to marshal transaction", err)
		}
		hash, outcome, err := c.postTx(ctx, body, did, nonce)
		c.nonces.settle(did, nonce, outcome)
		if err == nil {
			return &WriteResult{DID: did, Nonce: nonce, TxHash: hash}, nil
		}
		refused = &WriteError{DID: did, Nonce: nonce, MayLand: outcome == nonceUnknown, Err: err}
		if outcome != nonceUsed {
			return nil, refused
		}
	}
	return nil, refused
}

// submitSigned submits a transaction did signed under nonce, a nonce the
// caller chose, and records the outcome, so that this client's own writes
// skip the nonce while it is in flight. An unsigned transaction (did empty)
// records nothing.
func (c *Client) submitSigned(ctx context.Context, did string, nonce uint64, body []byte) error {
	_, outcome, err := c.postTx(ctx, body, did, nonce)
	if did != "" {
		c.nonces.settle(did, nonce, outcome)
	}
	return err
}
