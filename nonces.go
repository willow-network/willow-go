package willow

import (
	"bytes"
	"context"
	"crypto/sha256"
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

	"github.com/willow-network/willow-go/internal/httpbody"
)

// Transaction nonces.
//
// The chain accepts a transaction under a nonce in base+1 … base+24 that it
// hasn't used, where base, the account nonce, advances only over used nonces
// with no gap below them. Signing base+1 for every write gives two writes in
// flight the same nonce, and a nonce taken and never used (its transaction
// refused at CheckTx or dropped from the mempool) blocks the window until
// something uses it. So a Client keeps, per signing DID, the nonces it has
// handed out that haven't landed (each held while a submission under it is in
// flight, and for NonceHold after it was handed out or a submission under it
// was accepted or may have reached the node) and the nonces it has seen used
// above the base, and hands out the lowest nonce in the window that is
// neither.

const (
	// NonceWindow is how many nonces above the account nonce the chain
	// accepts.
	NonceWindow = 24
	// NonceHold is how long a nonce handed out and not seen to land stays
	// taken once no submission under it is in flight. The node holds a
	// pending transaction's nonce for 3 blocks or 120 s, whichever ends
	// first, so 120 s is the conservative bound.
	NonceHold = 120 * time.Second
)

// ErrNonceWindowFull is the cause of the error a write returns when every
// nonce the chain accepts for its DID is used or held by a write in flight
// (errors.Is(err, ErrNonceWindowFull)). Wait for earlier writes to land (see
// Client.WaitUntilLanded) and send it again.
var ErrNonceWindowFull = errors.New("nonce window full")

// ErrNonceUsed is the cause of a *WriteError for a write that wasn't sent, or
// wasn't signed again, because its nonce is used and the transaction that used
// it may be an earlier attempt of the same write (errors.Is(err,
// ErrNonceUsed)). If it is, that attempt landed and was applied or refused in
// its block: read what the write wrote before sending it again, without
// WithNonce, under a fresh nonce.
var ErrNonceUsed = errors.New("nonce already used")

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
// a 5xx answer), so it may have reached the node and may still land. To send
// it again, sign it under the same nonce (WithNonce(Nonce)): whichever
// attempt lands first uses the nonce and the other is refused, so the write
// runs at most once. Or wait for the nonce with Client.WaitUntilLanded and
// read what it wrote: a write sent again under a fresh nonce while the first
// is valid can run twice. Otherwise the write was refused before it reached
// the mempool and will not run (unless an earlier attempt under the same nonce
// does: see ErrNonceUsed).
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
// nonce as. It reads only the node's own nonce errors for this transaction's
// nonce (and DID), as the whole log or after one of the node's fixed prefixes
// ("Signature validation failed: ", "Nonce validation failed: "): "Nonce N of
// DID is held by a pending transaction; …", "Invalid nonce: N already used
// (replay)", and "Invalid nonce: N <= base nonce B". A log that only quotes
// such text (a signature mismatch quotes the expected message, which carries
// the caller's subgrove, key, and DIDs) says nothing about the nonce. Any other
// refusal gives the nonce back. (A refusal in a block, whose log ends "(nonce
// N spent)", never reaches /tx/submit's answer, which is CheckTx's.)
func refusalOutcome(log, did string, nonce uint64) nonceOutcome {
	for _, prefix := range []string{"Signature validation failed: ", "Nonce validation failed: "} {
		if rest, ok := strings.CutPrefix(log, prefix); ok {
			log = rest
			break
		}
	}
	n := strconv.FormatUint(nonce, 10)
	held := "Nonce " + n + " of " + did + " is held by a pending transaction"
	used := "Invalid nonce: " + n + " already used"
	if log == held || strings.HasPrefix(log, held+";") {
		return nonceHeld
	}
	if log == used || strings.HasPrefix(log, used+" (") {
		return nonceUsed
	}
	if base, ok := strings.CutPrefix(log, "Invalid nonce: "+n+" <= base nonce "); ok {
		if _, err := strconv.ParseUint(base, 10, 64); err == nil {
			return nonceUsed
		}
	}
	return nonceFree
}

// nonceClaim is what holds one nonce a Client handed out. The nonce is taken
// while any submission under it is in flight, however long that takes, and
// for NonceHold after NextNonce reserved it or a submission under it was
// accepted, refused as held, or failed in transit.
type nonceClaim struct {
	// inFlight counts the submissions under the nonce that haven't returned.
	// Each removes only its own count when it settles.
	inFlight int
	// reserved is when NextNonce handed the nonce out; a submission under it
	// replaces the reservation.
	reserved time.Time
	// held is when a submission under the nonce last left it held.
	held time.Time
}

// live reports whether the claim still holds its nonce at now.
func (c *nonceClaim) live(now time.Time) bool {
	within := func(at time.Time) bool { return !at.IsZero() && now.Sub(at) < NonceHold }
	return c.inFlight > 0 || within(c.reserved) || within(c.held)
}

// nonceAccount is one DID's nonces as a Client knows them.
type nonceAccount struct {
	// base is the highest base the chain has reported.
	base uint64
	// used holds nonces above base seen used: in the chain's bitmap, or named
	// by a refusal.
	used map[uint64]bool
	// claims holds each nonce handed out, and not seen used, that something
	// still holds.
	claims map[uint64]*nonceClaim
	// sent holds, for each nonce above base not seen used, the writes (by
	// writeDigest) submitted from this client under it that were accepted or
	// may have reached the node. A later refusal of the nonce as used may be
	// one of them landing.
	sent map[uint64]map[[32]byte]bool
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
		acct = &nonceAccount{used: map[uint64]bool{}, claims: map[uint64]*nonceClaim{}, sent: map[uint64]map[[32]byte]bool{}}
		a.accounts[did] = acct
	}
	return acct
}

// merge folds a state the chain reported into acct (a slower, older answer
// can't lower the base or clear a nonce seen used), then drops what the base
// passed or the chain shows used, and the claims that lapsed. A claim with a
// submission in flight doesn't lapse. The caller holds mu.
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
	for n := range acct.sent {
		if n <= acct.base || acct.used[n] {
			delete(acct.sent, n)
		}
	}
	for n, claim := range acct.claims {
		if n <= acct.base || acct.used[n] || !claim.live(now) {
			delete(acct.claims, n)
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

// take hands out, for a submission starting now, the lowest nonce in did's
// window that isn't used, seen used, or held, given the state the chain just
// reported. The nonce stays taken until the submission settles.
func (a *nonceAllocator) take(did string, state AccountNonceState) (uint64, error) {
	return a.pick(did, state, func(c *nonceClaim, _ time.Time) { c.inFlight = 1 })
}

// reserve hands out a nonce as take does, for a transaction the caller builds
// and sends itself: it stays taken for NonceHold, and while a submission under
// it is in flight.
func (a *nonceAllocator) reserve(did string, state AccountNonceState) (uint64, error) {
	return a.pick(did, state, func(c *nonceClaim, now time.Time) { c.reserved = now })
}

// pick hands out the lowest free nonce in did's window, claimed by claim.
func (a *nonceAllocator) pick(did string, state AccountNonceState, claim func(*nonceClaim, time.Time)) (uint64, error) {
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
		if _, held := acct.claims[n]; !held && !acct.used[n] {
			c := &nonceClaim{}
			claim(c, now)
			acct.claims[n] = c
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

// errNonceInFlight is begin's refusal of a nonce under which a submission
// from this client is in flight.
var errNonceInFlight = errors.New("a submission under the nonce from this client is in flight")

// begin records a submission under nonce, a nonce the caller chose, starting
// now: the nonce stays taken until it settles. It replaces a reservation of
// the nonce and keeps any hold an earlier submission left. Given state, the
// chain's report, it folds that in first and refuses with ErrNonceUsed a
// nonce it shows used. It refuses with errNonceInFlight a nonce under which a
// submission from this client is in flight (a write that took it, or another
// begun under it). The checks and the claim are made under one lock, so no
// write takes the nonce between them.
func (a *nonceAllocator) begin(did string, nonce uint64, state *AccountNonceState) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	acct := a.account(did)
	if state != nil {
		a.merge(acct, *state, a.now())
		if acct.view().IsUsed(nonce) {
			return ErrNonceUsed
		}
	}
	claim := acct.claims[nonce]
	if claim != nil && claim.inFlight > 0 {
		return errNonceInFlight
	}
	if claim == nil {
		claim = &nonceClaim{}
		acct.claims[nonce] = claim
	}
	claim.inFlight++
	claim.reserved = time.Time{}
	return nil
}

// settle records what one submission of the write digest (see writeDigest)
// signed by did under nonce (started by take or begin) left the nonce as. It
// removes only that submission's own in-flight count, so it never frees a hold
// another submission left. Accepted, unknown, and held nonces are held for
// NonceHold from now, as the node's hold runs from admission. It reports
// whether, before this submission, a submission of the same write from this
// client under the nonce was accepted or may have reached the node.
func (a *nonceAllocator) settle(did string, nonce uint64, outcome nonceOutcome, digest [32]byte) (sentBefore bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	acct := a.account(did)
	sentBefore = acct.sent[nonce][digest]
	claim := acct.claims[nonce]
	if claim != nil && claim.inFlight > 0 {
		claim.inFlight--
	}
	if nonce <= acct.base || acct.used[nonce] || outcome == nonceUsed {
		if nonce > acct.base {
			acct.used[nonce] = true
		}
		delete(acct.claims, nonce)
		delete(acct.sent, nonce)
		return sentBefore
	}
	now := a.now()
	switch outcome {
	case nonceAccepted, nonceUnknown, nonceHeld:
		if claim == nil {
			claim = &nonceClaim{}
			acct.claims[nonce] = claim
		}
		claim.held = now
		if outcome != nonceHeld {
			if acct.sent[nonce] == nil {
				acct.sent[nonce] = map[[32]byte]bool{}
			}
			acct.sent[nonce][digest] = true
		}
	}
	if claim != nil && !claim.live(now) {
		delete(acct.claims, nonce)
	}
	return sentBefore
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
	if err := json.NewDecoder(httpbody.Reader(resp.Body, httpbody.Small)).Decode(&answer); err != nil {
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
// doesn't hold. Take one here for a transaction the client doesn't choose the
// nonce of (a file write's FileSigningOptions.Nonce), so that no other write
// from this client takes it while it is in flight. A nonce handed out and
// never sent is free again after NonceHold; one sent through the client
// (Files) is held while the submission is in flight and as its outcome says.
//
// It returns an error wrapping ErrNonceWindowFull when every nonce in the
// window is used or held: wait for earlier writes to land.
func (c *Client) NextNonce(ctx context.Context, did string) (uint64, error) {
	state, err := c.GetAccountNonce(ctx, did)
	if err != nil {
		return 0, fmt.Errorf("failed to read the account nonce: %w", err)
	}
	return c.nonces.reserve(did, *state)
}

// WaitUntilLanded waits until the chain shows did's nonce used, polling its
// nonce state (see GetAccountNonce) until then or until ctx is done.
//
// A write returns once CheckTx accepts it; send a write that depends on it
// (an update of a key being stored, a store into a subgrove being
// registered) only after it lands, since writes in flight may land in any
// order. A write refused in its block also uses its nonce (every kind the
// SDK sends except DeregisterSubgrove, whose refusal leaves it unused): read
// what it wrote, or look the TxHash of its WriteResult up
// (consensus.Client.GetTx), to know it took effect. For a write whose
// *WriteError has MayLand set, read what it wrote: the API names no
// transaction hash for a submission that may have landed. (A CheckTx
// refusal's hash is on the *TransactionError the WriteError wraps.)
//
// Set an RPC URL (WithRPCURL) when writes run concurrently. Without one only
// the base is known, and the base advances only over used nonces with no gap
// below them, so a nonce that landed above a nonce not yet used (a write
// still pending, or one that never landed) doesn't show as landed: this waits
// for every earlier nonce of did, and fails at ctx's deadline if one never
// lands.
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

// WriteOption changes how a write method (Data.StoreItem,
// Registration.RegisterSubgrove, Registration.DeleteSubgrove, and
// Privacy.GrantSubgroveKey, RevokeSubgroveKey, and RotateSubgroveKey) signs
// its transaction.
type WriteOption func(*writeOptions)

type writeOptions struct {
	nonce    uint64
	hasNonce bool
}

// WithNonce signs the write under nonce instead of a nonce the client hands
// out. Use it to send a write again under the nonce of an earlier attempt
// that may have landed (the Nonce of a *WriteError with MayLand set):
// whichever attempt lands first uses the nonce and the other is refused, so
// the write runs at most once. Send the same write (the same fields) under it.
//
// The client reads the account's nonce state first. If the chain shows the
// nonce used, it sends nothing and returns a *WriteError wrapping
// ErrNonceUsed: the earlier attempt (or another transaction under the nonce)
// landed. A refusal as already used returns the same error; the write isn't
// signed again under another nonce. A refusal as held by a pending
// transaction, or another *WriteError with MayLand set (which is also how the
// API reports CometBFT refusing a transaction identical to one it has already
// seen), means a transaction under the nonce, most likely the earlier
// attempt, may be pending: wait for it with WaitUntilLanded. This attempt's
// outcome never frees the hold the earlier attempt left on the nonce. While a
// submission under the nonce from this client is in flight (a write that took
// it, or another sent under it), the write sends nothing and returns a
// *WriteError (not ErrNonceUsed): send it again once that one returns.
func WithNonce(nonce uint64) WriteOption {
	return func(o *writeOptions) {
		o.nonce, o.hasNonce = nonce, true
	}
}

// signedWrite builds a transaction signed by did with build, under a nonce
// the client hands out (or the one WithNonce gives), and submits it to POST
// /tx/submit once, recording the outcome for the nonce. A failure after the
// transaction was built returns a *WriteError naming its nonce.
//
// A refusal that says a nonce the client handed out is already used means no
// transaction under it can run, so the write is built again under the next
// free nonce, unless this client earlier sent the same write (the same
// transaction but for its nonce and signature; see writeDigest) under that
// nonce and that submission was accepted or may have reached the node: it may
// be what used the nonce, so the write fails with ErrNonceUsed rather than run
// twice. A different write that used the nonce says nothing about this one,
// which is signed again. Every earlier attempt within one call was refused at
// CheckTx, so none of them can run.
func (c *Client) signedWrite(ctx context.Context, did string, opts []WriteOption, build func(nonce uint64) (interface{}, error)) (*WriteResult, error) {
	var o writeOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	if o.hasNonce {
		return c.writeUnder(ctx, did, o.nonce, build)
	}
	var refused error
	for attempt := 0; attempt < NonceWindow; attempt++ {
		state, err := c.GetAccountNonce(ctx, did)
		if err != nil {
			return nil, fmt.Errorf("failed to read the account nonce: %w", err)
		}
		nonce, err := c.nonces.take(did, *state)
		if err != nil {
			return nil, err
		}
		result, outcome, sentBefore, err := c.writeOnce(ctx, did, nonce, build)
		if err == nil || outcome != nonceUsed {
			return result, err
		}
		if sentBefore {
			return nil, usedNonceError(err, "this client sent this same write under it before, and that attempt may have landed; "+
				"read what the write wrote before sending it again")
		}
		refused = err
	}
	return nil, refused
}

// writeUnder sends a write under nonce, a nonce the caller chose (WithNonce):
// unless the chain already shows it used, or a submission under it from this
// client is in flight, once, never under another nonce.
func (c *Client) writeUnder(ctx context.Context, did string, nonce uint64, build func(nonce uint64) (interface{}, error)) (*WriteResult, error) {
	state, err := c.GetAccountNonce(ctx, did)
	if err != nil {
		return nil, fmt.Errorf("failed to read the account nonce: %w", err)
	}
	switch err := c.nonces.begin(did, nonce, state); {
	case errors.Is(err, ErrNonceUsed):
		return nil, &WriteError{DID: did, Nonce: nonce, Err: fmt.Errorf(
			"%w: the chain shows nonce %d of %s used, so the write wasn't sent; if an earlier attempt of it was sent under this nonce, "+
				"that attempt landed: read what it wrote before sending the write again under a fresh nonce", ErrNonceUsed, nonce, did)}
	case err != nil:
		return nil, &WriteError{DID: did, Nonce: nonce, Err: fmt.Errorf(
			"%w, so the write wasn't sent: send it under nonce %d once that submission returns", err, nonce)}
	}
	result, outcome, _, err := c.writeOnce(ctx, did, nonce, build)
	if err != nil && outcome == nonceUsed {
		return nil, usedNonceError(err, "if an earlier attempt of this write was sent under it, that attempt landed; "+
			"read what it wrote before sending the write again under a fresh nonce")
	}
	return result, err
}

// writeOnce builds the transaction under nonce, which the caller has taken or
// begun a submission under, submits it once, and settles the nonce with the
// outcome (also if build panics). It reports whether a submission of the same
// write (see writeDigest) from this client under the nonce was accepted or may
// have reached the node before this one. A failure after the transaction was
// built is a *WriteError.
func (c *Client) writeOnce(ctx context.Context, did string, nonce uint64, build func(nonce uint64) (interface{}, error)) (result *WriteResult, outcome nonceOutcome, sentBefore bool, err error) {
	outcome = nonceFree
	var digest [32]byte
	defer func() { sentBefore = c.nonces.settle(did, nonce, outcome, digest) }()
	tx, err := build(nonce)
	if err != nil {
		return nil, nonceFree, false, err
	}
	body, err := json.Marshal(tx)
	if err != nil {
		return nil, nonceFree, false, NewSerializationError("failed to marshal transaction", err)
	}
	digest = writeDigest(body)
	var hash string
	hash, outcome, err = c.postTx(ctx, body, did, nonce)
	if err != nil {
		return nil, outcome, false, &WriteError{DID: did, Nonce: nonce, MayLand: outcome == nonceUnknown, Err: err}
	}
	return &WriteResult{DID: did, Nonce: nonce, TxHash: hash}, outcome, false, nil
}

// writeDigest identifies the write a transaction body makes apart from the
// nonce it is signed under: the SHA-256 of the body with its transaction's
// "signature" and "nonce" fields removed (object keys sorted). Two
// submissions of the same write under different nonces share it. A body that
// isn't one transaction object is digested whole.
func writeDigest(body []byte) [32]byte {
	var tx map[string]map[string]json.RawMessage
	if err := json.Unmarshal(body, &tx); err != nil || len(tx) != 1 {
		return sha256.Sum256(body)
	}
	for _, fields := range tx {
		delete(fields, "signature")
		delete(fields, "nonce")
	}
	canonical, err := json.Marshal(tx)
	if err != nil {
		return sha256.Sum256(body)
	}
	return sha256.Sum256(canonical)
}

// usedNonceError is a write refused because its nonce is used, as ErrNonceUsed
// for the reason why, still carrying the refusal.
func usedNonceError(err error, why string) error {
	var werr *WriteError
	if !errors.As(err, &werr) {
		return err
	}
	return &WriteError{DID: werr.DID, Nonce: werr.Nonce, Err: fmt.Errorf("%w (%s): %w", ErrNonceUsed, why, werr.Err)}
}

// submitSigned submits a transaction did signed under nonce, a nonce the
// caller chose, and records the outcome, so that this client's own writes
// skip the nonce while it is in flight and as long as its outcome holds it.
// It sends nothing while a submission under the nonce from this client is in
// flight. An unsigned transaction (did empty) records nothing.
func (c *Client) submitSigned(ctx context.Context, did string, nonce uint64, body []byte) error {
	if did == "" {
		_, _, err := c.postTx(ctx, body, did, nonce)
		return err
	}
	if err := c.nonces.begin(did, nonce, nil); err != nil {
		return fmt.Errorf("nonce %d of %s: %w, so the transaction wasn't sent", nonce, did, err)
	}
	outcome := nonceFree
	digest := writeDigest(body)
	defer func() { c.nonces.settle(did, nonce, outcome, digest) }()
	var err error
	_, outcome, err = c.postTx(ctx, body, did, nonce)
	return err
}
