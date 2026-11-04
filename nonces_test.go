package willow

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// nonceServer is a mocked API (and CometBFT RPC under /rpc) for did:willow:a:
// it reports the account's base (and, over ABCI, its bitmap), answers each
// /tx/submit with the next queued answer or else accepts it, and records the
// nonce of each transaction submitted.
type nonceServer struct {
	t       *testing.T
	mu      sync.Mutex
	base    uint64
	used    uint32
	answers []func(nonce uint64) (int, string)
	nonces  []uint64
	abciErr bool
	reads   int
	srv     *httptest.Server
}

func newNonceServer(t *testing.T, base uint64) *nonceServer {
	s := &nonceServer{t: t, base: base}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.srv.Close)
	return s
}

func accept(uint64) (int, string) {
	return http.StatusOK, `{"success":true,"data":{"tx_hash":"AB","code":0,"log":""},"error":null}`
}

// refuse answers a CheckTx refusal whose log is log, its %d the nonce.
func refuse(log string) func(uint64) (int, string) {
	return func(nonce uint64) (int, string) {
		text := log
		if strings.Contains(log, "%d") {
			text = fmt.Sprintf(log, nonce)
		}
		body, _ := json.Marshal(map[string]interface{}{
			"success": true, "data": map[string]interface{}{"tx_hash": "CD", "code": 1, "log": text}, "error": nil,
		})
		return http.StatusOK, string(body)
	}
}

func status(code int) func(uint64) (int, string) {
	return func(uint64) (int, string) {
		return code, `{"success":false,"data":null,"error":"refused"}`
	}
}

func (s *nonceServer) queue(answers ...func(uint64) (int, string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.answers = append(s.answers, answers...)
}

func (s *nonceServer) sent() []uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]uint64(nil), s.nonces...)
}

func (s *nonceServer) setState(base uint64, used uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.base, s.used = base, used
}

func (s *nonceServer) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/account/did:willow:a/nonce":
		s.reads++
		fmt.Fprintf(w, `{"success":true,"data":{"did":"did:willow:a","nonce":%d},"error":null}`, s.base)
	case r.Method == http.MethodPost && r.URL.Path == "/rpc":
		var req struct {
			Method string `json:"method"`
			Params struct {
				Path string `json:"path"`
			} `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Method != "abci_query" ||
			req.Params.Path != "/store/account_nonce_state/did:willow:a" {
			s.t.Errorf("unexpected RPC %+v (%v)", req, err)
		}
		s.reads++
		if s.abciErr {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		value := make([]byte, 11)
		binary.BigEndian.PutUint64(value, s.base)
		value[8], value[9], value[10] = byte(s.used), byte(s.used>>8), byte(s.used>>16)
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":{"response":{"code":0,"log":"","value":%q}}}`,
			base64.StdEncoding.EncodeToString(value))
	case r.Method == http.MethodPost && r.URL.Path == "/tx/submit":
		var tx map[string]map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&tx); err != nil || len(tx) != 1 {
			s.t.Errorf("transaction %v (%v)", tx, err)
		}
		var nonce uint64
		for _, fields := range tx {
			if err := json.Unmarshal(fields["nonce"], &nonce); err != nil {
				s.t.Error(err)
			}
		}
		s.nonces = append(s.nonces, nonce)
		answer := accept
		if len(s.answers) > 0 {
			answer, s.answers = s.answers[0], s.answers[1:]
		}
		code, body := answer(nonce)
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	default:
		s.t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

// client returns a client of the server signing as did:willow:a, its clock
// now(), and, with rpc, the server's /rpc as its RPC URL.
func (s *nonceServer) client(now func() time.Time, rpc bool) *Client {
	s.t.Helper()
	var opts []ClientOption
	if rpc {
		opts = append(opts, WithRPCURL(s.srv.URL+"/rpc"))
	}
	client, err := NewClient(s.srv.URL, opts...)
	if err != nil {
		s.t.Fatal(err)
	}
	client.SetIdentity(vectorIdentity(s.t, Ed25519))
	if now != nil {
		client.nonces = newNonceAllocator(now)
	}
	client.noncePollInterval = time.Millisecond
	return client
}

// fakeClock is a clock tests move by hand.
type fakeClock struct {
	mu sync.Mutex
	at time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{at: time.Unix(1_000_000, 0)} }

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

func store(t *testing.T, client *Client, key string) (*WriteResult, error) {
	t.Helper()
	return client.Data.StoreItem(context.Background(), "sg", key, map[string]interface{}{"k": key})
}

// Writes in flight together take distinct nonces, the lowest in the window;
// with all 24 held, the next write fails with ErrNonceWindowFull and sends
// nothing.
func TestConcurrentWritesTakeDistinctNonces(t *testing.T) {
	s := newNonceServer(t, 100)
	client := s.client(nil, false)
	var wg sync.WaitGroup
	results := make([]*WriteResult, NonceWindow)
	errs := make([]error, NonceWindow)
	for i := 0; i < NonceWindow; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = client.Data.StoreItem(context.Background(), "sg", "k"+strconv.Itoa(i), map[string]interface{}{"i": i})
		}(i)
	}
	wg.Wait()
	var nonces []uint64
	for i := range results {
		if errs[i] != nil {
			t.Fatalf("write %d: %v", i, errs[i])
		}
		nonces = append(nonces, results[i].Nonce)
	}
	sort.Slice(nonces, func(i, j int) bool { return nonces[i] < nonces[j] })
	for i, n := range nonces {
		if n != 101+uint64(i) {
			t.Fatalf("nonces %v, want 101 to 124 once each", nonces)
		}
	}

	_, err := store(t, client, "one-more")
	if !errors.Is(err, ErrNonceWindowFull) {
		t.Fatalf("25th write in flight: %v, want ErrNonceWindowFull", err)
	}
	if len(s.sent()) != NonceWindow {
		t.Fatalf("sent %d transactions, want %d", len(s.sent()), NonceWindow)
	}

	// Once the base passes them, the window is free again.
	s.setState(124, 0)
	if write, err := store(t, client, "after"); err != nil || write.Nonce != 125 {
		t.Fatalf("after the base advanced: %+v, %v", write, err)
	}
}

// A CheckTx refusal that doesn't say the nonce is held or used gives it back:
// the next write takes it. So does a 4xx, which never reached CheckTx.
func TestRefusedWriteGivesItsNonceBack(t *testing.T) {
	s := newNonceServer(t, 0)
	client := s.client(nil, false)
	s.queue(refuse("Subgrove not found: sg"), status(http.StatusBadRequest))

	_, err := store(t, client, "a")
	var werr *WriteError
	if !errors.As(err, &werr) || werr.Nonce != 1 || werr.MayLand {
		t.Fatalf("refused write: %v, want a WriteError for nonce 1 that won't land", err)
	}
	var txErr *TransactionError
	if !errors.As(err, &txErr) || txErr.ErrorCode != 1 {
		t.Fatalf("refused write: %v, want the CheckTx refusal", err)
	}
	if _, err := store(t, client, "b"); !IsValidationError(err) {
		t.Fatalf("400: %v, want a validation error", err)
	}
	if write, err := store(t, client, "c"); err != nil || write.Nonce != 1 {
		t.Fatalf("after two refusals: %+v, %v, want nonce 1", write, err)
	}
	if got := s.sent(); fmt.Sprint(got) != "[1 1 1]" {
		t.Fatalf("sent nonces %v, want [1 1 1]", got)
	}
}

// A refusal saying the nonce is held by a pending transaction keeps it taken
// and fails the write; one saying it is already used, at or below the base,
// or spent marks it used and signs the write again under the next nonce.
// Only the node's text for this transaction's own nonce and DID counts.
func TestHeldAndUsedRefusals(t *testing.T) {
	s := newNonceServer(t, 0)
	client := s.client(nil, false)

	s.queue(refuse("Nonce %d of did:willow:a is held by a pending transaction; sign this one with another nonce"))
	_, err := store(t, client, "held")
	var werr *WriteError
	if !errors.As(err, &werr) || werr.Nonce != 1 || werr.MayLand {
		t.Fatalf("held: %v, want a WriteError for nonce 1", err)
	}
	if write, err := store(t, client, "next"); err != nil || write.Nonce != 2 {
		t.Fatalf("after held: %+v, %v, want nonce 2 (1 stays held)", write, err)
	}

	s.queue(
		refuse("Signature validation failed: Invalid nonce: %d already used (replay)"),
		refuse("Invalid nonce: %d <= base nonce 9"),
		refuse("Subgrove not found (nonce %d spent)"),
	)
	write, err := store(t, client, "used")
	if err != nil || write.Nonce != 6 {
		t.Fatalf("after three used refusals: %+v, %v, want nonce 6", write, err)
	}
	if got := s.sent(); fmt.Sprint(got) != "[1 2 3 4 5 6]" {
		t.Fatalf("sent nonces %v, want [1 2 3 4 5 6]", got)
	}

	// Another nonce's or another DID's text in the log gives this one back.
	s.queue(
		refuse("Invalid nonce: 1%d already used (replay)"),
		refuse("Nonce %d of did:willow:ab is held by a pending transaction"),
	)
	for i := 0; i < 2; i++ {
		if _, err := store(t, client, "other"); err == nil {
			t.Fatal("refused write reported as accepted")
		}
	}
	if write, err := store(t, client, "again"); err != nil || write.Nonce != 7 {
		t.Fatalf("after refusals naming other nonces: %+v, %v, want nonce 7", write, err)
	}
}

func TestRefusalOutcome(t *testing.T) {
	for log, want := range map[string]nonceOutcome{
		"Nonce 5 of did:willow:a is held by a pending transaction; sign this one with another nonce": nonceHeld,
		"Invalid nonce: 5 already used (replay)":                                                     nonceUsed,
		"Signature validation failed: Invalid nonce: 5 <= base nonce 7":                              nonceUsed,
		"Subgrove not found (nonce 5 spent)":                                                         nonceUsed,
		"Nonce 15 of did:willow:a is held by a pending transaction":                                  nonceFree,
		"Nonce 5 of did:willow:b is held by a pending transaction":                                   nonceFree,
		"Invalid nonce: 55 already used (replay)":                                                    nonceFree,
		"Invalid nonce: 15 <= base nonce 20":                                                         nonceFree,
		"Subgrove not found (nonce 15 spent)":                                                        nonceFree,
		"Invalid nonce: 5 is too far ahead (base=100, max=124)":                                      nonceFree,
		"already used": nonceFree,
	} {
		if got := refusalOutcome(log, "did:willow:a", 5); got != want {
			t.Errorf("%q: %v, want %v", log, got, want)
		}
	}
}

// A submission that fails in transit (a 5xx) may have reached the node: its
// error says so and names the nonce, which stays taken.
func TestUnknownOutcomeKeepsTheNonce(t *testing.T) {
	s := newNonceServer(t, 0)
	client := s.client(nil, false)
	s.queue(status(http.StatusBadGateway))
	_, err := store(t, client, "a")
	var werr *WriteError
	if !errors.As(err, &werr) || werr.Nonce != 1 || !werr.MayLand || werr.DID != "did:willow:a" {
		t.Fatalf("502: %v, want a WriteError for nonce 1 that may land", err)
	}
	if write, err := store(t, client, "b"); err != nil || write.Nonce != 2 {
		t.Fatalf("after a 502: %+v, %v, want nonce 2", write, err)
	}
}

// A nonce handed out and not seen to land is free again NonceHold after its
// hold began; acceptance restarts the hold.
func TestHandedOutNoncesLapse(t *testing.T) {
	clock := newFakeClock()
	a := newNonceAllocator(clock.now)
	take := func() uint64 {
		t.Helper()
		n, err := a.take("did:willow:a", AccountNonceState{Base: 0})
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := take(); n != 1 {
		t.Fatalf("first: %d", n)
	}
	clock.advance(NonceHold - time.Second)
	if n := take(); n != 2 {
		t.Fatalf("within the hold: %d, want 2", n)
	}
	clock.advance(time.Second)
	if n := take(); n != 1 {
		t.Fatalf("after nonce 1's hold: %d, want 1 again", n)
	}
	// Nonce 1 is held from now; settling 2 as accepted restarts its hold too.
	a.settle("did:willow:a", 2, nonceAccepted)
	clock.advance(NonceHold - time.Second)
	if n := take(); n != 3 {
		t.Fatalf("with 1 and 2 held: %d, want 3", n)
	}
	clock.advance(time.Second)
	if n := take(); n != 1 {
		t.Fatalf("after 1's second hold: %d, want 1", n)
	}

	// Through a client: a write accepted and never seen to land frees its
	// nonce after NonceHold.
	s := newNonceServer(t, 0)
	clock = newFakeClock()
	client := s.client(clock.now, false)
	if write, err := store(t, client, "a"); err != nil || write.Nonce != 1 {
		t.Fatalf("%+v, %v", write, err)
	}
	if write, err := store(t, client, "b"); err != nil || write.Nonce != 2 {
		t.Fatalf("%+v, %v", write, err)
	}
	clock.advance(NonceHold)
	if write, err := store(t, client, "c"); err != nil || write.Nonce != 1 {
		t.Fatalf("after the hold: %+v, %v, want nonce 1", write, err)
	}
}

// With an RPC URL the client reads the bitmap and skips the nonces it shows
// used; if the ABCI query fails it reads the base from the API.
func TestNoncesSkipTheChainsBitmap(t *testing.T) {
	s := newNonceServer(t, 10)
	s.setState(10, 0b1011) // 11, 12, and 14 used
	client := s.client(nil, true)
	state, err := client.GetAccountNonce(context.Background(), "did:willow:a")
	if err != nil || *state != (AccountNonceState{Base: 10, Used: 0b1011}) {
		t.Fatalf("GetAccountNonce = %+v, %v", state, err)
	}
	for _, want := range []uint64{13, 15} {
		if write, err := store(t, client, "k"); err != nil || write.Nonce != want {
			t.Fatalf("%+v, %v, want nonce %d", write, err, want)
		}
	}
	// An older answer (a lower base, no bits) doesn't free what was seen used.
	s.setState(9, 0)
	if write, err := store(t, client, "k"); err != nil || write.Nonce != 16 {
		t.Fatalf("after a lagging answer: %+v, %v, want nonce 16", write, err)
	}

	s.mu.Lock()
	s.abciErr = true
	s.mu.Unlock()
	if state, err := client.GetAccountNonce(context.Background(), "did:willow:a"); err != nil || state.Base != 9 || state.Used != 0 {
		t.Fatalf("ABCI failing: %+v, %v, want the API's base", state, err)
	}
}

func TestParseAccountNonceState(t *testing.T) {
	for _, c := range []struct {
		hex  []byte
		want AccountNonceState
	}{
		{nil, AccountNonceState{}},
		{[]byte{0, 0, 0, 0, 0, 0, 1, 2}, AccountNonceState{Base: 258}},
		{[]byte{0, 0, 0, 0, 0, 0, 0, 7, 0b101, 0, 0x80}, AccountNonceState{Base: 7, Used: 0b101 | 1<<23}},
	} {
		got, err := ParseAccountNonceState(c.hex)
		if err != nil || got != c.want {
			t.Errorf("%x: %+v, %v, want %+v", c.hex, got, err, c.want)
		}
	}
	state := AccountNonceState{Base: 7, Used: 0b101 | 1<<23}
	for n, want := range map[uint64]bool{1: true, 7: true, 8: true, 9: false, 10: true, 30: false, 31: true, 32: false} {
		if state.IsUsed(n) != want {
			t.Errorf("IsUsed(%d) = %v", n, !want)
		}
	}
	if _, err := ParseAccountNonceState(make([]byte, 9)); err == nil {
		t.Error("9 bytes parsed")
	}
}

// WaitUntilLanded returns once the chain shows the nonce used, and fails with
// the context's error when it doesn't in time.
func TestWaitUntilLanded(t *testing.T) {
	s := newNonceServer(t, 0)
	client := s.client(nil, false)
	write, err := store(t, client, "a")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err = client.WaitUntilLanded(ctx, write.DID, write.Nonce)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("before it landed: %v, want the deadline", err)
	}

	go func() {
		time.Sleep(5 * time.Millisecond)
		s.setState(1, 0)
	}()
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.WaitUntilLanded(ctx, write.DID, write.Nonce); err != nil {
		t.Fatalf("after it landed: %v", err)
	}

	// Over ABCI a nonce above the base counts once its bit is set.
	rpc := s.client(nil, true)
	s.setState(1, 0b10) // 3 used, 2 not
	if err := rpc.WaitUntilLanded(ctx, "did:willow:a", 3); err != nil {
		t.Fatalf("bit set: %v", err)
	}
	short, cancelShort := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelShort()
	if err := rpc.WaitUntilLanded(short, "did:willow:a", 2); err == nil {
		t.Fatal("nonce 2 reported landed")
	}
}

// A transaction sent under a nonce the caller chose (a file write) holds that
// nonce: the client's own writes skip it while it is in flight.
func TestCallerChosenNoncesAreHeld(t *testing.T) {
	s := newNonceServer(t, 0)
	client := s.client(nil, false)
	id := vectorIdentity(t, Ed25519)
	nonce, err := client.NextNonce(context.Background(), id.DID())
	if err != nil || nonce != 1 {
		t.Fatalf("NextNonce = %d, %v", nonce, err)
	}
	if err := client.Files.Delete("sg", "f", fileSigning(id, nonce)); err != nil {
		t.Fatal(err)
	}
	if err := client.Files.Delete("sg", "g", fileSigning(id, 2)); err != nil {
		t.Fatal(err)
	}
	if write, err := store(t, client, "k"); err != nil || write.Nonce != 3 {
		t.Fatalf("%+v, %v, want nonce 3", write, err)
	}
}
