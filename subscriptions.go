package willow

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
)

// SubscribeSource tells the SDK which backend to open the subscription
// WebSocket against.
//
//   - SubscribeSourceValidator (default): {apiURL}/graphql/ws,
//     consensus-verified chain-tip events (BlockFinalized).
//   - SubscribeSourceIndexer: selected via discovery (or the explicit
//     indexerURL override), for `VerifyOnly` subgroves or caller-driven
//     indexer-side tails.
type SubscribeSource int

const (
	SubscribeSourceValidator SubscribeSource = iota
	SubscribeSourceIndexer
)

// SubscribeOptions is the optional argument bag for Subscribe.
//
// Auto-reconnect is on by default. To opt out explicitly, set
// Reconnect to a pointer to false (see BoolPtr). On unexpected
// disconnect the SDK applies exponential backoff and for
// SubscribeSourceIndexer re-resolves a different indexer via discovery.
type SubscribeOptions struct {
	// Variables passes GraphQL variables into the subscribe payload.
	Variables map[string]any
	// OperationName sets the GraphQL operation name (when the query
	// contains multiple).
	OperationName string
	// ConnectionPayload is forwarded on the `connection_init` frame
	// (e.g., auth tokens).
	ConnectionPayload map[string]any
	// Source picks which backend to connect to. Defaults to
	// SubscribeSourceValidator.
	Source SubscribeSource

	// Reconnect enables automatic reconnect on unexpected disconnect.
	// Nil means the SDK default (reconnect enabled). To opt out
	// explicitly, pass BoolPtr(false).
	//
	// Reconnection is reconnect-only: messages that were in flight when
	// the socket dropped are not replayed, and the new connection may
	// redeliver events the old one already emitted. Callers that need
	// exactly-once should dedupe by a stable field (e.g., block number
	// or entity id) themselves.
	Reconnect *bool

	// MaxReconnectAttempts caps the number of consecutive reconnect
	// attempts. Zero means retry forever. The counter resets only after
	// a reconnection delivers at least one real payload — this avoids an
	// infinite loop against a server that accepts the subscription but
	// immediately drops the socket.
	MaxReconnectAttempts int

	// ReconnectBackoff is the initial reconnect delay; it doubles on
	// each consecutive failure up to MaxReconnectBackoff. Zero means
	// 500 ms.
	ReconnectBackoff time.Duration

	// MaxReconnectBackoff caps the reconnect delay. Zero means 30 s.
	MaxReconnectBackoff time.Duration

	// OnReconnect is called when a reconnect attempt is scheduled.
	// attempt is 1-indexed; delay is the backoff we'll sleep before
	// trying. Callback errors are ignored.
	OnReconnect func(attempt int, delay time.Duration)
}

// BoolPtr is a convenience helper for the Reconnect field.
//
// Usage:
//
//	opts := &SubscribeOptions{Reconnect: BoolPtr(false)}
func BoolPtr(b bool) *bool { return &b }

// SubscriptionPayload is a single payload pushed by the server over a
// `next` frame. Mirrors the graphql-transport-ws wire shape.
type SubscriptionPayload struct {
	Data   map[string]any `json:"data,omitempty"`
	Errors any            `json:"errors,omitempty"`
}

// Subscription exposes an incoming stream of SubscriptionPayloads via
// its Events channel. Reconnects are transparent: the channel stays
// open across transient drops and only closes when the subscription is
// definitively over (server `complete`, caller Unsubscribe, reconnect
// disabled + socket drop, or MaxReconnectAttempts exhausted).
type Subscription struct {
	// Events emits server `next` payloads. Closed when the subscription
	// ends. Err() after close tells you why.
	Events <-chan SubscriptionPayload

	cancel func()
	mu     sync.Mutex
	err    error
	done   chan struct{}
	subID  string
}

// Err returns the error that terminated the subscription, or nil if it
// was a clean completion or Unsubscribe. Safe to call after <-Done().
func (s *Subscription) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func (s *Subscription) setErr(err error) {
	s.mu.Lock()
	s.err = err
	s.mu.Unlock()
}

// Done is closed when the subscription has fully terminated.
func (s *Subscription) Done() <-chan struct{} { return s.done }

// Unsubscribe cancels the subscription. The loop will send `complete`
// to the current server and close the socket on its way out. Safe to
// call more than once.
func (s *Subscription) Unsubscribe(ctx context.Context) error {
	s.cancel()
	select {
	case <-s.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

// Subscriptions is the subscription client wired into WillowClient.
type Subscriptions struct {
	apiURL     string
	indexers   *Indexers
	counter    atomic.Uint64
	httpClient *http.Client
}

// NewSubscriptions creates a subscription client. Normally constructed
// by NewClient; callers invoke it via Client.Subscriptions.
func NewSubscriptions(apiURL string, indexers *Indexers, httpClient *http.Client) *Subscriptions {
	return &Subscriptions{
		apiURL:     strings.TrimRight(apiURL, "/"),
		indexers:   indexers,
		httpClient: httpClient,
	}
}

// Subscribe opens a GraphQL subscription.
//
// The initial handshake runs synchronously — connection_init →
// connection_ack → subscribe — so the first-attempt failures surface
// here. After that the subscription is handed off to a background
// goroutine that handles reconnects (unless Reconnect is explicitly
// disabled).
//
// For SubscribeSourceIndexer, discovery happens inside this call on
// the first attempt. On each reconnect, the previously-used indexer is
// evicted from the discovery cache so failover to a different indexer
// is automatic.
func (s *Subscriptions) Subscribe(
	ctx context.Context,
	subgroveID, query string,
	opts *SubscribeOptions,
) (*Subscription, error) {
	resolved := resolveOptions(opts)

	subID := fmt.Sprintf("sub-%d-%d",
		s.counter.Add(1), time.Now().UnixNano())

	// Initial connect — eager-fail so discovery / handshake errors
	// surface directly to the caller.
	conn, initialIndexerDID, err := s.resolveAndConnect(
		ctx, subgroveID, query, subID, resolved, "")
	if err != nil {
		return nil, err
	}

	events := make(chan SubscriptionPayload, 64)
	loopCtx, cancel := context.WithCancel(context.Background())
	sub := &Subscription{
		Events: events,
		cancel: cancel,
		done:   make(chan struct{}),
		subID:  subID,
	}

	go s.subscriptionLoop(
		loopCtx, conn, initialIndexerDID, subgroveID, query, subID,
		resolved, events, sub)
	return sub, nil
}

// ---------------------------------------------------------------------------
// Internal plumbing
// ---------------------------------------------------------------------------

// resolvedOptions is SubscribeOptions with all defaults filled in.
type resolvedOptions struct {
	variables            map[string]any
	operationName        string
	connectionPayload    map[string]any
	source               SubscribeSource
	reconnect            bool
	maxReconnectAttempts int
	reconnectBackoff     time.Duration
	maxReconnectBackoff  time.Duration
	onReconnect          func(int, time.Duration)
}

func resolveOptions(opts *SubscribeOptions) resolvedOptions {
	r := resolvedOptions{
		reconnect:           true,
		reconnectBackoff:    500 * time.Millisecond,
		maxReconnectBackoff: 30 * time.Second,
	}
	if opts == nil {
		return r
	}
	r.variables = opts.Variables
	r.operationName = opts.OperationName
	r.connectionPayload = opts.ConnectionPayload
	r.source = opts.Source
	if opts.Reconnect != nil {
		r.reconnect = *opts.Reconnect
	}
	r.maxReconnectAttempts = opts.MaxReconnectAttempts
	if opts.ReconnectBackoff > 0 {
		r.reconnectBackoff = opts.ReconnectBackoff
	}
	if opts.MaxReconnectBackoff > 0 {
		r.maxReconnectBackoff = opts.MaxReconnectBackoff
	}
	r.onReconnect = opts.OnReconnect
	return r
}

type pumpExitKind int

const (
	pumpServerComplete pumpExitKind = iota
	pumpDisconnected
	pumpCancelled
)

type pumpExit struct {
	kind             pumpExitKind
	deliveredPayload bool
	// err is set when kind == pumpDisconnected and the disconnect was
	// not a clean-close. The loop surfaces it via Subscription.Err() iff
	// the subscription gives up (reconnect disabled or attempts
	// exhausted); otherwise a successful reconnect clears it.
	err error
}

// resolveAndConnect picks an endpoint (evicting any last-failed
// indexer first), opens the WebSocket, and drives the handshake. On
// failure it closes any partially opened connection and returns the
// error. Returns (conn, indexerDID, error); indexerDID is empty for
// validator mode.
func (s *Subscriptions) resolveAndConnect(
	ctx context.Context,
	subgroveID, query, subID string,
	opts resolvedOptions,
	skipIndexerDID string,
) (*websocket.Conn, string, error) {
	var wsURL, indexerDID string

	switch opts.source {
	case SubscribeSourceValidator:
		wsURL = httpToWS(s.apiURL) + "/graphql/ws"
	case SubscribeSourceIndexer:
		if s.indexers == nil {
			return nil, "", fmt.Errorf(
				"source=indexer requires an Indexers client — none provided")
		}
		// Evict the failed DID (if any) before re-resolving so discovery
		// picks a different candidate.
		if skipIndexerDID != "" {
			s.indexers.Evict(skipIndexerDID)
		}
		candidates, err := s.indexers.ForSubgrove(ctx, subgroveID)
		if err != nil {
			return nil, "", fmt.Errorf("indexer discovery: %w", err)
		}
		if len(candidates) == 0 {
			return nil, "", fmt.Errorf(
				"no indexer serves subgrove %q — cannot open indexer subscription",
				subgroveID)
		}
		chosen := candidates[0]
		indexerDID = chosen.IndexerDID
		endpoint := strings.TrimRight(chosen.EffectiveQueryEndpoint(), "/")
		wsURL = httpToWS(endpoint) + "/graphql/ws"
	}

	conn, err := connectAndHandshake(ctx, wsURL, subID, query, opts, s.httpClient)
	if err != nil {
		return nil, "", err
	}
	return conn, indexerDID, nil
}

// connectAndHandshake dials the WebSocket and drives the
// graphql-transport-ws connection_init → connection_ack → subscribe
// exchange. On any failure, closes the socket before propagating.
func connectAndHandshake(
	ctx context.Context,
	wsURL, subID, query string,
	opts resolvedOptions,
	httpClient *http.Client,
) (*websocket.Conn, error) {
	dialOpts := &websocket.DialOptions{
		HTTPClient:   httpClient,
		Subprotocols: []string{"graphql-transport-ws"},
	}
	conn, _, err := websocket.Dial(ctx, wsURL, dialOpts)
	if err != nil {
		return nil, fmt.Errorf("websocket dial %s: %w", wsURL, err)
	}

	initPayload := opts.connectionPayload
	if initPayload == nil {
		initPayload = map[string]any{}
	}
	if err := conn.Write(ctx, websocket.MessageText,
		mustJSON(map[string]any{
			"type":    "connection_init",
			"payload": initPayload,
		})); err != nil {
		conn.Close(websocket.StatusInternalError, "init failed")
		return nil, fmt.Errorf("send connection_init: %w", err)
	}

	// Wait for connection_ack. Tolerate server-originated ping during
	// handshake; reject a connection_error frame loudly.
	for {
		_, raw, err := conn.Read(ctx)
		if err != nil {
			conn.Close(websocket.StatusInternalError, "ack failed")
			return nil, fmt.Errorf("read connection_ack: %w", err)
		}
		var frame map[string]any
		if err := json.Unmarshal(raw, &frame); err != nil {
			continue
		}
		t, _ := frame["type"].(string)
		switch t {
		case "connection_ack":
			goto acked
		case "ping":
			_ = conn.Write(ctx, websocket.MessageText,
				mustJSON(map[string]any{"type": "pong"}))
		case "connection_error":
			conn.Close(websocket.StatusPolicyViolation, "rejected")
			return nil, fmt.Errorf(
				"server refused connection: %v", frame["payload"])
		}
	}

acked:
	subPayload := map[string]any{"query": query}
	if opts.variables != nil {
		subPayload["variables"] = opts.variables
	}
	if opts.operationName != "" {
		subPayload["operationName"] = opts.operationName
	}
	if err := conn.Write(ctx, websocket.MessageText,
		mustJSON(map[string]any{
			"type":    "subscribe",
			"id":      subID,
			"payload": subPayload,
		})); err != nil {
		conn.Close(websocket.StatusInternalError, "subscribe failed")
		return nil, fmt.Errorf("send subscribe: %w", err)
	}
	return conn, nil
}

// subscriptionLoop is the background task that pumps frames and
// handles reconnect-backoff cycles until the subscription is over.
func (s *Subscriptions) subscriptionLoop(
	ctx context.Context,
	initialConn *websocket.Conn,
	initialIndexerDID string,
	subgroveID, query, subID string,
	opts resolvedOptions,
	events chan<- SubscriptionPayload,
	sub *Subscription,
) {
	defer close(events)
	defer close(sub.done)

	conn := initialConn
	lastIndexerDID := initialIndexerDID
	attempts := 0

	for conn != nil {
		exit := pump(ctx, conn, subID, events)

		// If the caller cancelled, send a best-effort `complete` so the
		// server can tear down state promptly; otherwise just tear down
		// the socket. CloseNow skips the close-handshake round-trip —
		// important after abnormal drops, where Close would block
		// waiting for a close frame that'll never arrive.
		if exit.kind == pumpCancelled {
			sendCompleteBestEffort(conn, subID)
		}
		_ = conn.CloseNow()
		conn = nil

		if exit.kind == pumpServerComplete || exit.kind == pumpCancelled {
			return
		}

		// Disconnected branch.
		if !opts.reconnect {
			// Surface the drop reason through Err().
			if exit.err != nil {
				sub.setErr(exit.err)
			}
			return
		}

		// Only reset the retry counter when the connection we just lost
		// actually delivered data. A server that accepts the subscription
		// but immediately drops the socket would otherwise reset the
		// counter on every cycle and loop forever.
		if exit.deliveredPayload {
			attempts = 0
		}

		// Inner retry loop: backoff, then try to reconnect. Each failed
		// attempt counts toward MaxReconnectAttempts.
		lastErr := exit.err
		for conn == nil {
			if opts.maxReconnectAttempts > 0 && attempts >= opts.maxReconnectAttempts {
				// Exhausted: surface the last disconnect error.
				if lastErr != nil {
					sub.setErr(lastErr)
				}
				return
			}
			attempts++
			delay := time.Duration(
				float64(opts.reconnectBackoff) *
					math.Pow(2, float64(attempts-1)),
			)
			if delay > opts.maxReconnectBackoff {
				delay = opts.maxReconnectBackoff
			}

			if opts.onReconnect != nil {
				// Callback runs on the loop goroutine — if it panics, let
				// it propagate so bugs don't hide.
				opts.onReconnect(attempts, delay)
			}

			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}

			newConn, did, err := s.resolveAndConnect(
				ctx, subgroveID, query, subID, opts, lastIndexerDID)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				// Hold the most recent failure in case we eventually give
				// up — then loop around for another backoff + retry.
				lastErr = err
				continue
			}
			conn = newConn
			lastIndexerDID = did
		}
	}
}

func sendCompleteBestEffort(conn *websocket.Conn, subID string) {
	closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = conn.Write(closeCtx, websocket.MessageText,
		mustJSON(map[string]any{"type": "complete", "id": subID}))
}

// pump forwards frames to events until the socket ends or the loop
// context is cancelled. Returns a pumpExit describing how it ended;
// deliveredPayload is true iff at least one real `next` frame was
// forwarded before exit.
func pump(
	ctx context.Context,
	conn *websocket.Conn,
	subID string,
	events chan<- SubscriptionPayload,
) pumpExit {
	deliveredPayload := false
	for {
		select {
		case <-ctx.Done():
			return pumpExit{kind: pumpCancelled, deliveredPayload: deliveredPayload}
		default:
		}

		_, raw, err := conn.Read(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return pumpExit{
					kind:             pumpCancelled,
					deliveredPayload: deliveredPayload,
				}
			}
			// Don't record a clean-close as an error.
			var errToSurface error
			if !isNormalClose(err) {
				errToSurface = err
			}
			return pumpExit{
				kind:             pumpDisconnected,
				deliveredPayload: deliveredPayload,
				err:              errToSurface,
			}
		}

		var frame map[string]any
		if err := json.Unmarshal(raw, &frame); err != nil {
			continue
		}
		t, _ := frame["type"].(string)
		switch t {
		case "next":
			if id, _ := frame["id"].(string); id != subID {
				continue
			}
			payload, _ := frame["payload"].(map[string]any)
			p := SubscriptionPayload{}
			if payload != nil {
				if data, ok := payload["data"].(map[string]any); ok {
					p.Data = data
				}
				if errs, ok := payload["errors"]; ok {
					p.Errors = errs
				}
			}
			select {
			case events <- p:
			case <-ctx.Done():
				return pumpExit{
					kind:             pumpCancelled,
					deliveredPayload: deliveredPayload,
				}
			}
			deliveredPayload = true
		case "complete":
			if id, _ := frame["id"].(string); id == subID {
				return pumpExit{
					kind:             pumpServerComplete,
					deliveredPayload: deliveredPayload,
				}
			}
		case "error":
			if id, _ := frame["id"].(string); id == subID {
				select {
				case events <- SubscriptionPayload{Errors: frame["payload"]}:
				case <-ctx.Done():
					return pumpExit{
						kind:             pumpCancelled,
						deliveredPayload: deliveredPayload,
					}
				}
			}
		case "ping":
			_ = conn.Write(ctx, websocket.MessageText,
				mustJSON(map[string]any{"type": "pong"}))
		}
	}
}

func isNormalClose(err error) bool {
	s := websocket.CloseStatus(err)
	return s == websocket.StatusNormalClosure || s == websocket.StatusGoingAway
}

func httpToWS(url string) string {
	if strings.HasPrefix(url, "https://") {
		return "wss://" + url[len("https://"):]
	}
	if strings.HasPrefix(url, "http://") {
		return "ws://" + url[len("http://"):]
	}
	return url
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		// Only reachable if someone passes a non-JSON-serializable value
		// into opts — which is a programmer error, not a runtime one.
		panic(fmt.Sprintf("subscriptions: failed to marshal frame: %v", err))
	}
	return b
}
