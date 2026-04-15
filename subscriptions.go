package willow

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
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
}

// SubscriptionPayload is a single payload pushed by the server over a
// `next` frame. Mirrors the graphql-transport-ws wire shape.
type SubscriptionPayload struct {
	Data   map[string]any `json:"data,omitempty"`
	Errors any            `json:"errors,omitempty"`
}

// Subscription exposes an incoming stream of SubscriptionPayloads via
// its Events channel. Call Unsubscribe (or cancel the context passed to
// Subscribe) to close.
type Subscription struct {
	// Events emits server `next` payloads. Closed when the subscription
	// ends (server sent `complete`, connection dropped, or Unsubscribe
	// was called). `Err` after close tells you why.
	Events <-chan SubscriptionPayload

	cancel func()
	err    atomic.Value // error
	done   chan struct{}
	conn   *websocket.Conn
	subID  string
}

// Err returns the error that terminated the subscription, or nil if it
// was a clean completion or Unsubscribe. Safe to call after <-Done().
func (s *Subscription) Err() error {
	if e, ok := s.err.Load().(error); ok {
		return e
	}
	return nil
}

// Done is closed when the subscription has fully terminated.
func (s *Subscription) Done() <-chan struct{} { return s.done }

// Unsubscribe sends `complete` to the server and closes the WebSocket.
// Safe to call more than once; the second call is a no-op.
func (s *Subscription) Unsubscribe(ctx context.Context) error {
	s.cancel()
	if s.conn != nil {
		// Best-effort send of `complete`; the server may have already
		// hung up. Either way we close.
		completeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		_ = s.conn.Write(completeCtx, websocket.MessageText,
			mustJSON(map[string]any{"type": "complete", "id": s.subID}))
		_ = s.conn.Close(websocket.StatusNormalClosure, "client unsubscribed")
	}
	<-s.done
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
// Returns after the full connection_init → connection_ack → subscribe
// handshake completes, so connection errors surface to the caller
// rather than later through the Events channel. For
// SubscribeSourceIndexer, the discovery lookup happens inside this
// call.
//
// The returned Subscription's Events channel is closed when the
// subscription ends; check Err() for the termination reason.
func (s *Subscriptions) Subscribe(
	ctx context.Context,
	subgroveID, query string,
	opts *SubscribeOptions,
) (*Subscription, error) {
	if opts == nil {
		opts = &SubscribeOptions{}
	}

	wsURL, err := s.resolveWSURL(ctx, subgroveID, opts.Source)
	if err != nil {
		return nil, err
	}

	dialOpts := &websocket.DialOptions{
		HTTPClient:   s.httpClient,
		Subprotocols: []string{"graphql-transport-ws"},
	}
	conn, _, err := websocket.Dial(ctx, wsURL, dialOpts)
	if err != nil {
		return nil, fmt.Errorf("websocket dial %s: %w", wsURL, err)
	}

	// 1) connection_init
	initPayload := opts.ConnectionPayload
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

	// 2) Wait for connection_ack. Ignore pings that arrive before the ack.
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
	// 3) Send subscribe frame.
	subID := fmt.Sprintf("sub-%d-%d",
		s.counter.Add(1), time.Now().UnixNano())
	subPayload := map[string]any{"query": query}
	if opts.Variables != nil {
		subPayload["variables"] = opts.Variables
	}
	if opts.OperationName != "" {
		subPayload["operationName"] = opts.OperationName
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

	// 4) Spawn the pump goroutine. Buffer the channel modestly so the
	// pump doesn't block on a slow consumer — if the consumer is slow
	// enough to overflow 64, they've likely got other problems.
	events := make(chan SubscriptionPayload, 64)
	pumpCtx, cancel := context.WithCancel(context.Background())
	sub := &Subscription{
		Events: events,
		cancel: cancel,
		done:   make(chan struct{}),
		conn:   conn,
		subID:  subID,
	}

	go pump(pumpCtx, conn, subID, events, sub)
	return sub, nil
}

func (s *Subscriptions) resolveWSURL(
	ctx context.Context, subgroveID string, source SubscribeSource,
) (string, error) {
	if source == SubscribeSourceValidator {
		return httpToWS(s.apiURL) + "/graphql/ws", nil
	}

	// Indexer source.
	if s.indexers == nil {
		return "", fmt.Errorf(
			"source=indexer requires an Indexers client — none provided")
	}
	candidates, err := s.indexers.ForSubgrove(ctx, subgroveID)
	if err != nil {
		return "", fmt.Errorf("indexer discovery: %w", err)
	}
	if len(candidates) == 0 {
		return "", fmt.Errorf(
			"no indexer serves subgrove %q — cannot open indexer subscription",
			subgroveID)
	}
	endpoint := strings.TrimRight(candidates[0].EffectiveQueryEndpoint(), "/")
	return httpToWS(endpoint) + "/graphql/ws", nil
}

// pump runs in its own goroutine, reading frames from the socket and
// fanning matching `next` payloads onto the events channel. Terminates
// on server `complete`, transport error, or ctx cancel.
func pump(
	ctx context.Context,
	conn *websocket.Conn,
	subID string,
	events chan<- SubscriptionPayload,
	sub *Subscription,
) {
	defer close(events)
	defer close(sub.done)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		_, raw, err := conn.Read(ctx)
		if err != nil {
			// Don't record ctx.Done or a clean-close error as an error
			// — those are expected termination signals.
			if ctx.Err() == nil && !isNormalClose(err) {
				sub.err.Store(err)
			}
			return
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
				return
			}
		case "complete":
			if id, _ := frame["id"].(string); id == subID {
				return
			}
		case "error":
			if id, _ := frame["id"].(string); id == subID {
				// Deliver as payload with errors set so callers can
				// distinguish data vs errors via the struct fields.
				select {
				case events <- SubscriptionPayload{
					Errors: frame["payload"],
				}:
				case <-ctx.Done():
					return
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
