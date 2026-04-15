package willow

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// runFakeWSServer spins up an in-process graphql-transport-ws server
// that drives connection_init → connection_ack → subscribe and then
// hands off to onSubscribe for the per-subscription script.
//
// Returns an httptest.Server that wraps the handler. Callers use
// s.URL as the apiURL passed into the SDK.
func runFakeWSServer(
	t *testing.T,
	onSubscribe func(ctx context.Context, conn *websocket.Conn, subID string),
) *httptest.Server {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			Subprotocols: []string{"graphql-transport-ws"},
		})
		if err != nil {
			t.Logf("ws accept failed: %v", err)
			return
		}
		ctx := r.Context()
		defer conn.Close(websocket.StatusNormalClosure, "bye")

		// connection_init
		_, raw, err := conn.Read(ctx)
		if err != nil {
			return
		}
		var init map[string]any
		_ = json.Unmarshal(raw, &init)
		if init["type"] != "connection_init" {
			return
		}
		_ = conn.Write(ctx, websocket.MessageText,
			mustJSON(map[string]any{"type": "connection_ack"}))

		// subscribe
		_, raw, err = conn.Read(ctx)
		if err != nil {
			return
		}
		var sub map[string]any
		_ = json.Unmarshal(raw, &sub)
		if sub["type"] != "subscribe" {
			return
		}
		subID, _ := sub["id"].(string)

		onSubscribe(ctx, conn, subID)
	})
	return httptest.NewServer(handler)
}

func subsForTest(apiURL string) *Subscriptions {
	indexers := NewIndexers(http.DefaultClient, apiURL, "")
	return NewSubscriptions(apiURL, indexers, http.DefaultClient)
}

func TestValidatorSubscriptionDeliversNextPayloads(t *testing.T) {
	server := runFakeWSServer(t, func(ctx context.Context, conn *websocket.Conn, subID string) {
		for i := 0; i < 2; i++ {
			_ = conn.Write(ctx, websocket.MessageText, mustJSON(map[string]any{
				"type":    "next",
				"id":      subID,
				"payload": map[string]any{"data": map[string]any{"tick": i}},
			}))
		}
		_ = conn.Write(ctx, websocket.MessageText, mustJSON(map[string]any{
			"type": "complete", "id": subID,
		}))
		// Give the client time to drain frames before our handler
		// returns and closes the socket.
		time.Sleep(50 * time.Millisecond)
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	subs := subsForTest(server.URL)
	sub, err := subs.Subscribe(ctx, "my-subgrove", "subscription { tick }", nil)
	if err != nil {
		t.Fatalf("Subscribe failed: %v", err)
	}

	got := []SubscriptionPayload{}
	for p := range sub.Events {
		got = append(got, p)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 payloads, got %d", len(got))
	}
	// `data` values come back as JSON numbers (float64) — not ints.
	if got[0].Data["tick"].(float64) != 0 {
		t.Fatalf("first tick mismatch: %+v", got[0].Data)
	}
	if got[1].Data["tick"].(float64) != 1 {
		t.Fatalf("second tick mismatch: %+v", got[1].Data)
	}
	if err := sub.Err(); err != nil {
		t.Fatalf("unexpected error after clean complete: %v", err)
	}
}

func TestUnsubscribeClosesTheStream(t *testing.T) {
	// After Unsubscribe, the Events channel should close within a
	// reasonable timeout — the contract callers depend on.
	server := runFakeWSServer(t, func(ctx context.Context, conn *websocket.Conn, subID string) {
		// Send one payload then sit idle. The client will unsubscribe
		// before we send anything else.
		_ = conn.Write(ctx, websocket.MessageText, mustJSON(map[string]any{
			"type":    "next",
			"id":      subID,
			"payload": map[string]any{"data": map[string]any{"tick": 0}},
		}))
		// Read whatever the client sends; the connection ends when the
		// client closes or our handler returns.
		for {
			if _, _, err := conn.Read(ctx); err != nil {
				return
			}
		}
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	subs := subsForTest(server.URL)
	sub, err := subs.Subscribe(ctx, "my-subgrove", "subscription { tick }", nil)
	if err != nil {
		t.Fatalf("Subscribe failed: %v", err)
	}

	// Consume the expected payload.
	select {
	case p, ok := <-sub.Events:
		if !ok || p.Data["tick"].(float64) != 0 {
			t.Fatalf("unexpected first payload: %+v ok=%v", p, ok)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for first payload")
	}

	if err := sub.Unsubscribe(ctx); err != nil {
		t.Fatalf("Unsubscribe failed: %v", err)
	}
	// Events should now be closed.
	select {
	case _, ok := <-sub.Events:
		if ok {
			t.Fatal("Events should be closed after Unsubscribe")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Events did not close within timeout")
	}
}

func TestVariablesAndOperationNameFlowThrough(t *testing.T) {
	// Capture the subscribe frame the SDK sends.
	captured := make(chan map[string]any, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			Subprotocols: []string{"graphql-transport-ws"},
		})
		if err != nil {
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "bye")
		ctx := r.Context()

		_, _, _ = conn.Read(ctx) // connection_init
		_ = conn.Write(ctx, websocket.MessageText,
			mustJSON(map[string]any{"type": "connection_ack"}))

		_, raw, err := conn.Read(ctx) // subscribe
		if err != nil {
			return
		}
		var sub map[string]any
		_ = json.Unmarshal(raw, &sub)
		captured <- sub

		// Send one payload then complete so the iterator terminates.
		subID, _ := sub["id"].(string)
		_ = conn.Write(ctx, websocket.MessageText, mustJSON(map[string]any{
			"type":    "next",
			"id":      subID,
			"payload": map[string]any{"data": map[string]any{}},
		}))
		_ = conn.Write(ctx, websocket.MessageText, mustJSON(map[string]any{
			"type": "complete", "id": subID,
		}))
		time.Sleep(50 * time.Millisecond)
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	subs := subsForTest(server.URL)
	sub, err := subs.Subscribe(ctx, "my-subgrove",
		"subscription Foo($a: String) { x(a: $a) }",
		&SubscribeOptions{
			Variables:     map[string]any{"a": "hello"},
			OperationName: "Foo",
		})
	if err != nil {
		t.Fatalf("Subscribe failed: %v", err)
	}
	for range sub.Events {
		// drain
	}

	select {
	case sent := <-captured:
		payload, _ := sent["payload"].(map[string]any)
		if payload == nil {
			t.Fatalf("subscribe payload missing: %+v", sent)
		}
		if vars, ok := payload["variables"].(map[string]any); !ok || vars["a"] != "hello" {
			t.Fatalf("variables did not propagate: %+v", payload["variables"])
		}
		if op, _ := payload["operationName"].(string); op != "Foo" {
			t.Fatalf("operationName did not propagate: %v", payload["operationName"])
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for captured subscribe frame")
	}
}

func TestServerPingGetsPong(t *testing.T) {
	pongSeen := make(chan struct{}, 1)
	server := runFakeWSServer(t, func(ctx context.Context, conn *websocket.Conn, _ string) {
		_ = conn.Write(ctx, websocket.MessageText,
			mustJSON(map[string]any{"type": "ping"}))
		for {
			_, raw, err := conn.Read(ctx)
			if err != nil {
				return
			}
			var frame map[string]any
			if json.Unmarshal(raw, &frame) == nil && frame["type"] == "pong" {
				select {
				case pongSeen <- struct{}{}:
				default:
				}
				return
			}
		}
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	subs := subsForTest(server.URL)
	sub, err := subs.Subscribe(ctx, "my-subgrove", "subscription { tick }", nil)
	if err != nil {
		t.Fatalf("Subscribe failed: %v", err)
	}
	defer sub.Unsubscribe(ctx)

	select {
	case <-pongSeen:
	case <-time.After(1 * time.Second):
		t.Fatal("server never saw a pong in response to its ping")
	}
}

func TestIndexerSourceErrorsWhenNoIndexerServesSubgrove(t *testing.T) {
	// Point the "API URL" at a dead address so discovery fails.
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	subs := subsForTest("http://127.0.0.1:1")
	_, err := subs.Subscribe(ctx, "my-subgrove", "subscription { x }",
		&SubscribeOptions{Source: SubscribeSourceIndexer})
	if err == nil {
		t.Fatal("expected Subscribe to fail when no indexer is reachable")
	}
}

// ---------------------------------------------------------------------------
// Reconnect tests
//
// These use a scripted handler whose per-connection behavior is driven
// by a counter — tests say things like "drop connection #1 after one
// payload; on connection #2 send two payloads then complete".
// ---------------------------------------------------------------------------

// runScriptedWSServer is like runFakeWSServer but also hands the
// per-connection index to onSubscribe so tests can script each
// reconnect attempt independently. Returns the server and the counter.
func runScriptedWSServer(
	t *testing.T,
	onSubscribe func(ctx context.Context, conn *websocket.Conn, subID string, connIdx int),
) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var counter atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idx := int(counter.Add(1)) - 1
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			Subprotocols: []string{"graphql-transport-ws"},
		})
		if err != nil {
			return
		}
		ctx := r.Context()

		_, _, err = conn.Read(ctx)
		if err != nil {
			return
		}
		_ = conn.Write(ctx, websocket.MessageText,
			mustJSON(map[string]any{"type": "connection_ack"}))

		_, raw, err := conn.Read(ctx)
		if err != nil {
			return
		}
		var sub map[string]any
		_ = json.Unmarshal(raw, &sub)
		subID, _ := sub["id"].(string)

		onSubscribe(ctx, conn, subID, idx)
	})
	return httptest.NewServer(handler), &counter
}

func TestReconnectsOnUnexpectedDisconnect(t *testing.T) {
	// Conn #0: one payload then drop; conn #1: second payload then
	// complete. The SDK should reconnect transparently and deliver both.
	server, _ := runScriptedWSServer(t, func(
		ctx context.Context, conn *websocket.Conn, subID string, idx int,
	) {
		switch idx {
		case 0:
			_ = conn.Write(ctx, websocket.MessageText, mustJSON(map[string]any{
				"type":    "next",
				"id":      subID,
				"payload": map[string]any{"data": map[string]any{"tick": 0}},
			}))
			time.Sleep(20 * time.Millisecond)
			// Simulate an abnormal close.
			_ = conn.Close(websocket.StatusInternalError, "drop")
		case 1:
			_ = conn.Write(ctx, websocket.MessageText, mustJSON(map[string]any{
				"type":    "next",
				"id":      subID,
				"payload": map[string]any{"data": map[string]any{"tick": 1}},
			}))
			_ = conn.Write(ctx, websocket.MessageText, mustJSON(map[string]any{
				"type": "complete", "id": subID,
			}))
			time.Sleep(50 * time.Millisecond)
		}
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	subs := subsForTest(server.URL)
	sub, err := subs.Subscribe(ctx, "my-subgrove", "subscription { tick }",
		&SubscribeOptions{
			ReconnectBackoff:    10 * time.Millisecond,
			MaxReconnectBackoff: 50 * time.Millisecond,
		})
	if err != nil {
		t.Fatalf("Subscribe failed: %v", err)
	}

	got := []float64{}
	for p := range sub.Events {
		got = append(got, p.Data["tick"].(float64))
	}

	if len(got) != 2 || got[0] != 0 || got[1] != 1 {
		t.Fatalf("expected ticks [0,1] across reconnect, got %v", got)
	}
	if err := sub.Err(); err != nil {
		t.Fatalf("unexpected error after clean complete: %v", err)
	}
}

func TestDoesNotReconnectWhenReconnectIsFalse(t *testing.T) {
	// Drop every connection after one payload. With Reconnect=false the
	// SDK should accept exactly one drop and terminate.
	server, counter := runScriptedWSServer(t, func(
		ctx context.Context, conn *websocket.Conn, subID string, idx int,
	) {
		_ = conn.Write(ctx, websocket.MessageText, mustJSON(map[string]any{
			"type":    "next",
			"id":      subID,
			"payload": map[string]any{"data": map[string]any{"tick": idx}},
		}))
		time.Sleep(20 * time.Millisecond)
		_ = conn.Close(websocket.StatusInternalError, "drop")
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	subs := subsForTest(server.URL)
	sub, err := subs.Subscribe(ctx, "my-subgrove", "subscription { tick }",
		&SubscribeOptions{Reconnect: BoolPtr(false)})
	if err != nil {
		t.Fatalf("Subscribe failed: %v", err)
	}

	got := []float64{}
	for p := range sub.Events {
		got = append(got, p.Data["tick"].(float64))
	}

	if len(got) != 1 || got[0] != 0 {
		t.Fatalf("expected exactly [0], got %v", got)
	}
	if c := counter.Load(); c != 1 {
		t.Fatalf("expected exactly one connection, got %d", c)
	}
}

func TestGivesUpAfterMaxReconnectAttempts(t *testing.T) {
	// Server accepts every handshake but drops before delivering any
	// payload. Without the "reset attempts only on delivered payload"
	// rule this would loop forever. With the rule, the SDK stops after
	// MaxReconnectAttempts reconnects (total = 1 initial + 2 retries).
	server, counter := runScriptedWSServer(t, func(
		ctx context.Context, conn *websocket.Conn, _ string, _ int,
	) {
		time.Sleep(10 * time.Millisecond)
		_ = conn.Close(websocket.StatusInternalError, "drop-without-payload")
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	subs := subsForTest(server.URL)
	sub, err := subs.Subscribe(ctx, "my-subgrove", "subscription { tick }",
		&SubscribeOptions{
			MaxReconnectAttempts: 2,
			ReconnectBackoff:     10 * time.Millisecond,
			MaxReconnectBackoff:  50 * time.Millisecond,
		})
	if err != nil {
		t.Fatalf("Subscribe failed: %v", err)
	}

	// Drain events (there should be none) and wait for done.
	got := 0
	for range sub.Events {
		got++
	}
	if got != 0 {
		t.Fatalf("expected no payloads, got %d", got)
	}
	if c := counter.Load(); c != 3 {
		t.Fatalf("expected 3 total connections (1 initial + 2 retries), got %d", c)
	}
}

func TestUnsubscribeDuringBackoffCancelsReconnect(t *testing.T) {
	// Conn #0 drops fast; the SDK enters a 1-second backoff. We
	// unsubscribe mid-backoff and verify that no second connection is
	// ever accepted.
	serverReady := make(chan struct{}, 1)
	server, counter := runScriptedWSServer(t, func(
		ctx context.Context, conn *websocket.Conn, _ string, idx int,
	) {
		if idx == 0 {
			time.Sleep(20 * time.Millisecond)
			select {
			case serverReady <- struct{}{}:
			default:
			}
			_ = conn.Close(websocket.StatusInternalError, "drop")
			return
		}
		// Second connection would indicate the cancellation didn't work;
		// sit idle so the test can detect it.
		<-ctx.Done()
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	subs := subsForTest(server.URL)
	sub, err := subs.Subscribe(ctx, "my-subgrove", "subscription { tick }",
		&SubscribeOptions{
			ReconnectBackoff:    1 * time.Second,
			MaxReconnectBackoff: 1 * time.Second,
		})
	if err != nil {
		t.Fatalf("Subscribe failed: %v", err)
	}

	// Wait for the server-side drop, then unsubscribe during the backoff.
	select {
	case <-serverReady:
	case <-time.After(1 * time.Second):
		t.Fatal("server handler never reported the drop")
	}
	time.Sleep(10 * time.Millisecond)
	if err := sub.Unsubscribe(ctx); err != nil {
		t.Fatalf("Unsubscribe: %v", err)
	}

	if c := counter.Load(); c != 1 {
		t.Fatalf("expected exactly 1 connection (no reconnect after cancel), got %d", c)
	}
}
