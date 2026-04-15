package willow

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
