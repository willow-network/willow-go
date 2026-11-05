package willow

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// keyRecorder is a server that records the X-API-Key of each request, by
// path, and answers a SQL query.
type keyRecorder struct {
	*httptest.Server
	mu   sync.Mutex
	keys map[string][]string
}

func newKeyRecorder(t *testing.T, serve func(w http.ResponseWriter, r *http.Request) bool) *keyRecorder {
	t.Helper()
	k := &keyRecorder{keys: map[string][]string{}}
	k.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		k.mu.Lock()
		k.keys[r.URL.Path] = append(k.keys[r.URL.Path], r.Header.Get("X-API-Key"))
		k.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if serve != nil && serve(w, r) {
			return
		}
		if r.URL.Path == "/sql/sg" {
			_, _ = w.Write([]byte(`{"columns":["a"],"rows":[[1]]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(k.Close)
	return k
}

func (k *keyRecorder) seen() map[string][]string {
	k.mu.Lock()
	defer k.mu.Unlock()
	out := map[string][]string{}
	for p, keys := range k.keys {
		out[p] = append([]string(nil), keys...)
	}
	return out
}

// The managed API key goes to the API and to the indexer named with
// WithIndexerURL, and never to an indexer the SDK discovers from the API's
// /indexers list: anyone can register an indexer, and its endpoint would
// receive the key of every caller that queries or subscribes through it.
func TestAPIKeyGoesOnlyToTheAPIAndTheNamedIndexer(t *testing.T) {
	ctx := context.Background()
	discovered := newKeyRecorder(t, nil)
	api := newKeyRecorder(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/indexers" {
			return false
		}
		list, _ := json.Marshal([]IndexerInfo{{IndexerDID: "did:willow:x", Subgroves: []string{"sg"},
			Endpoint: discovered.URL, QueryEndpoint: discovered.URL, Status: "active", PerformanceScore: 1}})
		_, _ = w.Write([]byte(`{"success":true,"data":` + string(list) + `,"error":null}`))
		return true
	})
	client, err := NewClient(api.URL, WithAPIKey("secret"))
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []QuerySource{QuerySourceAuto, QuerySourceIndexer} {
		got, err := client.Indexing.SqlQueryWithSource(ctx, "sg", "SELECT a", false, source)
		if err != nil || got.Source != ServedByIndexer {
			t.Fatalf("source %v: %+v, %v; want the discovered indexer's answer", source, got, err)
		}
	}
	if got, err := client.Indexing.SqlQueryWithSource(ctx, "sg", "SELECT a", false, QuerySourceValidator); err != nil || got.Source != ServedByValidator {
		t.Fatalf("source validator: %+v, %v", got, err)
	}
	_, _ = client.Subscriptions.Subscribe(ctx, "sg", "subscription { a }",
		&SubscribeOptions{Source: SubscribeSourceIndexer, Reconnect: BoolPtr(false)})
	_, _ = client.Subscriptions.Subscribe(ctx, "sg", "subscription { a }", &SubscribeOptions{Reconnect: BoolPtr(false)})

	for path, keys := range discovered.seen() {
		for _, key := range keys {
			if key != "" {
				t.Errorf("the discovered indexer received the API key on %s", path)
			}
		}
	}
	if keys := discovered.seen()["/graphql/ws"]; len(keys) == 0 {
		t.Error("the indexer subscription never reached the discovered indexer")
	}
	for _, path := range []string{"/indexers", "/sql/sg", "/graphql/ws"} {
		keys := api.seen()[path]
		if len(keys) == 0 {
			t.Errorf("nothing reached the API on %s", path)
		}
		for _, key := range keys {
			if key != "secret" {
				t.Errorf("the API received key %q on %s, want the API key", key, path)
			}
		}
	}

	// An indexer named with WithIndexerURL is the caller's choice: it gets
	// the key, whichever option comes first.
	named := newKeyRecorder(t, nil)
	for _, opts := range [][]ClientOption{
		{WithAPIKey("secret"), WithIndexerURL(named.URL)},
		{WithIndexerURL(named.URL), WithAPIKey("secret")},
	} {
		client, err := NewClient(api.URL, opts...)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Indexing.SqlQuery(ctx, "sg", "SELECT a", false); err != nil {
			t.Fatal(err)
		}
	}
	if keys := named.seen()["/sql/sg"]; len(keys) != 2 || keys[0] != "secret" || keys[1] != "secret" {
		t.Errorf("the named indexer received keys %q, want the API key twice", keys)
	}
}
