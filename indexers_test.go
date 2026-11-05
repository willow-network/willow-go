package willow

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/willow-network/willow-go/consensus"
)

func info(did string, subgroves []string, perf float64, status string) IndexerInfo {
	return IndexerInfo{
		IndexerDID:       did,
		Subgroves:        subgroves,
		StakeAmount:      consensus.NewUint128(100),
		Endpoint:         "http://" + did + ":9090",
		QueryEndpoint:    "http://" + did + ":3032",
		Status:           status,
		PerformanceScore: perf,
	}
}

func TestEffectiveQueryEndpointPrefersQueryEndpoint(t *testing.T) {
	i := info("x", []string{"sg"}, 100, "active")
	if got := i.EffectiveQueryEndpoint(); got != "http://x:3032" {
		t.Fatalf("got %q, want http://x:3032", got)
	}
}

func TestEffectiveQueryEndpointFallsBackToEndpoint(t *testing.T) {
	i := info("x", []string{"sg"}, 100, "active")
	i.QueryEndpoint = ""
	if got := i.EffectiveQueryEndpoint(); got != "http://x:9090" {
		t.Fatalf("got %q, want http://x:9090", got)
	}
}

func TestExplicitOverrideReturnsSyntheticEntry(t *testing.T) {
	// Guard: even if /indexers would return something, the override must win.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("override should skip discovery, but /indexers was hit: %s", r.URL.Path)
	}))
	defer server.Close()

	disc := NewIndexers(http.DefaultClient, server.URL, "http://pinned:3032")
	if !disc.HasExplicitOverride() {
		t.Fatal("expected override")
	}
	all, err := disc.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].EffectiveQueryEndpoint() != "http://pinned:3032" {
		t.Fatalf("bad synthetic entry: %+v", all)
	}
	picks, err := disc.ForSubgrove(context.Background(), "any")
	if err != nil {
		t.Fatal(err)
	}
	if len(picks) != 1 {
		t.Fatalf("expected 1 pick, got %d", len(picks))
	}
}

func TestListFetchesFromValidator(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/indexers" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		calls++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"data": []IndexerInfo{
				info("a", []string{"sg-1"}, 90, "active"),
			},
		})
	}))
	defer server.Close()

	disc := NewIndexers(http.DefaultClient, server.URL, "")
	first, err := disc.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 || first[0].IndexerDID != "a" {
		t.Fatalf("bad list: %+v", first)
	}

	// Second call must hit cache (TTL = 30s by default)
	if _, err := disc.List(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("expected caching, got %d HTTP calls", calls)
	}
}

func TestForSubgroveFiltersAndSorts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"data": []IndexerInfo{
				info("slow", []string{"sg-shared"}, 40, "active"),
				info("fast", []string{"sg-shared"}, 99, "active"),
				info("other", []string{"sg-other"}, 100, "active"),
				info("inactive", []string{"sg-shared"}, 100, "inactive"),
			},
		})
	}))
	defer server.Close()

	disc := NewIndexers(http.DefaultClient, server.URL, "")
	picks, err := disc.ForSubgrove(context.Background(), "sg-shared")
	if err != nil {
		t.Fatal(err)
	}
	if len(picks) != 2 {
		t.Fatalf("expected 2 picks (fast, slow), got %d", len(picks))
	}
	if picks[0].IndexerDID != "fast" || picks[1].IndexerDID != "slow" {
		t.Fatalf("wrong order: %+v", picks)
	}
}

func TestEvictDropsFromCache(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"data": []IndexerInfo{
				info("a", []string{"sg"}, 100, "active"),
				info("b", []string{"sg"}, 50, "active"),
			},
		})
	}))
	defer server.Close()

	disc := NewIndexers(http.DefaultClient, server.URL, "")
	if _, err := disc.List(context.Background()); err != nil {
		t.Fatal(err)
	}
	disc.Evict("a")
	picks, err := disc.ForSubgrove(context.Background(), "sg")
	if err != nil {
		t.Fatal(err)
	}
	if len(picks) != 1 || picks[0].IndexerDID != "b" {
		t.Fatalf("eviction did not drop 'a': %+v", picks)
	}
}

func TestErrorTypesHaveContext(t *testing.T) {
	v := &ValidatorHasNoDataError{SubgroveID: "sg-x", Reason: "VerifyOnly"}
	if v.Error() == "" {
		t.Fatal("empty Error()")
	}
	if v.SubgroveID != "sg-x" {
		t.Fatal("missing subgrove id")
	}

	n := &NoIndexersReachableError{SubgroveID: "sg-x", Details: "timed out"}
	if n.Error() == "" {
		t.Fatal("empty Error()")
	}
}

// A routed query tries at most the three best-scored indexers serving the
// subgrove, so a registry listing many failing indexers can't make one query
// send many requests; Auto then falls back to the API.
func TestRoutedQueryTriesAtMostThreeIndexers(t *testing.T) {
	var mu sync.Mutex
	tried := map[string]int{}
	var indexers []IndexerInfo
	for i := 0; i < 6; i++ {
		did := fmt.Sprintf("did:willow:i%d", i)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			tried[did]++
			mu.Unlock()
			w.WriteHeader(http.StatusNotFound)
		}))
		t.Cleanup(srv.Close)
		indexers = append(indexers, IndexerInfo{IndexerDID: did, Subgroves: []string{"sg"}, Endpoint: srv.URL,
			QueryEndpoint: srv.URL, Status: "active", PerformanceScore: float64(i)})
	}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/indexers" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "data": indexers})
			return
		}
		_, _ = w.Write([]byte(`{"columns":["a"],"rows":[[1]]}`))
	}))
	t.Cleanup(api.Close)
	client, err := NewClient(api.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := client.Indexing.SqlQueryWithSource(ctx, "sg", "SELECT a", false, QuerySourceIndexer); err == nil {
		t.Fatal("every indexer failed, yet the query succeeded")
	}
	got, err := client.Indexing.SqlQueryWithSource(ctx, "sg", "SELECT a", false, QuerySourceAuto)
	if err != nil || got.Source != ServedByValidator || !got.Fallback {
		t.Fatalf("auto: %+v, %v; want the API's answer after the fallback", got, err)
	}
	mu.Lock()
	defer mu.Unlock()
	want := map[string]int{"did:willow:i5": 2, "did:willow:i4": 2, "did:willow:i3": 2}
	if fmt.Sprint(tried) != fmt.Sprint(want) {
		t.Fatalf("indexers tried %v, want the three best twice each: %v", tried, want)
	}
}
