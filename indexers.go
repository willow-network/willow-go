package willow

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"
)

// QuerySource tells the routing layer where to send a query.
//
//   - QuerySourceValidator: consensus-verified chain-tip. Every row is
//     Merkle-provable. Fails fast for VerifyOnly subgroves.
//   - QuerySourceIndexer: full history + analytics via an indexer.
//   - QuerySourceAuto (default): indexer if one serves this subgrove, else
//     validator. Sets Fallback=true when it falls back.
type QuerySource int

const (
	QuerySourceAuto QuerySource = iota
	QuerySourceValidator
	QuerySourceIndexer
)

// ServedBy tells the caller which backend actually served a query.
type ServedBy int

const (
	ServedByValidator ServedBy = iota
	ServedByIndexer
)

func (s ServedBy) String() string {
	switch s {
	case ServedByIndexer:
		return "indexer"
	default:
		return "validator"
	}
}

// RoutedQueryResult wraps a query response with routing metadata.
//
// Callers get back both the raw result and an explicit tag identifying
// which backend served it — useful for UIs that want to display the trust
// model.
type RoutedQueryResult[T any] struct {
	Result     T
	Source     ServedBy
	IndexerDID string // Empty when Source == ServedByValidator
	Fallback   bool   // True when Auto routing fell back from indexer to validator
}

// DefaultCacheTTL is how long a successful /indexers response is reused
// before the SDK re-fetches.
const DefaultCacheTTL = 30 * time.Second

// Indexers is a discovery client for the validator's GET /indexers endpoint.
//
// When the SDK is constructed with an explicit indexerURL, discovery is
// bypassed and a synthetic single-entry list is returned so the routing
// code path stays uniform.
type Indexers struct {
	httpClient  *http.Client
	apiURL      string
	indexerURL  string
	cacheTTL    time.Duration
	mu          sync.Mutex
	cache       []IndexerInfo
	cacheTaken  bool
	cacheFilled time.Time
}

// NewIndexers constructs a discovery client. Normally called by the
// WillowClient builder — consumers access it through client.Indexers().
func NewIndexers(httpClient *http.Client, apiURL, indexerURL string) *Indexers {
	return &Indexers{
		httpClient: httpClient,
		apiURL:     apiURL,
		indexerURL: indexerURL,
		cacheTTL:   DefaultCacheTTL,
	}
}

// HasExplicitOverride reports whether an explicit indexer URL was provided
// (in which case discovery is skipped).
func (d *Indexers) HasExplicitOverride() bool {
	return d.indexerURL != ""
}

// Invalidate forces the next List to re-fetch from the validator.
func (d *Indexers) Invalidate() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cacheTaken = false
	d.cache = nil
}

// Evict drops a specific indexer from the cache (e.g., after a 5xx).
func (d *Indexers) Evict(indexerDID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cache == nil {
		return
	}
	out := d.cache[:0]
	for _, i := range d.cache {
		if i.IndexerDID != indexerDID {
			out = append(out, i)
		}
	}
	d.cache = out
}

// List returns all registered indexers, cached for cacheTTL.
func (d *Indexers) List(ctx context.Context) ([]IndexerInfo, error) {
	if d.indexerURL != "" {
		return []IndexerInfo{syntheticEntry(d.indexerURL)}, nil
	}

	d.mu.Lock()
	if d.cacheTaken && time.Since(d.cacheFilled) < d.cacheTTL {
		cached := make([]IndexerInfo, len(d.cache))
		copy(cached, d.cache)
		d.mu.Unlock()
		return cached, nil
	}
	d.mu.Unlock()

	url := d.apiURL + "/indexers"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("build /indexers request: %w", err)
	}
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch /indexers: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("/indexers returned status %d", resp.StatusCode)
	}
	var envelope struct {
		Success bool          `json:"success"`
		Data    []IndexerInfo `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("decode /indexers response: %w", err)
	}

	d.mu.Lock()
	d.cache = envelope.Data
	d.cacheTaken = true
	d.cacheFilled = time.Now()
	out := make([]IndexerInfo, len(envelope.Data))
	copy(out, envelope.Data)
	d.mu.Unlock()
	return out, nil
}

// ForSubgrove returns active indexers serving subgroveID, sorted by
// PerformanceScore descending (best first).
//
// With an explicit indexerURL override, always returns a single synthetic
// entry — the routing code doesn't need to special-case this.
func (d *Indexers) ForSubgrove(ctx context.Context, subgroveID string) ([]IndexerInfo, error) {
	if d.indexerURL != "" {
		return []IndexerInfo{syntheticEntry(d.indexerURL)}, nil
	}
	all, err := d.List(ctx)
	if err != nil {
		return nil, err
	}
	picks := make([]IndexerInfo, 0, len(all))
	for _, i := range all {
		if i.Status != "active" {
			continue
		}
		for _, sg := range i.Subgroves {
			if sg == subgroveID {
				picks = append(picks, i)
				break
			}
		}
	}
	sort.SliceStable(picks, func(a, b int) bool {
		return picks[a].PerformanceScore > picks[b].PerformanceScore
	})
	return picks, nil
}

func syntheticEntry(url string) IndexerInfo {
	return IndexerInfo{
		IndexerDID:       "explicit-override",
		Subgroves:        nil,
		StakeAmount:      0,
		Endpoint:         url,
		QueryEndpoint:    url,
		Status:           "active",
		PerformanceScore: 100,
		LastUpdate:       0,
	}
}

// ValidatorHasNoDataError is returned when QuerySourceValidator was
// requested but the validator has no data for the subgrove (VerifyOnly
// retention, pruned, or not indexed).
type ValidatorHasNoDataError struct {
	SubgroveID string
	Reason     string
}

func (e *ValidatorHasNoDataError) Error() string {
	return fmt.Sprintf("validator cannot serve data for subgrove %q: %s", e.SubgroveID, e.Reason)
}

// NoIndexersReachableError is returned when QuerySourceIndexer was
// requested but either no indexer serves the subgrove or every candidate
// failed.
type NoIndexersReachableError struct {
	SubgroveID string
	Details    string
}

func (e *NoIndexersReachableError) Error() string {
	return fmt.Sprintf("no indexer could serve subgrove %q: %s", e.SubgroveID, e.Details)
}
