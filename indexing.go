package willow

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/willow-network/willow-go/grovedb"
)

// IndexingOperations provides methods for blockchain indexing and GraphQL queries.
type IndexingOperations struct {
	client *Client
}

// Query executes a GraphQL query against a subgrove.
// When an indexer URL is configured, the query is routed there.
func (i *IndexingOperations) Query(ctx context.Context, subgroveID string, req *GraphQLRequest) (*GraphQLResponse, error) {
	// Enable proof by default if light client is available
	if i.client.HasLightClient() {
		req.IncludeProof = true
	}

	baseURL := i.client.IndexerBaseURL()
	url := fmt.Sprintf("%s/graphql/%s", baseURL, subgroveID)

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal GraphQL request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := i.client.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("GraphQL query request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GraphQL query failed with status %d", resp.StatusCode)
	}

	var response GraphQLResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode GraphQL response: %w", err)
	}

	// Verify proof if available
	if i.client.HasLightClient() && len(response.Proof) > 0 {
		if err := i.verifyProof(ctx, response.Proof); err != nil {
			return nil, NewProofError(fmt.Sprintf("proof verification failed: %v", err))
		}
	}

	return &response, nil
}

// QueryUnverified executes a GraphQL query without proof verification (faster).
func (i *IndexingOperations) QueryUnverified(ctx context.Context, subgroveID string, req *GraphQLRequest) (*GraphQLResponse, error) {
	req.IncludeProof = false

	path := fmt.Sprintf("/graphql/%s", subgroveID)
	var response GraphQLResponse
	err := i.client.post(ctx, path, req, &response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

// Execute is a convenience method for executing GraphQL queries.
func (i *IndexingOperations) Execute(ctx context.Context, subgroveID, query string, variables map[string]interface{}) (*GraphQLResponse, error) {
	return i.Query(ctx, subgroveID, &GraphQLRequest{
		Query:     query,
		Variables: variables,
	})
}

// GraphQLQueryWithSource executes a GraphQL query with explicit source selection.
//
// Callers declare the trust model via QuerySource:
//   - QuerySourceValidator: consensus-verified chain-tip. Returns a
//     *ValidatorHasNoDataError for VerifyOnly subgroves.
//   - QuerySourceIndexer: historical/analytics via an indexer. Returns a
//     *NoIndexersReachableError if none are reachable.
//   - QuerySourceAuto (default): indexer if one serves this subgrove, else
//     validator. On indexer failure, falls back to validator with
//     Fallback=true in the returned result.
func (i *IndexingOperations) GraphQLQueryWithSource(
	ctx context.Context,
	subgroveID string,
	req *GraphQLRequest,
	source QuerySource,
) (*RoutedQueryResult[*GraphQLResponse], error) {
	bodyBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal GraphQL request: %w", err)
	}
	return routeQuery[*GraphQLResponse](
		ctx, i.client, "graphql", subgroveID, bodyBytes, source,
	)
}

// SqlQueryWithSource executes a SQL query with explicit source selection.
//
// See GraphQLQueryWithSource for source semantics.
func (i *IndexingOperations) SqlQueryWithSource(
	ctx context.Context,
	subgroveID, query string,
	includeProof bool,
	source QuerySource,
) (*RoutedQueryResult[*SqlResponse], error) {
	req := SqlRequest{
		Query:        query,
		IncludeProof: &includeProof,
	}
	bodyBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal SQL request: %w", err)
	}
	return routeQuery[*SqlResponse](
		ctx, i.client, "sql", subgroveID, bodyBytes, source,
	)
}

// routeQuery is the shared routing helper used by both GraphQL and SQL
// source-routed variants.
func routeQuery[T any](
	ctx context.Context,
	c *Client,
	pathPrefix, subgroveID string,
	body []byte,
	source QuerySource,
) (*RoutedQueryResult[T], error) {
	path := fmt.Sprintf("/%s/%s", pathPrefix, subgroveID)

	callValidator := func() (T, error) {
		var zero T
		url := c.baseURL.String() + path
		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
		if err != nil {
			return zero, fmt.Errorf("build validator request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.httpClient.Do(req)
		if err != nil {
			return zero, fmt.Errorf("validator request: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusForbidden {
			return zero, &ValidatorHasNoDataError{
				SubgroveID: subgroveID,
				Reason:     fmt.Sprintf("HTTP %d", resp.StatusCode),
			}
		}
		if resp.StatusCode != http.StatusOK {
			return zero, fmt.Errorf("validator returned %d", resp.StatusCode)
		}
		// Validator wraps responses in { success, data }; indexer doesn't.
		// Decode into a union envelope that handles both shapes.
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			return zero, fmt.Errorf("read validator response: %w", err)
		}
		return unwrapResponse[T](raw)
	}

	callIndexer := func(info IndexerInfo) (T, error) {
		var zero T
		endpoint := strings.TrimRight(info.EffectiveQueryEndpoint(), "/")
		url := endpoint + path
		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
		if err != nil {
			return zero, fmt.Errorf("build indexer request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.httpClient.Do(req)
		if err != nil {
			return zero, fmt.Errorf("indexer request: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 500 {
			c.Indexers.Evict(info.IndexerDID)
			return zero, fmt.Errorf("indexer returned %d", resp.StatusCode)
		}
		if resp.StatusCode != http.StatusOK {
			return zero, fmt.Errorf("indexer returned %d", resp.StatusCode)
		}
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			return zero, fmt.Errorf("read indexer response: %w", err)
		}
		return unwrapResponse[T](raw)
	}

	switch source {
	case QuerySourceValidator:
		result, err := callValidator()
		if err != nil {
			return nil, err
		}
		return &RoutedQueryResult[T]{Result: result, Source: ServedByValidator}, nil

	case QuerySourceIndexer:
		candidates, err := c.Indexers.ForSubgrove(ctx, subgroveID)
		if err != nil {
			return nil, err
		}
		if len(candidates) == 0 {
			return nil, &NoIndexersReachableError{
				SubgroveID: subgroveID,
				Details:    "no indexer in the registry serves this subgrove",
			}
		}
		var errs []string
		for _, info := range candidates {
			result, err := callIndexer(info)
			if err == nil {
				return &RoutedQueryResult[T]{
					Result:     result,
					Source:     ServedByIndexer,
					IndexerDID: info.IndexerDID,
				}, nil
			}
			errs = append(errs, fmt.Sprintf("%s: %v", info.IndexerDID, err))
		}
		return nil, &NoIndexersReachableError{
			SubgroveID: subgroveID,
			Details:    strings.Join(errs, "; "),
		}

	default: // QuerySourceAuto
		candidates, _ := c.Indexers.ForSubgrove(ctx, subgroveID)
		hadCandidates := len(candidates) > 0
		for _, info := range candidates {
			result, err := callIndexer(info)
			if err == nil {
				return &RoutedQueryResult[T]{
					Result:     result,
					Source:     ServedByIndexer,
					IndexerDID: info.IndexerDID,
				}, nil
			}
			// continue to next indexer / fall back to validator
		}
		result, err := callValidator()
		if err != nil {
			return nil, err
		}
		return &RoutedQueryResult[T]{
			Result:   result,
			Source:   ServedByValidator,
			Fallback: hadCandidates,
		}, nil
	}
}

// unwrapResponse handles both the validator's { success, data: T } envelope
// and the indexer's raw T response, returning T in both cases.
func unwrapResponse[T any](raw []byte) (T, error) {
	var zero T
	// Try indexer-shaped raw T first (faster path).
	if err := json.Unmarshal(raw, &zero); err == nil {
		// Check if it's actually an envelope disguised as T — if T is a
		// pointer to a struct and the JSON has `success` + `data`, prefer
		// the data field.
		var envelope struct {
			Success *bool           `json:"success"`
			Data    json.RawMessage `json:"data"`
		}
		if json.Unmarshal(raw, &envelope) == nil && envelope.Success != nil && len(envelope.Data) > 0 {
			var wrapped T
			if err := json.Unmarshal(envelope.Data, &wrapped); err == nil {
				return wrapped, nil
			}
		}
		return zero, nil
	}
	return zero, fmt.Errorf("failed to decode response")
}

// SqlQuery executes a SQL query against a subgrove.
// When an indexer URL is configured, the query is routed there.
func (i *IndexingOperations) SqlQuery(ctx context.Context, subgroveID, query string, includeProof bool) (*SqlResponse, error) {
	req := SqlRequest{
		Query:        query,
		IncludeProof: &includeProof,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SQL request: %w", err)
	}

	baseURL := i.client.IndexerBaseURL()
	url := fmt.Sprintf("%s/sql/%s", baseURL, subgroveID)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := i.client.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("SQL query request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("SQL query failed with status %d", resp.StatusCode)
	}

	var result SqlResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode SQL response: %w", err)
	}

	return &result, nil
}

// ExecuteWithResult executes a query and unmarshals the result into the provided type.
func (i *IndexingOperations) ExecuteWithResult(ctx context.Context, subgroveID, query string, variables map[string]interface{}, result interface{}) error {
	response, err := i.Execute(ctx, subgroveID, query, variables)
	if err != nil {
		return err
	}

	if len(response.Errors) > 0 {
		return fmt.Errorf("graphql error: %s", response.Errors[0].Message)
	}

	if response.Data != nil {
		return json.Unmarshal(response.Data, result)
	}

	return nil
}

// ListSubgroves retrieves all available subgroves.
func (i *IndexingOperations) ListSubgroves(ctx context.Context) ([]SubgroveInfo, error) {
	var subgroves []SubgroveInfo
	err := i.client.get(ctx, "/subgroves", &subgroves)
	if err != nil {
		return nil, err
	}
	return subgroves, nil
}

// GetSubgrove retrieves information about a specific subgrove.
func (i *IndexingOperations) GetSubgrove(ctx context.Context, subgroveID string) (*SubgroveInfo, error) {
	var subgrove SubgroveInfo
	err := i.client.get(ctx, fmt.Sprintf("/subgroves/%s", subgroveID), &subgrove)
	if err != nil {
		return nil, err
	}
	return &subgrove, nil
}

// ListIndexers retrieves all indexers.
func (i *IndexingOperations) ListIndexers(ctx context.Context) ([]IndexerInfo, error) {
	var indexers []IndexerInfo
	err := i.client.get(ctx, "/indexers", &indexers)
	if err != nil {
		return nil, err
	}
	return indexers, nil
}

// GetIndexer retrieves information about a specific indexer.
func (i *IndexingOperations) GetIndexer(ctx context.Context, indexerID string) (*IndexerInfo, error) {
	var indexer IndexerInfo
	err := i.client.get(ctx, fmt.Sprintf("/indexers/%s", indexerID), &indexer)
	if err != nil {
		return nil, err
	}
	return &indexer, nil
}

// GetIndexerStatus retrieves the status of an indexer for a subgrove.
func (i *IndexingOperations) GetIndexerStatus(ctx context.Context, indexerID, subgroveID string) (*IndexerInfo, error) {
	var indexer IndexerInfo
	path := fmt.Sprintf("/indexers/%s/status/%s", indexerID, subgroveID)
	err := i.client.get(ctx, path, &indexer)
	if err != nil {
		return nil, err
	}
	return &indexer, nil
}

func (i *IndexingOperations) verifyProof(ctx context.Context, proof []byte) error {
	if !i.client.HasLightClient() {
		return ErrLightClientNotInitialized
	}

	// Get the trusted root hash from the light client
	trustedHeader, err := i.client.lightClient.GetLatestTrustedHeader()
	if err != nil {
		return NewLightClientError("failed to get trusted header", err)
	}

	// Verify the GroveDB proof
	result, err := grovedb.VerifyProof(proof)
	if err != nil {
		return NewProofError(fmt.Sprintf("failed to verify proof: %v", err))
	}

	// Compare root hashes
	if result.RootHash != trustedHeader.AppHash {
		return NewProofError(fmt.Sprintf("root hash mismatch: expected %s, got %s",
			trustedHeader.AppHash, result.RootHash))
	}

	return nil
}

// GraphQLQueryBuilder provides a fluent interface for building GraphQL queries.
type GraphQLQueryBuilder struct {
	req *GraphQLRequest
}

// NewGraphQLQuery creates a new GraphQL query builder.
func NewGraphQLQuery(query string) *GraphQLQueryBuilder {
	return &GraphQLQueryBuilder{
		req: &GraphQLRequest{
			Query:     query,
			Variables: make(map[string]interface{}),
		},
	}
}

// Variable adds a variable to the query.
func (b *GraphQLQueryBuilder) Variable(name string, value interface{}) *GraphQLQueryBuilder {
	b.req.Variables[name] = value
	return b
}

// Variables sets multiple variables.
func (b *GraphQLQueryBuilder) Variables(vars map[string]interface{}) *GraphQLQueryBuilder {
	for k, v := range vars {
		b.req.Variables[k] = v
	}
	return b
}

// OperationName sets the operation name.
func (b *GraphQLQueryBuilder) OperationName(name string) *GraphQLQueryBuilder {
	b.req.OperationName = name
	return b
}

// IncludeProof enables proof inclusion.
func (b *GraphQLQueryBuilder) IncludeProof() *GraphQLQueryBuilder {
	b.req.IncludeProof = true
	return b
}

// Build returns the constructed GraphQLRequest.
func (b *GraphQLQueryBuilder) Build() *GraphQLRequest {
	return b.req
}
