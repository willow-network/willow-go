package willow

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/willow-network/willow-go/internal/httpbody"
)

// IndexingOperations provides methods for blockchain indexing and GraphQL queries.
//
// No GraphQL or SQL answer is verified: the SDK can't bind an indexer's or
// the API's answer to the chain's state (it verifies no CometBFT header, and
// no proof ties the answer's rows to a root), so every query method returns
// the answer as it comes.
type IndexingOperations struct {
	client *Client
}

// Query returns an unsupported-operation error and sends nothing.
//
// Verifying a GraphQL answer takes a proof that binds the returned data to a
// state root, and that root checked against a CometBFT header verified by the
// validators' commit signatures. The answer's proof doesn't bind its data, and
// this SDK verifies no header (see the lightclient package), so it doesn't
// present a GraphQL answer as verified. QueryUnverified sends the query and
// returns its answer unverified.
//
// Deprecated: Query always fails; use QueryUnverified, which returns the
// answer unverified.
func (i *IndexingOperations) Query(ctx context.Context, subgroveID string, req *GraphQLRequest) (*GraphQLResponse, error) {
	return nil, NewUnsupportedError("Indexing.Query: this SDK can't verify a GraphQL answer against the chain; QueryUnverified sends the query and returns its answer unverified")
}

// QueryUnverified sends a GraphQL query asking for no proof (include_proof
// false) and returns the answer as it comes, unverified. With an indexer URL
// set (WithIndexerURL) the query goes to that indexer; otherwise to the API,
// signed by the client's identity when one is set. req isn't changed.
func (i *IndexingOperations) QueryUnverified(ctx context.Context, subgroveID string, req *GraphQLRequest) (*GraphQLResponse, error) {
	if req == nil {
		return nil, NewValidationError("QueryUnverified: no GraphQL request")
	}
	sent := *req
	sent.IncludeProof = BoolPtr(false)
	path := fmt.Sprintf("/graphql/%s", subgroveID)
	var response GraphQLResponse
	if i.client.indexerURL == nil {
		// The API answers GraphQL with the GraphQL response itself, not the
		// success/data envelope.
		if err := i.client.post(ctx, path, &sent, httpbody.Large, &response); err != nil {
			return nil, err
		}
		return &response, nil
	}

	body, err := json.Marshal(&sent)
	if err != nil {
		return nil, NewSerializationError("failed to marshal GraphQL request", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, i.client.IndexerBaseURL()+path, bytes.NewReader(body))
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
	if err := httpbody.Decode(resp.Body, httpbody.Large, &response); err != nil {
		return nil, fmt.Errorf("failed to decode GraphQL response: %w", err)
	}
	return &response, nil
}

// Execute sends a GraphQL query with its variables, unverified: it is
// QueryUnverified with a request built from them.
func (i *IndexingOperations) Execute(ctx context.Context, subgroveID, query string, variables map[string]interface{}) (*GraphQLResponse, error) {
	return i.QueryUnverified(ctx, subgroveID, &GraphQLRequest{
		Query:     query,
		Variables: variables,
	})
}

// GraphQLQueryWithSource executes a GraphQL query with explicit source
// selection and returns the answer unverified. It asks for no proof
// (include_proof false) unless req sets IncludeProof; a proof asked for is
// returned, unverified, as the answer's JSON in GraphQLResponse.Proof. req
// isn't changed.
//
// Callers choose the backend via QuerySource:
//   - QuerySourceValidator: the API, which serves the chain-tip state.
//     Returns a *ValidatorHasNoDataError for VerifyOnly subgroves.
//   - QuerySourceIndexer: historical/analytics via an indexer. Returns a
//     *NoIndexersReachableError if none are reachable.
//   - QuerySourceAuto (default): indexer if one serves this subgrove, else
//     validator. On indexer failure, falls back to validator with
//     Fallback=true in the returned result.
//
// It tries at most the three best-scored indexers serving the subgrove.
func (i *IndexingOperations) GraphQLQueryWithSource(
	ctx context.Context,
	subgroveID string,
	req *GraphQLRequest,
	source QuerySource,
) (*RoutedQueryResult[*GraphQLResponse], error) {
	if req == nil {
		return nil, NewValidationError("GraphQLQueryWithSource: no GraphQL request")
	}
	sent := *req
	if sent.IncludeProof == nil {
		// The API and indexers attach a proof unless asked not to.
		sent.IncludeProof = BoolPtr(false)
	}
	bodyBytes, err := json.Marshal(&sent)
	if err != nil {
		return nil, fmt.Errorf("marshal GraphQL request: %w", err)
	}
	return routeQuery[*GraphQLResponse](
		ctx, i.client, "graphql", subgroveID, bodyBytes, source,
	)
}

// SqlQueryWithSource executes a SQL query with explicit source selection and
// returns the answer (and any proof it carries) unverified.
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

// maxIndexerCandidates is how many indexers a routed query tries, the best
// scored first, before it fails (QuerySourceIndexer) or falls back to the API
// (QuerySourceAuto).
const maxIndexerCandidates = 3

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
		if err := c.signAPIRequest(req, body); err != nil {
			return zero, err
		}
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
		raw, err := httpbody.ReadAll(resp.Body, httpbody.Large)
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
		raw, err := httpbody.ReadAll(resp.Body, httpbody.Large)
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
		candidates = candidates[:min(len(candidates), maxIndexerCandidates)]
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
		candidates = candidates[:min(len(candidates), maxIndexerCandidates)]
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

// unwrapResponse reads a routed query's answer: T in the API's {success,
// data, error} envelope, or T alone (an indexer's answer, and the API's SQL
// and GraphQL answers). It refuses an answer that holds more JSON than the
// SDK decodes (see httpbody.CheckJSON) and decodes T once. An envelope that
// reports a failure, or carries no data, is an error.
func unwrapResponse[T any](raw []byte) (T, error) {
	var zero T
	if err := httpbody.CheckJSON(raw); err != nil {
		return zero, err
	}
	// Whether it is an envelope; the probe decodes nothing else.
	var probe struct {
		Success *bool `json:"success"`
	}
	if json.Unmarshal(raw, &probe) != nil || probe.Success == nil {
		var result T
		if err := json.Unmarshal(raw, &result); err != nil {
			return zero, fmt.Errorf("failed to decode response: %w", err)
		}
		return result, nil
	}
	var envelope apiEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return zero, fmt.Errorf("failed to decode response: %w", err)
	}
	if len(envelope.Data) == 0 || string(envelope.Data) == "null" {
		if err := envelope.decode(nil); err != nil {
			return zero, err
		}
		return zero, NewAPIError("the answer's envelope carries no data")
	}
	var result T
	if err := envelope.decode(&result); err != nil {
		return zero, err
	}
	return result, nil
}

// SqlQuery executes a SQL query against a subgrove and returns the answer
// (and, with includeProof, its proof) unverified.
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
	if i.client.indexerURL == nil {
		// Sent to the API, so it carries the identity's read rights.
		if err := i.client.signAPIRequest(httpReq, body); err != nil {
			return nil, err
		}
	}

	resp, err := i.client.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("SQL query request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("SQL query failed with status %d", resp.StatusCode)
	}

	var result SqlResponse
	if err := httpbody.Decode(resp.Body, httpbody.Large, &result); err != nil {
		return nil, fmt.Errorf("failed to decode SQL response: %w", err)
	}

	return &result, nil
}

// ExecuteWithResult sends a query unverified (see Execute) and unmarshals its
// data into result.
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
	err := i.client.getData(ctx, "/subgroves", &subgroves)
	if err != nil {
		return nil, err
	}
	return subgroves, nil
}

// GetSubgrove retrieves information about a specific subgrove.
func (i *IndexingOperations) GetSubgrove(ctx context.Context, subgroveID string) (*SubgroveInfo, error) {
	var subgrove SubgroveInfo
	err := i.client.getData(ctx, fmt.Sprintf("/subgroves/%s", subgroveID), &subgrove)
	if err != nil {
		return nil, err
	}
	return &subgrove, nil
}

// ListIndexers retrieves all indexers.
func (i *IndexingOperations) ListIndexers(ctx context.Context) ([]IndexerInfo, error) {
	var indexers []IndexerInfo
	err := i.client.getData(ctx, "/indexers", &indexers)
	if err != nil {
		return nil, err
	}
	return indexers, nil
}

// GetIndexer retrieves information about a specific indexer.
func (i *IndexingOperations) GetIndexer(ctx context.Context, indexerID string) (*IndexerInfo, error) {
	var indexer IndexerInfo
	err := i.client.getData(ctx, fmt.Sprintf("/indexers/%s", indexerID), &indexer)
	if err != nil {
		return nil, err
	}
	return &indexer, nil
}

// GetIndexerStatus returns an unsupported-operation error and sends nothing:
// the API serves no per-subgrove indexer status route. GetIndexer reads an
// indexer, with the subgroves it serves and its status.
//
// Deprecated: GetIndexerStatus always fails; use GetIndexer.
func (i *IndexingOperations) GetIndexerStatus(ctx context.Context, indexerID, subgroveID string) (*IndexerInfo, error) {
	return nil, NewUnsupportedError("GetIndexerStatus: the API serves no per-subgrove indexer status route; GetIndexer reads an indexer, with the subgroves it serves and its status")
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

// IncludeProof asks for a proof. QueryUnverified asks for none whatever the
// request says; GraphQLQueryWithSource asks for one only when it is set, and
// returns it unverified.
func (b *GraphQLQueryBuilder) IncludeProof() *GraphQLQueryBuilder {
	b.req.IncludeProof = BoolPtr(true)
	return b
}

// Build returns the constructed GraphQLRequest.
func (b *GraphQLQueryBuilder) Build() *GraphQLRequest {
	return b.req
}
