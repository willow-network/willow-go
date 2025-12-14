package willow

import (
	"context"
	"fmt"

	"github.com/willow-network/willow-go/grovedb"
)

// DataOperations provides methods for data storage and retrieval.
type DataOperations struct {
	client *Client
}

// Store stores data in a subgrove.
func (d *DataOperations) Store(ctx context.Context, appID, subgroveID string, data map[string]interface{}) error {
	if err := d.client.RequireAuth(); err != nil {
		return err
	}

	path := fmt.Sprintf("/data/%s/%s", appID, subgroveID)
	return d.client.post(ctx, path, data, nil)
}

// StoreItem stores a single item with a specified key.
func (d *DataOperations) StoreItem(ctx context.Context, appID, subgroveID, key string, data map[string]interface{}) error {
	if err := d.client.RequireAuth(); err != nil {
		return err
	}

	req := StoreRequest{
		Key:  key,
		Data: data,
	}

	path := fmt.Sprintf("/data/%s/%s", appID, subgroveID)
	return d.client.post(ctx, path, req, nil)
}

// Get retrieves data by key with automatic proof verification.
//
// This method always verifies proofs using the light client for trustless verification.
// The light client auto-initializes with trust-on-first-use if not already configured.
//
// Important: TODO: When mainnet/testnet launches, the light client will be
// initialized with hardcoded checkpoint headers instead of trust-on-first-use.
func (d *DataOperations) Get(ctx context.Context, appID, subgroveID, key string) (*DataResponse, error) {
	if err := d.client.RequireAuth(); err != nil {
		return nil, err
	}

	// Get data with proof
	path := fmt.Sprintf("/data/%s/%s/%s?include_proof=true", appID, subgroveID, key)
	var response DataResponse
	if err := d.client.get(ctx, path, &response); err != nil {
		return nil, err
	}

	// Always verify proof using light client (auto-initializes if needed)
	// This provides trustless verification by default.
	if response.Proof != nil {
		if err := d.verifyProof(ctx, response.Proof); err != nil {
			return nil, NewProofError(fmt.Sprintf("proof verification failed: %v", err))
		}
	}

	return &response, nil
}

// GetUnverified retrieves data without proof verification (faster).
func (d *DataOperations) GetUnverified(ctx context.Context, appID, subgroveID, key string) (*DataResponse, error) {
	if err := d.client.RequireAuth(); err != nil {
		return nil, err
	}

	path := fmt.Sprintf("/data/%s/%s/%s", appID, subgroveID, key)
	var response DataResponse
	if err := d.client.get(ctx, path, &response); err != nil {
		return nil, err
	}

	return &response, nil
}

// Update updates existing data by key.
func (d *DataOperations) Update(ctx context.Context, appID, subgroveID, key string, data map[string]interface{}) error {
	if err := d.client.RequireAuth(); err != nil {
		return err
	}

	path := fmt.Sprintf("/data/%s/%s/%s", appID, subgroveID, key)
	return d.client.put(ctx, path, data, nil)
}

// Delete deletes data by key.
func (d *DataOperations) Delete(ctx context.Context, appID, subgroveID, key string) error {
	if err := d.client.RequireAuth(); err != nil {
		return err
	}

	path := fmt.Sprintf("/data/%s/%s/%s", appID, subgroveID, key)
	return d.client.delete(ctx, path, nil)
}

// BatchStore stores multiple items in a single request.
func (d *DataOperations) BatchStore(ctx context.Context, appID, subgroveID string, items []StoreRequest) error {
	if err := d.client.RequireAuth(); err != nil {
		return err
	}

	req := BatchStoreRequest{
		Items: items,
	}

	path := fmt.Sprintf("/data/%s/%s/batch", appID, subgroveID)
	return d.client.post(ctx, path, req, nil)
}

// Query queries data with filters and automatic proof verification.
//
// This method always verifies proofs using the light client for trustless verification.
// The light client auto-initializes with trust-on-first-use if not already configured.
//
// Important: TODO: When mainnet/testnet launches, the light client will be
// initialized with hardcoded checkpoint headers instead of trust-on-first-use.
func (d *DataOperations) Query(ctx context.Context, appID, subgroveID string, query *QueryRequest) (*QueryResponse, error) {
	if err := d.client.RequireAuth(); err != nil {
		return nil, err
	}

	// Always enable proof for trustless verification
	query.IncludeProof = true

	path := fmt.Sprintf("/query/%s/%s", appID, subgroveID)
	var response QueryResponse
	if err := d.client.post(ctx, path, query, &response); err != nil {
		return nil, err
	}

	// Always verify proof using light client (auto-initializes if needed)
	if len(response.Proof) > 0 {
		proof := &DataProof{Proof: response.Proof}
		if err := d.verifyProof(ctx, proof); err != nil {
			return nil, NewProofError(fmt.Sprintf("proof verification failed: %v", err))
		}
	}

	return &response, nil
}

// QueryUnverified queries data without proof verification (faster).
func (d *DataOperations) QueryUnverified(ctx context.Context, appID, subgroveID string, query *QueryRequest) (*QueryResponse, error) {
	if err := d.client.RequireAuth(); err != nil {
		return nil, err
	}

	query.IncludeProof = false

	path := fmt.Sprintf("/query/%s/%s", appID, subgroveID)
	var response QueryResponse
	if err := d.client.post(ctx, path, query, &response); err != nil {
		return nil, err
	}

	return &response, nil
}

// GetProof retrieves the proof for a specific key.
func (d *DataOperations) GetProof(ctx context.Context, appID, subgroveID, key string) (*DataProof, error) {
	if err := d.client.RequireAuth(); err != nil {
		return nil, err
	}

	path := fmt.Sprintf("/proof/%s/%s/%s", appID, subgroveID, key)
	var proof DataProof
	if err := d.client.get(ctx, path, &proof); err != nil {
		return nil, err
	}

	return &proof, nil
}

// VerifyProof verifies a proof against the light client.
func (d *DataOperations) VerifyProof(ctx context.Context, proof *DataProof) error {
	return d.verifyProof(ctx, proof)
}

func (d *DataOperations) verifyProof(ctx context.Context, proof *DataProof) error {
	// Get or create light client for trustless verification
	// This auto-initializes with trust-on-first-use if not already configured.
	lc, err := d.client.GetOrCreateLightClient(ctx)
	if err != nil {
		return NewLightClientError("failed to initialize light client", err)
	}

	// Get the trusted root hash from the light client
	trustedRootHash, err := lc.GetVerifiedRootHash(ctx)
	if err != nil {
		return NewLightClientError("failed to get verified root hash", err)
	}

	// Verify the GroveDB proof
	result, err := grovedb.VerifyProof(proof.Proof)
	if err != nil {
		return NewProofError(fmt.Sprintf("failed to verify proof: %v", err))
	}

	// Compare root hashes
	if result.RootHash != trustedRootHash {
		return NewProofError(fmt.Sprintf("root hash mismatch: expected %s, got %s",
			trustedRootHash, result.RootHash))
	}

	return nil
}

// QueryBuilder provides a fluent interface for building queries.
type QueryBuilder struct {
	query *QueryRequest
}

// NewQueryBuilder creates a new QueryBuilder.
func NewQueryBuilder() *QueryBuilder {
	return &QueryBuilder{
		query: &QueryRequest{},
	}
}

// Filter adds a filter condition.
func (qb *QueryBuilder) Filter(field, operator string, value interface{}) *QueryBuilder {
	qb.query.Filters = append(qb.query.Filters, QueryFilter{
		Field:    field,
		Operator: operator,
		Value:    value,
	})
	return qb
}

// Equals adds an equality filter.
func (qb *QueryBuilder) Equals(field string, value interface{}) *QueryBuilder {
	return qb.Filter(field, "eq", value)
}

// NotEquals adds a not-equals filter.
func (qb *QueryBuilder) NotEquals(field string, value interface{}) *QueryBuilder {
	return qb.Filter(field, "ne", value)
}

// GreaterThan adds a greater-than filter.
func (qb *QueryBuilder) GreaterThan(field string, value interface{}) *QueryBuilder {
	return qb.Filter(field, "gt", value)
}

// GreaterThanOrEqual adds a greater-than-or-equal filter.
func (qb *QueryBuilder) GreaterThanOrEqual(field string, value interface{}) *QueryBuilder {
	return qb.Filter(field, "gte", value)
}

// LessThan adds a less-than filter.
func (qb *QueryBuilder) LessThan(field string, value interface{}) *QueryBuilder {
	return qb.Filter(field, "lt", value)
}

// LessThanOrEqual adds a less-than-or-equal filter.
func (qb *QueryBuilder) LessThanOrEqual(field string, value interface{}) *QueryBuilder {
	return qb.Filter(field, "lte", value)
}

// Contains adds a contains filter.
func (qb *QueryBuilder) Contains(field string, value interface{}) *QueryBuilder {
	return qb.Filter(field, "contains", value)
}

// In adds an in filter.
func (qb *QueryBuilder) In(field string, values []interface{}) *QueryBuilder {
	return qb.Filter(field, "in", values)
}

// Search adds a full-text search.
func (qb *QueryBuilder) Search(fields []string, query string) *QueryBuilder {
	qb.query.Search = &QuerySearch{
		Fields: fields,
		Query:  query,
	}
	return qb
}

// SortAsc adds ascending sort.
func (qb *QueryBuilder) SortAsc(field string) *QueryBuilder {
	qb.query.Sort = &QuerySort{
		Field:     field,
		Ascending: true,
	}
	return qb
}

// SortDesc adds descending sort.
func (qb *QueryBuilder) SortDesc(field string) *QueryBuilder {
	qb.query.Sort = &QuerySort{
		Field:     field,
		Ascending: false,
	}
	return qb
}

// Limit sets the maximum number of results.
func (qb *QueryBuilder) Limit(limit int) *QueryBuilder {
	qb.query.Limit = limit
	return qb
}

// Offset sets the result offset.
func (qb *QueryBuilder) Offset(offset int) *QueryBuilder {
	qb.query.Offset = offset
	return qb
}

// IncludeProof enables proof inclusion.
func (qb *QueryBuilder) IncludeProof() *QueryBuilder {
	qb.query.IncludeProof = true
	return qb
}

// Build returns the constructed QueryRequest.
func (qb *QueryBuilder) Build() *QueryRequest {
	return qb.query
}
