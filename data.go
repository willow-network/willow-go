package willow

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/willow-network/willow-go/consensus"
	"github.com/willow-network/willow-go/grovedb"
)

// DataOperations provides methods for data storage and retrieval.
type DataOperations struct {
	client *Client
}

// Store returns an unsupported-operation error and sends nothing: data is
// written by a StoreData transaction, which needs a key. Use StoreItem.
func (d *DataOperations) Store(ctx context.Context, subgroveID string, data map[string]interface{}) error {
	return NewUnsupportedError("Store: data is written by a StoreData transaction sent to POST /tx/submit, which needs a key; use StoreItem")
}

// StoreItem stores data under key by sending a signed StoreData transaction to
// POST /tx/submit, owned by the client's identity.
//
// data is sent as its JSON text (encoding/json, object keys sorted) carried as
// bytes, and the signature binds those exact bytes with the subgrove, key,
// owner, and the transaction's nonce (see FormatDataStoreMessage). The nonce is
// the lowest free one in the identity's window (see Client.NextNonce), so
// writes in flight together take distinct nonces; at most 24 can be in flight
// per identity. StoreItem returns once the chain's CheckTx accepts the
// transaction, with the nonce and transaction hash; the write is applied, or
// refused, in its block (see Client.WaitUntilLanded). A failure after the
// transaction was signed is a *WriteError naming its nonce; to send it again
// under that nonce, pass WithNonce.
func (d *DataOperations) StoreItem(ctx context.Context, subgroveID, key string, data map[string]interface{}, opts ...WriteOption) (*WriteResult, error) {
	if err := d.client.RequireAuth(); err != nil {
		return nil, err
	}
	if data == nil {
		return nil, NewValidationError("StoreItem: data must be a JSON object, not nil")
	}
	body, err := json.Marshal(data)
	if err != nil {
		return nil, NewSerializationError("failed to encode the data", err)
	}

	identity := d.client.GetIdentity()
	return d.client.signedWrite(ctx, identity.DID(), opts, func(nonce uint64) (interface{}, error) {
		message, err := FormatDataStoreMessage(subgroveID, key, identity.DID(), body, nonce)
		if err != nil {
			return nil, err
		}
		signature, err := identity.Sign([]byte(message))
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{
			"StoreData": consensus.DataStoreTx{
				SubgroveID:  subgroveID,
				Key:         key,
				Data:        body,
				OwnerDid:    identity.DID(),
				Signature:   signature,
				PublicKeyID: identity.PublicKeyID(),
				Nonce:       nonce,
			},
		}, nil
	})
}

// Get retrieves the value stored under key.
//
// The API's data route answers with the value alone, without a proof, so Get
// has nothing to verify. GetProof fetches the key's GroveDB proof.
func (d *DataOperations) Get(ctx context.Context, subgroveID, key string) (*DataResponse, error) {
	if err := d.client.RequireAuth(); err != nil {
		return nil, err
	}

	path := fmt.Sprintf("/data/%s/%s?include_proof=true", subgroveID, key)
	return d.getValue(ctx, path, key)
}

// GetUnverified retrieves the value stored under key, asking the API for no
// proof.
func (d *DataOperations) GetUnverified(ctx context.Context, subgroveID, key string) (*DataResponse, error) {
	if err := d.client.RequireAuth(); err != nil {
		return nil, err
	}

	path := fmt.Sprintf("/data/%s/%s?include_proof=false", subgroveID, key)
	return d.getValue(ctx, path, key)
}

// getValue reads a /data answer: its data is the stored JSON value.
func (d *DataOperations) getValue(ctx context.Context, path, key string) (*DataResponse, error) {
	var value map[string]interface{}
	if err := d.client.getData(ctx, path, &value); err != nil {
		return nil, err
	}
	return &DataResponse{Key: key, Data: value}, nil
}

// Update returns an unsupported-operation error and sends nothing: the API's
// REST data routes refuse writes, and data is updated by an UpdateData
// transaction, which this SDK does not build.
func (d *DataOperations) Update(ctx context.Context, subgroveID, key string, data map[string]interface{}) error {
	return NewUnsupportedError("Update: the API's REST data routes refuse writes; data is updated by an UpdateData transaction sent to POST /tx/submit, which this SDK does not build")
}

// Delete returns an unsupported-operation error and sends nothing: the API's
// REST data routes refuse writes, and data is deleted by a DeleteData
// transaction, which this SDK does not build.
func (d *DataOperations) Delete(ctx context.Context, subgroveID, key string) error {
	return NewUnsupportedError("Delete: the API's REST data routes refuse writes; data is deleted by a DeleteData transaction sent to POST /tx/submit, which this SDK does not build")
}

// BatchStore returns an unsupported-operation error and sends nothing: the API
// serves no batch write route. Store each item with StoreItem, which sends one
// StoreData transaction per item under its own nonce; at most 24 can be in
// flight per identity, so past that wait for earlier ones to land
// (Client.WaitUntilLanded).
func (d *DataOperations) BatchStore(ctx context.Context, subgroveID string, items []StoreRequest) error {
	return NewUnsupportedError("BatchStore: the API serves no batch write route; store each item with StoreItem, " +
		"one StoreData transaction per item under its own nonce; at most 24 can be in flight per identity, " +
		"so past that wait for earlier ones to land (WaitUntilLanded)")
}

// Query returns an unsupported-operation error and sends nothing.
//
// A query's proof is of the state after block Height, so its root is the
// app_hash of the CometBFT header at Height+1. Verifying a query takes that
// header verified against the validators' commit signatures, the proof's
// root reproduced, and the returned documents matched to the values the proof
// proves. This SDK does none of these (see VerifyProof), so it doesn't present
// a query as verified. QueryUnverified sends the query and returns its
// documents unverified.
func (d *DataOperations) Query(ctx context.Context, subgroveID string, query *QueryRequest) (*QueryResponse, error) {
	return nil, NewUnsupportedError("Query: this SDK can't verify a query's proof against the chain (see VerifyProof); QueryUnverified sends the query and returns its documents unverified")
}

// QueryUnverified queries data without a proof (include_proof false) and
// returns the API's documents as they are.
func (d *DataOperations) QueryUnverified(ctx context.Context, subgroveID string, query *QueryRequest) (*QueryResponse, error) {
	if err := d.client.RequireAuth(); err != nil {
		return nil, err
	}

	if query == nil {
		query = &QueryRequest{}
	}
	query.IncludeProof = BoolPtr(false)

	response, err := d.query(ctx, subgroveID, query)
	if err != nil {
		return nil, err
	}

	// Apply computed fields if registered for this dataset
	if fields, ok := d.client.computedFields.Get(subgroveID); ok {
		return ApplyComputedFieldsToResponse(response, fields), nil
	}

	return response, nil
}

// query sends a query and reads the data of the API's answer: the matching
// documents, their total, and, when asked for, a hex proof and its height.
func (d *DataOperations) query(ctx context.Context, subgroveID string, query *QueryRequest) (*QueryResponse, error) {
	var answer struct {
		Total     int                      `json:"total"`
		Offset    int                      `json:"offset"`
		Documents []map[string]interface{} `json:"documents"`
		Proof     string                   `json:"proof"`
		Height    uint64                   `json:"height"`
	}
	body, err := queryBody(query)
	if err != nil {
		return nil, err
	}
	if err := d.client.postData(ctx, fmt.Sprintf("/query/%s", subgroveID), body, &answer); err != nil {
		return nil, err
	}
	response := &QueryResponse{
		Results:    make([]QueryResult, len(answer.Documents)),
		TotalCount: answer.Total,
		HasMore:    answer.Offset+len(answer.Documents) < answer.Total,
		Height:     answer.Height,
	}
	for i, document := range answer.Documents {
		response.Results[i] = QueryResult{Data: document}
	}
	if answer.Proof != "" {
		proof, err := hex.DecodeString(strings.TrimPrefix(answer.Proof, "0x"))
		if err != nil {
			return nil, NewSerializationError("query proof is not hex", err)
		}
		response.Proof = proof
	}
	return response, nil
}

// queryBody is the body the API's /query reads: one equality filter as
// {"filters": {field: value}}, sort as {"field", "order": "asc" or "desc"},
// limit, offset, and include_proof. It refuses what the route doesn't apply
// (more than one filter, an operator other than eq, an object value, full-text
// search) rather than send a query whose filter the API would ignore.
func queryBody(q *QueryRequest) (map[string]interface{}, error) {
	body := map[string]interface{}{}
	if q == nil {
		return body, nil
	}
	switch len(q.Filters) {
	case 0:
	case 1:
		f := q.Filters[0]
		if f.Operator != "eq" {
			return nil, NewValidationError(fmt.Sprintf("query: the API's /query applies only an equality filter, not %q", f.Operator))
		}
		if _, isObject := f.Value.(map[string]interface{}); isObject {
			return nil, NewValidationError("query: the API's /query matches a field against a value that is not an object")
		}
		body["filters"] = map[string]interface{}{f.Field: f.Value}
	default:
		return nil, NewValidationError(fmt.Sprintf("query: the API's /query applies one filter, not %d", len(q.Filters)))
	}
	if q.Search != nil {
		return nil, NewValidationError("query: the API's /query has no full-text search")
	}
	if q.Sort != nil {
		order := "desc"
		if q.Sort.Ascending {
			order = "asc"
		}
		body["sort"] = map[string]string{"field": q.Sort.Field, "order": order}
	}
	if q.Limit < 0 || q.Offset < 0 {
		return nil, NewValidationError("query: limit and offset can't be negative")
	}
	if q.Limit > 0 {
		body["limit"] = q.Limit
	}
	if q.Offset > 0 {
		body["offset"] = q.Offset
	}
	if q.IncludeProof != nil {
		body["include_proof"] = *q.IncludeProof
	}
	return body, nil
}

// GetProof retrieves the GroveDB proof of a key, with the GroveDB path and
// key it proves and the height of the block whose state it is of.
//
// The proof is of the state after block Height, so its root is the app_hash
// of the CometBFT header at Height+1. Checking it takes that header verified
// against the validators' commit signatures and a GroveDB verifier that
// reproduces the chain's proofs, run at Path; this SDK has neither (see
// VerifyProof), so GetProof returns the proof unverified.
func (d *DataOperations) GetProof(ctx context.Context, subgroveID, key string) (*DataProof, error) {
	if err := d.client.RequireAuth(); err != nil {
		return nil, err
	}

	path := fmt.Sprintf("/proof/%s/%s", subgroveID, key)
	// The API answers {proof: hex, path: [hex], key: hex, height}.
	var answer struct {
		Proof  string   `json:"proof"`
		Path   []string `json:"path"`
		Key    string   `json:"key"`
		Height int64    `json:"height"`
	}
	if err := d.client.getData(ctx, path, &answer); err != nil {
		return nil, err
	}
	proof, err := hex.DecodeString(strings.TrimPrefix(answer.Proof, "0x"))
	if err != nil {
		return nil, NewSerializationError("proof is not hex", err)
	}
	result := &DataProof{Proof: proof, Height: answer.Height}
	for _, segment := range answer.Path {
		b, err := hex.DecodeString(segment)
		if err != nil {
			return nil, NewSerializationError("proof path segment is not hex", err)
		}
		result.Path = append(result.Path, b)
	}
	if answer.Key != "" {
		if result.Key, err = hex.DecodeString(answer.Key); err != nil {
			return nil, NewSerializationError("proof key is not hex", err)
		}
	}
	return result, nil
}

// VerifyProof returns an unsupported-operation error.
//
// A proof's root must equal the app_hash of the CometBFT header at
// proof.Height+1, verified against the validators' commit signatures. This
// SDK doesn't verify CometBFT headers, and its GroveDB verifier doesn't
// reproduce the chain's root for every proof, so it doesn't present a proof
// as verified.
func (d *DataOperations) VerifyProof(ctx context.Context, proof *DataProof) error {
	return NewUnsupportedError("VerifyProof: this SDK doesn't verify CometBFT headers, and its GroveDB verifier doesn't reproduce the chain's root for every proof, so it can't verify a proof against the chain")
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
	qb.query.IncludeProof = BoolPtr(true)
	return qb
}

// Build returns the constructed QueryRequest.
func (qb *QueryBuilder) Build() *QueryRequest {
	return qb.query
}

// GetCheckpointStateRoot retrieves checkpoint information including state root.
func (d *DataOperations) GetCheckpointStateRoot(ctx context.Context, subgroveID, checkpointID string) (*CheckpointInfo, error) {
	path := fmt.Sprintf("/checkpoints/%s/%s/state-root", subgroveID, checkpointID)
	var response CheckpointInfo
	if err := d.client.getData(ctx, path, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// QueryHistorical queries historical indexed data from a checkpoint.
// Routes through consensus to available indexer nodes that serve historical data.
// The API answers this route with the HistoricalQueryResponse itself, not the
// success/data envelope.
func (d *DataOperations) QueryHistorical(ctx context.Context, subgroveID, checkpointID string, req *HistoricalQueryRequest) (*HistoricalQueryResponse, error) {
	path := fmt.Sprintf("/historical/query/%s/%s", subgroveID, checkpointID)
	var response HistoricalQueryResponse
	if err := d.client.post(ctx, path, req, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// QueryHistoricalVerified queries historical data with automatic proof verification.
// Forces proof inclusion and verifies the proof against the checkpoint's state root.
func (d *DataOperations) QueryHistoricalVerified(ctx context.Context, subgroveID, checkpointID string, req *HistoricalQueryRequest) (*HistoricalQueryResponse, error) {
	// Force proof inclusion
	req.IncludeProof = true

	response, err := d.QueryHistorical(ctx, subgroveID, checkpointID, req)
	if err != nil {
		return nil, err
	}

	// Verify the proof against checkpoint state root
	if response.Proof == "" {
		return nil, NewProofError("historical query did not return proof data despite include_proof=true")
	}

	// Decode hex proof
	proofBytes, err := hex.DecodeString(strings.TrimPrefix(response.Proof, "0x"))
	if err != nil {
		return nil, NewProofError(fmt.Sprintf("failed to decode historical proof hex: %v", err))
	}

	// Verify proof and compare with state root
	result, err := grovedb.VerifyProof(proofBytes)
	if err != nil {
		return nil, NewProofError(fmt.Sprintf("failed to verify historical proof: %v", err))
	}

	// Normalize and compare root hashes
	computedRoot := strings.ToLower(strings.TrimPrefix(result.RootHash, "0x"))
	expectedRoot := strings.ToLower(strings.TrimPrefix(response.StateRoot, "0x"))

	if computedRoot != expectedRoot {
		return nil, NewProofError(fmt.Sprintf(
			"historical proof verification failed: computed root %s does not match checkpoint state root %s",
			result.RootHash, response.StateRoot))
	}

	return response, nil
}
