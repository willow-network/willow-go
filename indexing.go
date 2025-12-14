package willow

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/willow-network/willow-go/grovedb"
)

// IndexingOperations provides methods for blockchain indexing and GraphQL queries.
type IndexingOperations struct {
	client *Client
}

// Query executes a GraphQL query against a subgraph.
func (i *IndexingOperations) Query(ctx context.Context, subgraphID string, req *GraphQLRequest) (*GraphQLResponse, error) {
	// Enable proof by default if light client is available
	if i.client.HasLightClient() {
		req.IncludeProof = true
	}

	path := fmt.Sprintf("/graphql/%s", subgraphID)
	var response GraphQLResponse
	err := i.client.post(ctx, path, req, &response)
	if err != nil {
		return nil, err
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
func (i *IndexingOperations) QueryUnverified(ctx context.Context, subgraphID string, req *GraphQLRequest) (*GraphQLResponse, error) {
	req.IncludeProof = false

	path := fmt.Sprintf("/graphql/%s", subgraphID)
	var response GraphQLResponse
	err := i.client.post(ctx, path, req, &response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

// Execute is a convenience method for executing GraphQL queries.
func (i *IndexingOperations) Execute(ctx context.Context, subgraphID, query string, variables map[string]interface{}) (*GraphQLResponse, error) {
	return i.Query(ctx, subgraphID, &GraphQLRequest{
		Query:     query,
		Variables: variables,
	})
}

// ExecuteWithResult executes a query and unmarshals the result into the provided type.
func (i *IndexingOperations) ExecuteWithResult(ctx context.Context, subgraphID, query string, variables map[string]interface{}, result interface{}) error {
	response, err := i.Execute(ctx, subgraphID, query, variables)
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

// ListSubgraphs retrieves all available subgraphs.
func (i *IndexingOperations) ListSubgraphs(ctx context.Context) ([]SubgraphInfo, error) {
	var subgraphs []SubgraphInfo
	err := i.client.get(ctx, "/subgraphs", &subgraphs)
	if err != nil {
		return nil, err
	}
	return subgraphs, nil
}

// GetSubgraph retrieves information about a specific subgraph.
func (i *IndexingOperations) GetSubgraph(ctx context.Context, subgraphID string) (*SubgraphInfo, error) {
	var subgraph SubgraphInfo
	err := i.client.get(ctx, fmt.Sprintf("/subgraphs/%s", subgraphID), &subgraph)
	if err != nil {
		return nil, err
	}
	return &subgraph, nil
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

// GetIndexerStatus retrieves the status of an indexer for a subgraph.
func (i *IndexingOperations) GetIndexerStatus(ctx context.Context, indexerID, subgraphID string) (*IndexerInfo, error) {
	var indexer IndexerInfo
	path := fmt.Sprintf("/indexers/%s/status/%s", indexerID, subgraphID)
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
