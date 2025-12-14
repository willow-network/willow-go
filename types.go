// Package willow provides a Go SDK for interacting with the Willow network.
package willow

import (
	"encoding/json"
	"time"
)

// SignatureAlgorithm represents the cryptographic algorithm used for signatures.
type SignatureAlgorithm string

const (
	// Ed25519 is the Ed25519 signature algorithm.
	Ed25519 SignatureAlgorithm = "Ed25519"
	// Secp256k1 is the secp256k1 signature algorithm.
	Secp256k1 SignatureAlgorithm = "secp256k1"
)

// KeyType returns the DID key type string for this algorithm.
func (a SignatureAlgorithm) KeyType() string {
	switch a {
	case Ed25519:
		return "Ed25519VerificationKey2018"
	case Secp256k1:
		return "EcdsaSecp256k1VerificationKey2019"
	default:
		return ""
	}
}

// PublicKey represents a public key in a DID document.
type PublicKey struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	PublicKeyHex string `json:"public_key_hex,omitempty"`
}

// DidDocument represents a DID (Decentralized Identifier) document.
type DidDocument struct {
	ID         string      `json:"id"`
	PublicKeys []PublicKey `json:"public_keys"`
	Created    int64       `json:"created"`
	Updated    int64       `json:"updated"`
}

// DidInfo contains information about a DID including its balance.
type DidInfo struct {
	Did       string       `json:"did"`
	Document  *DidDocument `json:"document,omitempty"`
	Balance   uint64       `json:"balance"`
	Nonce     uint64       `json:"nonce"`
	CreatedAt int64        `json:"created_at"`
}

// AuthenticationChallenge represents a challenge for DID authentication.
type AuthenticationChallenge struct {
	Challenge string `json:"challenge"`
	Nonce     string `json:"nonce"`
	ExpiresAt int64  `json:"expires_at"`
}

// AuthenticationResponse represents the response to an authentication challenge.
type AuthenticationResponse struct {
	Did         string `json:"did"`
	Challenge   string `json:"challenge"`
	Nonce       string `json:"nonce"`
	Signature   string `json:"signature"`
	PublicKeyID string `json:"public_key_id"`
}

// Session represents an authenticated session.
type Session struct {
	Did       string `json:"did"`
	Token     string `json:"token,omitempty"`
	ExpiresAt int64  `json:"expires_at"`
}

// IsExpired checks if the session has expired.
func (s *Session) IsExpired() bool {
	return time.Now().Unix() > s.ExpiresAt
}

// SchemaField defines a field in a schema.
type SchemaField struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Required bool   `json:"required,omitempty"`
	Indexed  bool   `json:"indexed,omitempty"`
}

// IndexType represents the type of index.
type IndexType string

const (
	IndexTypeHash     IndexType = "hash"
	IndexTypeRange    IndexType = "range"
	IndexTypeFullText IndexType = "fulltext"
	IndexTypeInverted IndexType = "inverted"
)

// IndexDefinition defines an index on a schema.
type IndexDefinition struct {
	Name   string    `json:"name"`
	Fields []string  `json:"fields"`
	Type   IndexType `json:"type"`
	Unique bool      `json:"unique,omitempty"`
}

// SchemaDefinition defines the schema for a subgrove.
type SchemaDefinition struct {
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Fields      []SchemaField     `json:"fields"`
	Indexes     []IndexDefinition `json:"indexes,omitempty"`
}

// AppType represents the type of application.
type AppType string

const (
	AppTypeStandard AppType = "standard"
	AppTypeIndexer  AppType = "indexer"
)

// RegisterAppRequest represents a request to register a new app.
type RegisterAppRequest struct {
	AppID       string   `json:"app_id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	AppType     AppType  `json:"app_type"`
	OwnerDid    string   `json:"owner_did"`
	Admins      []string `json:"admins,omitempty"`
}

// AppRegistration represents a registered application.
type AppRegistration struct {
	AppID       string   `json:"app_id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	AppType     AppType  `json:"app_type"`
	OwnerDid    string   `json:"owner_did"`
	Admins      []string `json:"admins,omitempty"`
	Balance     uint64   `json:"balance"`
	CreatedAt   int64    `json:"created_at"`
	UpdatedAt   int64    `json:"updated_at"`
}

// RegisterSubgroveRequest represents a request to register a new subgrove.
type RegisterSubgroveRequest struct {
	SubgroveID  string           `json:"subgrove_id"`
	AppID       string           `json:"app_id"`
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Schema      SchemaDefinition `json:"schema"`
	OwnerDid    string           `json:"owner_did"`
	Writers     []string         `json:"writers,omitempty"`
	Readers     []string         `json:"readers,omitempty"`
	RewardRate  uint64           `json:"reward_rate,omitempty"`
}

// SubgroveRegistration represents a registered subgrove.
type SubgroveRegistration struct {
	SubgroveID  string           `json:"subgrove_id"`
	AppID       string           `json:"app_id"`
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Schema      SchemaDefinition `json:"schema"`
	OwnerDid    string           `json:"owner_did"`
	Writers     []string         `json:"writers,omitempty"`
	Readers     []string         `json:"readers,omitempty"`
	RewardRate  uint64           `json:"reward_rate,omitempty"`
	ItemCount   uint64           `json:"item_count"`
	StorageUsed uint64           `json:"storage_used"`
	CreatedAt   int64            `json:"created_at"`
	UpdatedAt   int64            `json:"updated_at"`
}

// TokenInfo represents information about the WILL token.
type TokenInfo struct {
	Name              string `json:"name"`
	Symbol            string `json:"symbol"`
	Decimals          uint8  `json:"decimals"`
	TotalSupply       uint64 `json:"total_supply"`
	CirculatingSupply uint64 `json:"circulating_supply"`
}

// BalanceInfo represents balance information for a DID or app.
type BalanceInfo struct {
	ID        string `json:"id"`
	Balance   uint64 `json:"balance"`
	Available uint64 `json:"available"`
	Locked    uint64 `json:"locked"`
}

// FeeSchedule represents the fee schedule for storage operations.
type FeeSchedule struct {
	StorageFeePerByte  uint64 `json:"storage_fee_per_byte"`
	QueryFeeBase       uint64 `json:"query_fee_base"`
	QueryFeePerResult  uint64 `json:"query_fee_per_result"`
	TransactionFeeBase uint64 `json:"transaction_fee_base"`
}

// ValidatorStatus represents the status of a validator.
type ValidatorStatus string

const (
	ValidatorStatusActive   ValidatorStatus = "active"
	ValidatorStatusInactive ValidatorStatus = "inactive"
	ValidatorStatusJailed   ValidatorStatus = "jailed"
)

// ValidatorInfo represents information about a validator.
type ValidatorInfo struct {
	Address     string          `json:"address"`
	PublicKey   string          `json:"public_key"`
	VotingPower int64           `json:"voting_power"`
	Status      ValidatorStatus `json:"status"`
	Commission  float64         `json:"commission"`
	Moniker     string          `json:"moniker,omitempty"`
	Website     string          `json:"website,omitempty"`
	Details     string          `json:"details,omitempty"`
}

// QueryFilter represents a filter condition for queries.
type QueryFilter struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

// QuerySort represents sorting options for queries.
type QuerySort struct {
	Field     string `json:"field"`
	Ascending bool   `json:"ascending"`
}

// QuerySearch represents full-text search options.
type QuerySearch struct {
	Fields []string `json:"fields"`
	Query  string   `json:"query"`
}

// QueryRequest represents a query request.
type QueryRequest struct {
	Filters      []QueryFilter `json:"filters,omitempty"`
	Search       *QuerySearch  `json:"search,omitempty"`
	Sort         *QuerySort    `json:"sort,omitempty"`
	Limit        int           `json:"limit,omitempty"`
	Offset       int           `json:"offset,omitempty"`
	IncludeProof bool          `json:"include_proof,omitempty"`
}

// QueryResult represents a single result from a query.
type QueryResult struct {
	Key  string                 `json:"key"`
	Data map[string]interface{} `json:"data"`
}

// QueryResponse represents the response to a query.
type QueryResponse struct {
	Results    []QueryResult `json:"results"`
	TotalCount int           `json:"total_count"`
	HasMore    bool          `json:"has_more"`
	Proof      []byte        `json:"proof,omitempty"`
}

// GraphQLRequest represents a GraphQL query request.
type GraphQLRequest struct {
	Query         string                 `json:"query"`
	Variables     map[string]interface{} `json:"variables,omitempty"`
	OperationName string                 `json:"operation_name,omitempty"`
	IncludeProof  bool                   `json:"include_proof,omitempty"`
}

// GraphQLError represents a GraphQL error.
type GraphQLError struct {
	Message    string                 `json:"message"`
	Locations  []GraphQLLocation      `json:"locations,omitempty"`
	Path       []interface{}          `json:"path,omitempty"`
	Extensions map[string]interface{} `json:"extensions,omitempty"`
}

// GraphQLLocation represents a location in a GraphQL query.
type GraphQLLocation struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

// GraphQLResponse represents a GraphQL query response.
type GraphQLResponse struct {
	Data   json.RawMessage `json:"data,omitempty"`
	Errors []GraphQLError  `json:"errors,omitempty"`
	Proof  []byte          `json:"proof,omitempty"`
}

// SubgraphInfo represents information about a subgraph (indexed blockchain data).
type SubgraphInfo struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Description  string `json:"description,omitempty"`
	Network      string `json:"network"`
	StartBlock   uint64 `json:"start_block"`
	CurrentBlock uint64 `json:"current_block"`
	Status       string `json:"status"`
	CreatedAt    int64  `json:"created_at"`
	UpdatedAt    int64  `json:"updated_at"`
}

// IndexerInfo represents information about an indexer node.
type IndexerInfo struct {
	ID          string   `json:"id"`
	Address     string   `json:"address"`
	Stake       uint64   `json:"stake"`
	Subgraphs   []string `json:"subgraphs"`
	Status      string   `json:"status"`
	Performance float64  `json:"performance"`
}

// HealthStatus represents the health status of a node.
type HealthStatus struct {
	Healthy     bool   `json:"healthy"`
	Version     string `json:"version"`
	NodeID      string `json:"node_id"`
	Network     string `json:"network"`
	BlockHeight int64  `json:"block_height"`
	SyncStatus  string `json:"sync_status"`
}

// DataProof represents a proof for data retrieval.
type DataProof struct {
	Proof      []byte `json:"proof"`
	RootHash   string `json:"root_hash"`
	Height     int64  `json:"height"`
	VerifiedAt int64  `json:"verified_at"`
}

// DataResponse represents the response from a data retrieval operation.
type DataResponse struct {
	Key   string                 `json:"key"`
	Data  map[string]interface{} `json:"data"`
	Proof *DataProof             `json:"proof,omitempty"`
}

// StoreRequest represents a request to store data.
type StoreRequest struct {
	Key  string                 `json:"key,omitempty"`
	Data map[string]interface{} `json:"data"`
}

// BatchStoreRequest represents a request to store multiple items.
type BatchStoreRequest struct {
	Items []StoreRequest `json:"items"`
}

// ApiResponse represents a generic API response.
type ApiResponse[T any] struct {
	Success bool   `json:"success"`
	Data    T      `json:"data,omitempty"`
	Error   string `json:"error,omitempty"`
}

// Permission represents a permission entry.
type Permission struct {
	Did        string   `json:"did"`
	AppID      string   `json:"app_id"`
	SubgroveID string   `json:"subgrove_id,omitempty"`
	Actions    []string `json:"actions"`
	GrantedBy  string   `json:"granted_by"`
	GrantedAt  int64    `json:"granted_at"`
	ExpiresAt  *int64   `json:"expires_at,omitempty"`
}

// TransferRequest represents a request to transfer tokens.
type TransferRequest struct {
	FromDid string `json:"from_did"`
	ToDid   string `json:"to_did"`
	Amount  uint64 `json:"amount"`
	Memo    string `json:"memo,omitempty"`
}

// RetryConfig contains configuration for retry behavior.
type RetryConfig struct {
	MaxRetries     int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	BackoffFactor  float64
}

// DefaultRetryConfig returns the default retry configuration.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:     3,
		InitialBackoff: 100 * time.Millisecond,
		MaxBackoff:     5 * time.Second,
		BackoffFactor:  2.0,
	}
}
