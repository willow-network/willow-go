// Package willow provides a Go SDK for interacting with the Willow network.
package willow

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/willow-network/willow-go/consensus"
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

// RegisterSubgroveRequest represents a request to register a new subgrove.
type RegisterSubgroveRequest struct {
	SubgroveID  string           `json:"subgrove_id"`
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
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Schema      SchemaDefinition `json:"schema"`
	OwnerDid    string           `json:"owner_did"`
	Writers     []string         `json:"writers,omitempty"`
	Readers     []string         `json:"free_readers,omitempty"`
	RewardRate  uint64           `json:"reward_rate,omitempty"`
	ItemCount   uint64           `json:"item_count"`
	StorageUsed uint64           `json:"storage_used"`
	CreatedAt   int64            `json:"created_at"`
	UpdatedAt   int64            `json:"updated_at"`
}

// TokenInfo represents information about the WILL token. Supplies are decimal
// strings of the smallest unit: the API sends them as u128 numbers.
type TokenInfo struct {
	Name              string `json:"name"`
	Symbol            string `json:"symbol"`
	Decimals          uint8  `json:"decimals"`
	GenesisSupply     string `json:"genesis_supply"`
	MintedSupply      string `json:"minted_supply"`
	MaxSupply         string `json:"max_supply"`
	CirculatingSupply string `json:"circulating_supply"`
}

// UnmarshalJSON reads the supplies from JSON numbers (as the API sends them)
// or decimal strings.
func (t *TokenInfo) UnmarshalJSON(data []byte) error {
	type plain TokenInfo
	var raw struct {
		plain
		GenesisSupply     amountString `json:"genesis_supply"`
		MintedSupply      amountString `json:"minted_supply"`
		MaxSupply         amountString `json:"max_supply"`
		CirculatingSupply amountString `json:"circulating_supply"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*t = TokenInfo(raw.plain)
	t.GenesisSupply = string(raw.GenesisSupply)
	t.MintedSupply = string(raw.MintedSupply)
	t.MaxSupply = string(raw.MaxSupply)
	t.CirculatingSupply = string(raw.CirculatingSupply)
	return nil
}

// BalanceInfo is a DID's balance, in the smallest token unit (10^-18 WILL).
type BalanceInfo struct {
	DID string `json:"did"`
	// Available is the spendable balance.
	Available consensus.Uint128 `json:"available"`
	// Staked is the amount staked with validators.
	Staked consensus.Uint128 `json:"staked"`
	// Locked is the amount unbonding.
	Locked consensus.Uint128 `json:"locked"`
}

// FeeSchedule represents the fee schedule for operations. Fees are decimal
// strings of the smallest unit: the API sends them as u128 numbers.
type FeeSchedule struct {
	DidRegistration      string `json:"did_registration"`
	SubgroveRegistration string `json:"subgrove_registration"`
	BaseTxCost           string `json:"base_tx_cost"`
	CostPerByte          string `json:"cost_per_byte"`
	QueryFee             string `json:"query_fee"`
	TransferFeePercentage uint32 `json:"transfer_fee_percentage"`
	MaxTxSizeBytes       uint64 `json:"max_tx_size_bytes"`
	MaxDataPayloadBytes  uint64 `json:"max_data_payload_bytes"`
}

// UnmarshalJSON reads the fees from JSON numbers (as the API sends them) or
// decimal strings.
func (f *FeeSchedule) UnmarshalJSON(data []byte) error {
	type plain FeeSchedule
	var raw struct {
		plain
		DidRegistration      amountString `json:"did_registration"`
		SubgroveRegistration amountString `json:"subgrove_registration"`
		BaseTxCost           amountString `json:"base_tx_cost"`
		CostPerByte          amountString `json:"cost_per_byte"`
		QueryFee             amountString `json:"query_fee"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*f = FeeSchedule(raw.plain)
	f.DidRegistration = string(raw.DidRegistration)
	f.SubgroveRegistration = string(raw.SubgroveRegistration)
	f.BaseTxCost = string(raw.BaseTxCost)
	f.CostPerByte = string(raw.CostPerByte)
	f.QueryFee = string(raw.QueryFee)
	return nil
}

// amountString decodes a u128 amount, a JSON number or decimal string, into
// its decimal digits.
type amountString string

func (a *amountString) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}
	var u consensus.Uint128
	if err := u.UnmarshalJSON(data); err != nil {
		return err
	}
	*a = amountString(u.String())
	return nil
}

// ValidatorStatus represents the status of a validator.
type ValidatorStatus string

const (
	ValidatorStatusActive   ValidatorStatus = "active"
	ValidatorStatusInactive ValidatorStatus = "inactive"
	ValidatorStatusJailed   ValidatorStatus = "jailed"
)

// ValidatorInfo is a validator as the API's /validators routes answer: its
// DID, stakes in the smallest token unit (10^-18 WILL), and state.
type ValidatorInfo struct {
	DID        string            `json:"did"`
	TotalStake consensus.Uint128 `json:"total_stake"`
	SelfStake  consensus.Uint128 `json:"self_stake"`
	Active     bool              `json:"active"`
	Jailed     bool              `json:"jailed"`
	// JailEndTime is the Unix time a jailed validator's jail ends.
	JailEndTime     *uint64 `json:"jail_end_time,omitempty"`
	ConsensusPubkey string  `json:"consensus_pubkey,omitempty"`
}

// Status returns the validator's status: jailed, active, or inactive.
func (v ValidatorInfo) Status() ValidatorStatus {
	switch {
	case v.Jailed:
		return ValidatorStatusJailed
	case v.Active:
		return ValidatorStatusActive
	}
	return ValidatorStatusInactive
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
	IncludeProof *bool         `json:"include_proof,omitempty"`
}

// QueryResult represents a single result from a query. The API's /query
// answers with the matching documents alone, so Key is empty for its results.
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
	// Height is the block height the proof was generated at.
	Height uint64 `json:"height,omitempty"`
}

// HistoricalQueryRequest represents a request for historical checkpoint data.
// It is sent with Path and Key as arrays of byte values, and IncludeProof
// even when false (the API's default is true).
type HistoricalQueryRequest struct {
	Path         [][]byte `json:"path"`                 // GroveDB path as byte arrays
	Key          []byte   `json:"key,omitempty"`        // Key to query (for single-key queries)
	QueryType    string   `json:"query_type,omitempty"` // Query type: "get", "get_range", "get_path"
	IncludeProof bool     `json:"include_proof"`        // Whether to include proof
}

// MarshalJSON writes the request as the API reads it: Path and Key as arrays
// of byte values (a Vec<u8>), not base64.
func (r HistoricalQueryRequest) MarshalJSON() ([]byte, error) {
	path := make([]consensus.ByteArray, len(r.Path))
	for i, segment := range r.Path {
		path[i] = segment
	}
	var key *consensus.ByteArray
	if r.Key != nil {
		k := consensus.ByteArray(r.Key)
		key = &k
	}
	return json.Marshal(struct {
		Path         []consensus.ByteArray `json:"path"`
		Key          *consensus.ByteArray  `json:"key,omitempty"`
		QueryType    string                `json:"query_type,omitempty"`
		IncludeProof bool                  `json:"include_proof"`
	}{path, key, r.QueryType, r.IncludeProof})
}

// HistoricalQueryResponse represents the response from a historical query.
type HistoricalQueryResponse struct {
	Success          bool        `json:"success"`
	ProviderDID      string      `json:"provider_did,omitempty"`
	ProviderEndpoint string      `json:"provider_endpoint,omitempty"`
	StateRoot        string      `json:"state_root"`      // Checkpoint state root, as the answer reports it (unverified)
	BlockRange       [2]uint64   `json:"block_range"`     // Block range covered by the checkpoint
	Data             interface{} `json:"data"`            // Query results from the indexer
	Proof            string      `json:"proof,omitempty"` // Merkle proof (hex-encoded), unverified
	CanReindex       bool        `json:"can_reindex"`     // Whether data can be re-indexed
	Error            string      `json:"error,omitempty"` // Error message if any
}

// CheckpointInfo represents information about a checkpoint.
type CheckpointInfo struct {
	CheckpointID string    `json:"checkpoint_id"`
	SubgroveID   string    `json:"subgrove_id"`
	StateRoot    string    `json:"state_root"` // State root hash (hex)
	BlockRange   [2]uint64 `json:"block_range"`
	IndexerDID   string    `json:"indexer_did"`
	SubmittedAt  uint64    `json:"submitted_at"` // Unix timestamp
	IsTrusted    bool      `json:"is_trusted"`
}

// GraphQLRequest represents a GraphQL query request.
type GraphQLRequest struct {
	Query         string                 `json:"query"`
	Variables     map[string]interface{} `json:"variables,omitempty"`
	OperationName string                 `json:"operation_name,omitempty"`
	IncludeProof  *bool                  `json:"include_proof,omitempty"`
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
//
// Proof is the proof object the answer carries, as JSON, unverified (the SDK
// can't verify it; see IndexingOperations), or nil when it carries none.
type GraphQLResponse struct {
	Data   json.RawMessage `json:"data,omitempty"`
	Errors []GraphQLError  `json:"errors,omitempty"`
	Proof  json.RawMessage `json:"proof,omitempty"`
}

// UnmarshalJSON reads a GraphQL answer, leaving Proof nil when the answer's
// proof is null or absent.
func (r *GraphQLResponse) UnmarshalJSON(b []byte) error {
	type plain GraphQLResponse
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	if string(bytes.TrimSpace(p.Proof)) == "null" {
		p.Proof = nil
	}
	*r = GraphQLResponse(p)
	return nil
}

// SqlRequest represents a SQL query request
type SqlRequest struct {
	Query        string `json:"query"`
	IncludeProof *bool  `json:"include_proof,omitempty"`
}

// SqlResponse represents the response from a SQL query
type SqlResponse struct {
	Columns  []string        `json:"columns"`
	Rows     [][]interface{} `json:"rows"`
	Total    *uint64         `json:"total,omitempty"`
	Warnings []string        `json:"warnings,omitempty"`
	Proof    *QueryProof     `json:"proof,omitempty"`
}

// QueryProof is the Merkle proof data a SQL answer carries, returned
// unverified (see IndexingOperations).
type QueryProof struct {
	MerkleProofs   []MerkleProofData `json:"merkle_proofs"`
	StateRoot      []byte            `json:"state_root"`
	BlockHeight    uint64            `json:"block_height"`
	EthereumAnchor *EthereumAnchor   `json:"ethereum_anchor,omitempty"`
}

// MerkleProofData contains a single Merkle proof
type MerkleProofData struct {
	Key       string   `json:"key"`
	ValueHash []byte   `json:"value_hash"`
	Siblings  [][]byte `json:"siblings"`
	Path      string   `json:"path"`
}

// EthereumAnchor contains Ethereum anchoring information
type EthereumAnchor struct {
	BlockNumber uint64 `json:"block_number"`
	TxHash      []byte `json:"tx_hash"`
	Contract    string `json:"contract"`
}

// SubgroveInfo is a subgrove as the API's /subgroves routes answer. The list
// (ListSubgroves) carries its registration with Mode, Chain, and
// IndexerCount; one subgrove (GetSubgrove) carries Status, LatestBlock,
// DeploymentBlock, Indexers, and Chain.
type SubgroveInfo struct {
	SubgroveID  string `json:"subgrove_id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	OwnerDid    string `json:"owner_did"`
	// Mode is DataStorage or BlockchainIndexing.
	Mode string `json:"mode,omitempty"`
	// Chain is the canonical id of the chain an indexing subgrove indexes.
	Chain        string `json:"chain,omitempty"`
	IndexerCount int    `json:"indexer_count,omitempty"`
	Status       string `json:"status,omitempty"`
	// LatestBlock is the latest indexed source-chain block, 0 before any.
	LatestBlock uint64 `json:"latest_block,omitempty"`
	// DeploymentBlock is the Willow height the subgrove was registered at.
	DeploymentBlock uint64   `json:"deployment_block,omitempty"`
	Indexers        []string `json:"indexers,omitempty"`
}

// IndexerInfo represents information about an indexer node.
// Matches the validator's `GET /indexers` response shape.
type IndexerInfo struct {
	IndexerDID string   `json:"indexer_did"`
	Subgroves  []string `json:"subgroves"`
	// StakeAmount is in the smallest token unit (10^-18 WILL).
	StakeAmount consensus.Uint128 `json:"stake_amount"`
	// Endpoint is the monitoring / health endpoint (historically also used
	// for queries).
	Endpoint string `json:"endpoint"`
	// QueryEndpoint is the preferred endpoint for client query traffic
	// (GraphQL/SQL/historical). When empty, callers should fall back to
	// Endpoint. See EffectiveQueryEndpoint.
	QueryEndpoint    string  `json:"query_endpoint,omitempty"`
	Status           string  `json:"status"`
	PerformanceScore float64 `json:"performance_score"`
	LastUpdate       uint64  `json:"last_update"`
}

// EffectiveQueryEndpoint returns the URL clients should POST GraphQL/SQL
// queries to. Prefers QueryEndpoint when non-empty; falls back to Endpoint.
func (i *IndexerInfo) EffectiveQueryEndpoint() string {
	if i.QueryEndpoint != "" {
		return i.QueryEndpoint
	}
	return i.Endpoint
}

// HealthStatus represents the health status of a node. The API's /health
// answers with Status ("healthy", "degraded", or "unhealthy"), Timestamp,
// Version, and Checks; Healthy is set from Status.
type HealthStatus struct {
	Status      string                 `json:"status,omitempty"`
	Timestamp   string                 `json:"timestamp,omitempty"`
	Checks      map[string]interface{} `json:"checks,omitempty"`
	Healthy     bool                   `json:"healthy"`
	Version     string                 `json:"version"`
	NodeID      string                 `json:"node_id"`
	Network     string                 `json:"network"`
	BlockHeight int64                  `json:"block_height"`
	SyncStatus  string                 `json:"sync_status"`
}

// DataProof represents a proof for data retrieval.
type DataProof struct {
	Proof []byte `json:"proof"`
	// Path is the GroveDB path the proof descends to, and Key the key it
	// proves under it.
	Path       [][]byte `json:"path,omitempty"`
	Key        []byte   `json:"key,omitempty"`
	RootHash   string   `json:"root_hash"`
	Height     int64    `json:"height"`
	VerifiedAt int64    `json:"verified_at"`
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
	Did        string `json:"did"`
	SubgroveID string `json:"subgrove_id,omitempty"`
	// Role is the subgrove role granted, in lowercase (for example "reader").
	Role       string   `json:"role,omitempty"`
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
