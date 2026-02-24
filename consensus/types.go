package consensus

import "encoding/json"

// TransactionStatus represents the status of a transaction.
type TransactionStatus string

const (
	TransactionStatusPending  TransactionStatus = "pending"
	TransactionStatusSuccess  TransactionStatus = "success"
	TransactionStatusFailed   TransactionStatus = "failed"
	TransactionStatusNotFound TransactionStatus = "not_found"
)

// BroadcastResult represents the result of broadcasting a transaction.
type BroadcastResult struct {
	Success      bool   `json:"success"`
	TxHash       string `json:"tx_hash,omitempty"`
	Height       int64  `json:"height,omitempty"`
	ErrorCode    int    `json:"error_code,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
	RawLog       string `json:"raw_log,omitempty"`
}

// TxResult represents the result of querying a transaction.
type TxResult struct {
	Hash    string            `json:"hash"`
	Height  int64             `json:"height"`
	Index   uint32            `json:"index"`
	Status  TransactionStatus `json:"status"`
	Code    uint32            `json:"code"`
	Log     string            `json:"log"`
	GasUsed int64             `json:"gas_used"`
	GasWant int64             `json:"gas_wanted"`
	Data    json.RawMessage   `json:"data,omitempty"`
}

// Transaction represents a generic transaction envelope.
type Transaction struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

// RegisterDidTx represents a DID registration transaction.
type RegisterDidTx struct {
	DidDocument interface{} `json:"did_document"`
	Signature   []byte      `json:"signature"`
	PublicKeyID string      `json:"public_key_id"`
	Nonce       uint64      `json:"nonce"`
}

// RegisterAppTx represents an app registration transaction.
type RegisterAppTx struct {
	AppID       string   `json:"app_id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	AppType     string   `json:"app_type"`
	OwnerDid    string   `json:"owner_did"`
	Admins      []string `json:"admins,omitempty"`
	Signature   []byte   `json:"signature"`
	PublicKeyID string   `json:"public_key_id"`
	Nonce       uint64   `json:"nonce"`
}

// SubgroveDataStorage holds configuration for DataStorage mode.
type SubgroveDataStorage struct {
	Name                  string   `json:"name"`
	Writers               []string `json:"writers,omitempty"`
	FreeReaders           []string `json:"free_readers,omitempty"`
	ReadPricing           any      `json:"read_pricing,omitempty"`
	RequiredVerifications int      `json:"required_verifications,omitempty"`
}

// SubgroveBlockchainIndexing holds configuration for BlockchainIndexing mode.
type SubgroveBlockchainIndexing struct {
	ManifestIPFS    string `json:"manifest_ipfs"`
	ManifestContent []byte `json:"manifest_content,omitempty"`
	WasmModules     []any  `json:"wasm_modules,omitempty"`
	ExecutionMode   any    `json:"execution_mode,omitempty"`
	IndexerConfig   any    `json:"indexer_config,omitempty"`
}

// SubgroveMode represents the mode of a subgrove: DataStorage or BlockchainIndexing.
// Exactly one field should be non-nil.
type SubgroveMode struct {
	DataStorage        *SubgroveDataStorage        `json:"DataStorage,omitempty"`
	BlockchainIndexing *SubgroveBlockchainIndexing  `json:"BlockchainIndexing,omitempty"`
}

// RegisterSubgroveTx represents a subgrove registration transaction.
type RegisterSubgroveTx struct {
	SubgroveID  string        `json:"subgrove_id"`
	AppID       string        `json:"app_id"`
	Schema      string        `json:"schema"`
	OwnerDid    string        `json:"owner_did"`
	Mode        *SubgroveMode `json:"mode,omitempty"`
	Signature   []byte        `json:"signature"`
	PublicKeyID string        `json:"public_key_id"`
	Nonce       uint64        `json:"nonce"`
}

// TransferTx represents a token transfer transaction.
type TransferTx struct {
	FromDid     string `json:"from_did"`
	ToDid       string `json:"to_did"`
	Amount      uint64 `json:"amount"`
	Memo        string `json:"memo,omitempty"`
	Signature   []byte `json:"signature"`
	PublicKeyID string `json:"public_key_id"`
	Nonce       uint64 `json:"nonce"`
}

// DataStoreTx represents a data storage transaction.
type DataStoreTx struct {
	AppID       string          `json:"app_id"`
	SubgroveID  string          `json:"subgrove_id"`
	Key         string          `json:"key"`
	Data        json.RawMessage `json:"data"`
	OwnerDid    string          `json:"owner_did"`
	Signature   []byte          `json:"signature"`
	PublicKeyID string          `json:"public_key_id"`
	Nonce       uint64          `json:"nonce"`
}

// DataDeleteTx represents a data deletion transaction.
type DataDeleteTx struct {
	AppID       string `json:"app_id"`
	SubgroveID  string `json:"subgrove_id"`
	Key         string `json:"key"`
	OwnerDid    string `json:"owner_did"`
	Signature   []byte `json:"signature"`
	PublicKeyID string `json:"public_key_id"`
	Nonce       uint64 `json:"nonce"`
}

// FundAppTx represents a transaction to fund an app.
type FundAppTx struct {
	FromDid     string `json:"from_did"`
	AppID       string `json:"app_id"`
	Amount      uint64 `json:"amount"`
	Signature   []byte `json:"signature"`
	PublicKeyID string `json:"public_key_id"`
	Nonce       uint64 `json:"nonce"`
}
