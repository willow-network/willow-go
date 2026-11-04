package consensus

import (
	"encoding/json"
	"fmt"
)

// ByteArray is a []byte with JSON marshaling as a number array.
//
// The consensus Transaction enum stores `signature: Vec<u8>`, which
// serde_json serializes as a JSON array of integers (`[1, 2, 3, ...]`).
// Go's default `json.Marshal([]byte)` emits a base64 string instead —
// validator rejects that with "invalid type: string, expected a sequence".
// Every tx-type `Signature` field uses this instead of raw `[]byte`.
type ByteArray []byte

// MarshalJSON outputs the underlying bytes as a JSON array of integers.
func (b ByteArray) MarshalJSON() ([]byte, error) {
	ints := make([]int, len(b))
	for i, v := range b {
		ints[i] = int(v)
	}
	return json.Marshal(ints)
}

// UnmarshalJSON accepts either a JSON array of integers (canonical) or a
// base64 string (for back-compat with any caller that still sends one).
func (b *ByteArray) UnmarshalJSON(data []byte) error {
	var ints []int
	if err := json.Unmarshal(data, &ints); err == nil {
		out := make([]byte, len(ints))
		for i, v := range ints {
			out[i] = byte(v)
		}
		*b = out
		return nil
	}
	var raw []byte
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*b = raw
	return nil
}

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
	Signature   ByteArray      `json:"signature"`
	PublicKeyID string      `json:"public_key_id"`
	Nonce       uint64      `json:"nonce"`
}

// ReadPricing is a subgrove's pricing for paid reads.
type ReadPricing struct {
	Enabled bool `json:"enabled"`
	// PricePerQuery is in the smallest token unit (10^-18 WILL).
	PricePerQuery Uint128 `json:"price_per_query"`
	// OwnerRevenueShareBps is the owner's share of revenue in basis points
	// (0-10000); the rest goes to the protocol treasury.
	OwnerRevenueShareBps uint32 `json:"owner_revenue_share_bps"`
}

// SubgroveDataStorage holds configuration for DataStorage mode. Nil slices are
// sent as empty lists, and a nil ReadPricing as null (no paid reads).
type SubgroveDataStorage struct {
	Name        string       `json:"name"`
	Writers     []string     `json:"writers"`
	FreeReaders []string     `json:"free_readers"`
	ReadPricing *ReadPricing `json:"read_pricing"`
}

// MarshalJSON sends every field, nil slices as empty lists.
func (m SubgroveDataStorage) MarshalJSON() ([]byte, error) {
	type plain SubgroveDataStorage
	p := plain(m)
	p.Writers = orEmpty(p.Writers)
	p.FreeReaders = orEmpty(p.FreeReaders)
	return json.Marshal(p)
}

// SubgroveFileStorage holds configuration for FileStorage mode. Nil slices are
// sent as empty lists, and a nil ReadPricing as null (no paid downloads).
type SubgroveFileStorage struct {
	Name string `json:"name"`
	// MaxFileSize is the largest file the subgrove accepts, in bytes.
	MaxFileSize uint64 `json:"max_file_size"`
	// ReplicationFactor is the least number of storage nodes holding each file.
	ReplicationFactor uint8        `json:"replication_factor"`
	Writers           []string     `json:"writers"`
	FreeReaders       []string     `json:"free_readers"`
	ReadPricing       *ReadPricing `json:"read_pricing"`
	// RetentionPeriod is in seconds; 0 keeps files permanently.
	RetentionPeriod uint64 `json:"retention_period"`
}

// MarshalJSON sends every field, nil slices as empty lists.
func (m SubgroveFileStorage) MarshalJSON() ([]byte, error) {
	type plain SubgroveFileStorage
	p := plain(m)
	p.Writers = orEmpty(p.Writers)
	p.FreeReaders = orEmpty(p.FreeReaders)
	return json.Marshal(p)
}

// RetentionWindow specifies how long real-time indexed data is retained on consensus nodes.
type RetentionWindow struct {
	Type  string `json:"type"`            // "Blocks", "Seconds", "Indefinite", or "VerifyOnly"
	Value uint64 `json:"value,omitempty"`
}

// SubgroveBlockchainIndexing holds configuration for BlockchainIndexing mode.
//
// Its fields don't encode the chain's indexing mode, so FormatRegisterSubgroveMessage
// refuses a registration in this mode.
type SubgroveBlockchainIndexing struct {
	ManifestContent []byte           `json:"manifest_content,omitempty"`
	WasmModules     []any            `json:"wasm_modules,omitempty"`
	ExecutionMode   any              `json:"execution_mode,omitempty"`
	IndexerConfig   any              `json:"indexer_config,omitempty"`
	RetentionWindow *RetentionWindow `json:"retention_window,omitempty"`
}

// SubgroveMode represents the mode of a subgrove: DataStorage, FileStorage, or
// BlockchainIndexing. Exactly one field should be non-nil.
type SubgroveMode struct {
	DataStorage        *SubgroveDataStorage        `json:"DataStorage,omitempty"`
	FileStorage        *SubgroveFileStorage        `json:"FileStorage,omitempty"`
	BlockchainIndexing *SubgroveBlockchainIndexing `json:"BlockchainIndexing,omitempty"`
}

// TeeType is a trusted execution environment a subgrove can require of
// checkpoint submissions.
type TeeType string

// The TEE types the chain knows.
const (
	TeeAwsNitro TeeType = "AwsNitro"
	TeeIntelSgx TeeType = "IntelSgx"
	TeeAmdSev   TeeType = "AmdSev"
)

// CheckpointVerificationConfig is a subgrove's checkpoint verification
// configuration.
type CheckpointVerificationConfig struct {
	// RequiredTEE, when set, requires checkpoint submissions to carry an
	// attestation from this TEE type.
	RequiredTEE *TeeType `json:"required_tee"`
}

// RegisterSubgroveTx represents a subgrove registration transaction, sent as
// {"RegisterSubgrove": tx}. Every field is sent, so the chain decodes exactly
// the values the signature covers: nil slices go as empty lists, a nil Mode as
// the chain's default (DataStorage with an empty name and lists, no read
// pricing), and other nil optional fields as null.
//
// It is signed over FormatRegisterSubgroveMessage (in the willow package),
// whose Config line is the SHA-256 of RegisterSubgroveUnsignedBincode of the
// JSON sent.
type RegisterSubgroveTx struct {
	SubgroveID  string `json:"subgrove_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	// Schema is the subgrove's document schema as JSON text, in the chain's
	// form: {"version":1,"fields":{...},"indexes":[...],"required_fields":[...]}.
	Schema   string   `json:"schema"`
	OwnerDid string   `json:"owner_did"`
	Admins   []string `json:"admins"`
	// InitialFunding, when set, funds the subgrove in the same transaction (in
	// the smallest token unit).
	InitialFunding         *Uint128                     `json:"initial_funding"`
	CheckpointVerification CheckpointVerificationConfig `json:"checkpoint_verification"`
	Mode                   *SubgroveMode                `json:"mode"`
	Privacy                *PrivacyConfig               `json:"privacy"`
	InitialOwnerKeyGrant   *EncryptedKeyGrant           `json:"initial_owner_key_grant"`
	// TemplateConfig is the chain's TemplateSubgroveConfig as JSON; nil sends null.
	TemplateConfig json.RawMessage `json:"template_config"`
	// ConfirmationDepth is the number of blocks held in the chain-tip buffer
	// before submissions fire.
	ConfirmationDepth         uint32    `json:"confirmation_depth"`
	Signature                 ByteArray `json:"signature"`
	PublicKeyID               string    `json:"public_key_id"`
	Nonce                     uint64    `json:"nonce"`
	CryptographicCompleteness bool      `json:"cryptographic_completeness"`
}

// MarshalJSON sends every field, nil slices as empty lists and a nil Mode as
// the chain's default DataStorage (the chain refuses a null mode).
func (tx RegisterSubgroveTx) MarshalJSON() ([]byte, error) {
	type plain RegisterSubgroveTx
	p := plain(tx)
	p.Admins = orEmpty(p.Admins)
	if p.Mode == nil {
		p.Mode = &SubgroveMode{DataStorage: &SubgroveDataStorage{}}
	}
	return json.Marshal(p)
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// TransferTx represents a token transfer transaction.
type TransferTx struct {
	FromDid     string `json:"from_did"`
	ToDid       string `json:"to_did"`
	Amount      uint64 `json:"amount"`
	Memo        string `json:"memo,omitempty"`
	Signature   ByteArray `json:"signature"`
	PublicKeyID string `json:"public_key_id"`
	Nonce       uint64 `json:"nonce"`
}

// DataStoreTx represents a data storage transaction, sent as {"StoreData": tx}.
type DataStoreTx struct {
	SubgroveID string `json:"subgrove_id"`
	Key        string `json:"key"`
	// Data is the JSON text of the stored object as UTF-8 bytes. The chain
	// reads it as bytes, so it is sent as a JSON array of byte values, and the
	// signed message hashes exactly these bytes.
	Data        ByteArray `json:"data"`
	OwnerDid    string    `json:"owner_did"`
	Signature   ByteArray `json:"signature"`
	PublicKeyID string    `json:"public_key_id"`
	Nonce       uint64    `json:"nonce"`
}

// DataDeleteTx represents a data deletion transaction.
type DataDeleteTx struct {
	SubgroveID  string `json:"subgrove_id"`
	Key         string `json:"key"`
	OwnerDid    string `json:"owner_did"`
	Signature   ByteArray `json:"signature"`
	PublicKeyID string `json:"public_key_id"`
	Nonce       uint64 `json:"nonce"`
}

// FundSubgroveTx represents a transaction to fund a subgrove.
type FundSubgroveTx struct {
	FromDid     string `json:"from_did"`
	SubgroveID  string `json:"subgrove_id"`
	Amount      uint64 `json:"amount"`
	Signature   ByteArray `json:"signature"`
	PublicKeyID string `json:"public_key_id"`
	Nonce       uint64 `json:"nonce"`
}

// DeregisterSubgroveTx represents a transaction to deregister (delete) a subgrove.
// Remaining funding balance is refunded to the owner.
type DeregisterSubgroveTx struct {
	SubgroveID  string `json:"subgrove_id"`
	OwnerDid    string `json:"owner_did"`
	Signature   ByteArray `json:"signature"`
	PublicKeyID string `json:"public_key_id"`
	Nonce       uint64 `json:"nonce"`
}

// DeregisterSubgroveSignMessage returns the canonical signing message for a deregister subgrove transaction.
func DeregisterSubgroveSignMessage(subgroveID, ownerDid string, nonce uint64) string {
	return fmt.Sprintf("DeregisterSubgrove:%s:%s:%d", subgroveID, ownerDid, nonce)
}
