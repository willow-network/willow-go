package lightclient

import (
	"encoding/hex"
	"time"
)

// Config contains configuration for the light client.
type Config struct {
	// ChainID is the chain ID to verify against.
	ChainID string

	// ValidatorEndpoints are the RPC endpoints of trusted validators.
	ValidatorEndpoints []string

	// TrustThreshold is the minimum fraction of validators required for consensus.
	// Default is 2/3.
	TrustThreshold TrustThreshold

	// TrustingPeriod is the duration for which headers are considered valid.
	// Default is 24 hours.
	TrustingPeriod time.Duration

	// MaxClockDrift is the maximum allowed clock drift between header time and local time.
	// Default is 10 seconds.
	MaxClockDrift time.Duration

	// MinValidatorsForConsensus is the minimum number of validators required.
	// Default is 1.
	MinValidatorsForConsensus int

	// AutoSync enables automatic background synchronization.
	AutoSync bool

	// SyncInterval is the interval between sync attempts when AutoSync is enabled.
	// Default is 5 minutes.
	SyncInterval time.Duration

	// RPCTimeout is the timeout for RPC requests.
	// Default is 10 seconds.
	RPCTimeout time.Duration

	// MaxRetries is the maximum number of retries for failed requests.
	MaxRetries int
}

// DefaultConfig returns the default light client configuration.
func DefaultConfig() Config {
	return Config{
		TrustThreshold: TrustThreshold{
			Numerator:   2,
			Denominator: 3,
		},
		TrustingPeriod:            24 * time.Hour,
		MaxClockDrift:             10 * time.Second,
		MinValidatorsForConsensus: 1,
		AutoSync:                  true,
		SyncInterval:              5 * time.Minute,
		RPCTimeout:                10 * time.Second,
		MaxRetries:                3,
	}
}

// TrustThreshold represents the trust threshold as a fraction.
type TrustThreshold struct {
	Numerator   int
	Denominator int
}

// Validate checks if voting power meets the trust threshold.
func (t TrustThreshold) Validate(votingPower, totalPower int64) bool {
	// votingPower / totalPower >= numerator / denominator
	return votingPower*int64(t.Denominator) >= totalPower*int64(t.Numerator)
}

// Version represents the block version.
type Version struct {
	Block uint64 `json:"block"`
	App   uint64 `json:"app"`
}

// BlockID represents a block ID.
type BlockID struct {
	Hash          string        `json:"hash"`
	PartSetHeader PartSetHeader `json:"part_set_header"`
}

// PartSetHeader represents a part set header.
type PartSetHeader struct {
	Total uint32 `json:"total"`
	Hash  string `json:"hash"`
}

// Header represents a block header.
type Header struct {
	Version            Version   `json:"version"`
	ChainID            string    `json:"chain_id"`
	Height             int64     `json:"height"`
	Time               time.Time `json:"time"`
	LastBlockID        *BlockID  `json:"last_block_id,omitempty"`
	LastCommitHash     string    `json:"last_commit_hash"`
	DataHash           string    `json:"data_hash"`
	ValidatorsHash     string    `json:"validators_hash"`
	NextValidatorsHash string    `json:"next_validators_hash"`
	ConsensusHash      string    `json:"consensus_hash"`
	AppHash            string    `json:"app_hash"`
	LastResultsHash    string    `json:"last_results_hash"`
	EvidenceHash       string    `json:"evidence_hash"`
	ProposerAddress    string    `json:"proposer_address"`
}

// Validator represents a validator.
type Validator struct {
	Address          string `json:"address"`
	PublicKey        string `json:"pub_key"`
	PublicKeyType    string `json:"pub_key_type"`
	VotingPower      int64  `json:"voting_power"`
	ProposerPriority int64  `json:"proposer_priority"`
}

// ValidatorSet represents a set of validators.
type ValidatorSet struct {
	Validators       []Validator `json:"validators"`
	TotalVotingPower int64       `json:"total_voting_power"`
}

// GetTotalVotingPower calculates the total voting power.
func (vs *ValidatorSet) GetTotalVotingPower() int64 {
	if vs.TotalVotingPower > 0 {
		return vs.TotalVotingPower
	}
	var total int64
	for _, v := range vs.Validators {
		total += v.VotingPower
	}
	return total
}

// Commit represents a commit with signatures.
type Commit struct {
	Height     int64       `json:"height"`
	Round      int32       `json:"round"`
	BlockID    BlockID     `json:"block_id"`
	Signatures []CommitSig `json:"signatures"`
}

// CommitSig represents a commit signature.
type CommitSig struct {
	BlockIDFlag      int       `json:"block_id_flag"`
	ValidatorAddress string    `json:"validator_address"`
	Timestamp        time.Time `json:"timestamp"`
	Signature        string    `json:"signature"`
}

// IsAbsent returns true if the signature is absent.
func (cs *CommitSig) IsAbsent() bool {
	return cs.BlockIDFlag == 1 // BlockIDFlagAbsent
}

// IsCommit returns true if the signature is a commit signature.
func (cs *CommitSig) IsCommit() bool {
	return cs.BlockIDFlag == 2 // BlockIDFlagCommit
}

// LightBlock represents a light block with header, validators, and commit.
type LightBlock struct {
	Header        Header       `json:"header"`
	ValidatorSet  ValidatorSet `json:"validator_set"`
	Commit        Commit       `json:"commit"`
	TrustedHeight int64        `json:"trusted_height,omitempty"`
	TrustedAt     time.Time    `json:"trusted_at,omitempty"`
}

// TrustedHeader represents a trusted header with metadata.
type TrustedHeader struct {
	Header    Header    `json:"header"`
	AppHash   string    `json:"app_hash"`
	Height    int64     `json:"height"`
	TrustedAt time.Time `json:"trusted_at"`
}

// TrustedState represents the trusted state of the light client.
type TrustedState struct {
	Header       TrustedHeader `json:"header"`
	ValidatorSet ValidatorSet  `json:"validator_set"`
}

// VerificationResult represents the result of header verification.
type VerificationResult struct {
	Verified       bool   `json:"verified"`
	Height         int64  `json:"height"`
	AppHash        string `json:"app_hash"`
	Error          string `json:"error,omitempty"`
	VotingPower    int64  `json:"voting_power"`
	TotalPower     int64  `json:"total_power"`
	SignatureCount int    `json:"signature_count"`
}

// ProofVerificationResult represents the result of proof verification.
type ProofVerificationResult struct {
	Verified     bool   `json:"verified"`
	RootHash     string `json:"root_hash"`
	ExpectedHash string `json:"expected_hash"`
	Height       int64  `json:"height"`
	Error        string `json:"error,omitempty"`
}

// SyncStatus represents the synchronization status.
type SyncStatus struct {
	LatestTrustedHeight int64     `json:"latest_trusted_height"`
	LatestTrustedTime   time.Time `json:"latest_trusted_time"`
	LatestKnownHeight   int64     `json:"latest_known_height"`
	IsSynced            bool      `json:"is_synced"`
	LastSyncAttempt     time.Time `json:"last_sync_attempt"`
	LastSyncError       string    `json:"last_sync_error,omitempty"`
}

// hexToBytes converts a hex string to bytes.
func hexToBytes(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

// bytesToHex converts bytes to a hex string.
func bytesToHex(b []byte) string {
	return hex.EncodeToString(b)
}
