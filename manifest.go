// Package willow — canonical WillowManifest builder.
//
// Mirrors willow_types::consensus::manifest::WillowManifest in the Rust
// workspace. The consensus validator rejects any manifest_content that
// doesn't decode into this exact shape, so SDK callers should build
// their on-chain manifest bytes via SerializeManifest.
//
// v1 scope is EVM-only. Solana data sources have a different shape
// (program_id + start_slot + instructions) and follow when there's a
// real Go consumer.
package willow

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// SupportedChain is a canonical chain identifier accepted by Willow's
// consensus validator. Order mirrors SupportedChain::ALL in willow-types.
type SupportedChain string

const (
	ChainMainnet       SupportedChain = "mainnet"
	ChainSepolia       SupportedChain = "sepolia"
	ChainHolesky       SupportedChain = "holesky"
	ChainBsc           SupportedChain = "bsc"
	ChainOptimism      SupportedChain = "optimism"
	ChainArbitrumOne   SupportedChain = "arbitrum-one"
	ChainBase          SupportedChain = "base"
	ChainPolygon       SupportedChain = "polygon"
	ChainSolanaMainnet SupportedChain = "solana-mainnet"
)

// SupportedChains is the canonical chain set. Adding a chain is a
// consensus change: bump willow-types first, then mirror here.
var SupportedChains = []SupportedChain{
	ChainMainnet, ChainSepolia, ChainHolesky,
	ChainBsc, ChainOptimism, ChainArbitrumOne, ChainBase, ChainPolygon,
	ChainSolanaMainnet,
}

// ChainFamily indicates the proof / data-source primitives a chain uses.
type ChainFamily string

const (
	FamilyEvm    ChainFamily = "evm"
	FamilySolana ChainFamily = "solana"
)

// FamilyOf returns the family a chain belongs to.
func FamilyOf(chain SupportedChain) ChainFamily {
	if chain == ChainSolanaMainnet {
		return FamilySolana
	}
	return FamilyEvm
}

// EvmChainID returns the EIP-155 chain id for EVM-family chains, or
// (0, false) for non-EVM chains.
func EvmChainID(chain SupportedChain) (uint64, bool) {
	switch chain {
	case ChainMainnet:
		return 1, true
	case ChainSepolia:
		return 11_155_111, true
	case ChainHolesky:
		return 17_000, true
	case ChainBsc:
		return 56, true
	case ChainOptimism:
		return 10, true
	case ChainArbitrumOne:
		return 42_161, true
	case ChainBase:
		return 8453, true
	case ChainPolygon:
		return 137, true
	default:
		return 0, false
	}
}

// IsSupportedChain returns true iff s is a canonical chain id.
func IsSupportedChain(s string) bool {
	for _, c := range SupportedChains {
		if string(c) == s {
			return true
		}
	}
	return false
}

// FromEvmChainID maps an EIP-155 chain id to a canonical chain.
func FromEvmChainID(id uint64) (SupportedChain, bool) {
	for _, c := range SupportedChains {
		if cid, ok := EvmChainID(c); ok && cid == id {
			return c, true
		}
	}
	return "", false
}

// ManifestSpecVersion is the schema version pinned by consensus.
const ManifestSpecVersion = "1.0.0"

// Mirrors MAX_* constants in willow-types.
const (
	MaxDataSources       = 64
	MaxEventsPerSource   = 32
	MaxNameLen           = 64
	MaxAbiLen            = 64
	MaxDescriptionLen    = 1024
)

// EvmDataSource is one indexed EVM contract within a manifest.
type EvmDataSource struct {
	Name       string         `json:"name"`
	Network    SupportedChain `json:"network"`
	Address    string         `json:"address"`     // 0x + 40 hex (lowercased on serialize)
	Abi        string         `json:"abi"`
	StartBlock uint64         `json:"start_block"`
	Events     []string       `json:"events"`
}

// WillowManifest is the canonical on-chain manifest shape.
type WillowManifest struct {
	SpecVersion string          `json:"spec_version"`
	Description *string         `json:"description,omitempty"`
	DataSources []EvmDataSource `json:"data_sources"`
}

// ManifestValidationError carries a field path so callers can attribute
// validation failures.
type ManifestValidationError struct {
	Message string
	Field   string
}

func (e *ManifestValidationError) Error() string {
	return e.Message
}

func newErr(path, message string) *ManifestValidationError {
	return &ManifestValidationError{Message: message, Field: path}
}

var (
	addressRe    = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)
	nameRe       = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	eventNameRe  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	eventParamRe = regexp.MustCompile(`^[A-Za-z0-9_\[\]]+$`)
)

func validateEventSignature(sig, path string) error {
	if sig == "" {
		return newErr(path, fmt.Sprintf("%s must not be empty", path))
	}
	open := strings.Index(sig, "(")
	if open == -1 {
		return newErr(path, fmt.Sprintf("%s %q missing '('", path, sig))
	}
	if !strings.HasSuffix(sig, ")") {
		return newErr(path, fmt.Sprintf("%s %q missing trailing ')'", path, sig))
	}
	name := sig[:open]
	params := sig[open+1 : len(sig)-1]
	if !eventNameRe.MatchString(name) {
		return newErr(path, fmt.Sprintf("%s event name %q is not a valid identifier", path, name))
	}
	if params == "" {
		return nil
	}
	for _, part := range strings.Split(params, ",") {
		if !eventParamRe.MatchString(part) {
			return newErr(path, fmt.Sprintf("%s has invalid parameter type %q", path, part))
		}
	}
	return nil
}

func validateDataSource(ds *EvmDataSource, path string) error {
	if ds.Name == "" {
		return newErr(path+".name", fmt.Sprintf("%s.name must not be empty", path))
	}
	if len(ds.Name) > MaxNameLen {
		return newErr(path+".name", fmt.Sprintf("%s.name length %d exceeds maximum %d", path, len(ds.Name), MaxNameLen))
	}
	if !nameRe.MatchString(ds.Name) {
		return newErr(path+".name", fmt.Sprintf("%s.name %q must be alphanumeric, '-', or '_'", path, ds.Name))
	}
	if !IsSupportedChain(string(ds.Network)) {
		return newErr(path+".network", fmt.Sprintf("%s.network %q is not a canonical chain", path, ds.Network))
	}
	if FamilyOf(ds.Network) != FamilyEvm {
		return newErr(path+".network", fmt.Sprintf("%s.network %q is non-EVM; Solana data sources have a different shape and are not yet supported by this builder", path, ds.Network))
	}
	if !addressRe.MatchString(ds.Address) {
		return newErr(path+".address", fmt.Sprintf("%s.address must be 0x + 40 hex chars (got %q)", path, ds.Address))
	}
	if ds.Abi == "" {
		return newErr(path+".abi", fmt.Sprintf("%s.abi must not be empty", path))
	}
	if len(ds.Abi) > MaxAbiLen {
		return newErr(path+".abi", fmt.Sprintf("%s.abi length %d exceeds maximum %d", path, len(ds.Abi), MaxAbiLen))
	}
	if len(ds.Events) == 0 {
		return newErr(path+".events", fmt.Sprintf("%s.events must declare at least one event", path))
	}
	if len(ds.Events) > MaxEventsPerSource {
		return newErr(path+".events", fmt.Sprintf("%s.events has %d entries (maximum %d)", path, len(ds.Events), MaxEventsPerSource))
	}
	for i, sig := range ds.Events {
		if err := validateEventSignature(sig, fmt.Sprintf("%s.events[%d]", path, i)); err != nil {
			return err
		}
	}
	return nil
}

// ValidateManifest applies every canonical-schema check. Same rules as
// WillowManifest::from_bytes + validate() in willow-types.
func ValidateManifest(m *WillowManifest) error {
	if m.SpecVersion != ManifestSpecVersion {
		return newErr("spec_version", fmt.Sprintf("unsupported spec_version %q (expected %q)", m.SpecVersion, ManifestSpecVersion))
	}
	if m.Description != nil && len(*m.Description) > MaxDescriptionLen {
		return newErr("description", fmt.Sprintf("description length %d exceeds maximum %d", len(*m.Description), MaxDescriptionLen))
	}
	if len(m.DataSources) == 0 {
		return newErr("data_sources", "manifest must declare at least one data source")
	}
	if len(m.DataSources) > MaxDataSources {
		return newErr("data_sources", fmt.Sprintf("manifest has %d data sources (maximum %d)", len(m.DataSources), MaxDataSources))
	}
	for i := range m.DataSources {
		if err := validateDataSource(&m.DataSources[i], fmt.Sprintf("data_sources[%d]", i)); err != nil {
			return err
		}
	}
	return nil
}

// SerializeManifest validates and emits the canonical JSON byte form
// that goes on-chain via SubgroveMode.BlockchainIndexing.manifest_content.
//
// EVM addresses are normalised to lowercase so the emitted bytes
// round-trip bit-for-bit with WillowManifest::from_bytes in Rust.
func SerializeManifest(m *WillowManifest) ([]byte, error) {
	if err := ValidateManifest(m); err != nil {
		return nil, err
	}
	normalized := *m
	normalized.DataSources = make([]EvmDataSource, len(m.DataSources))
	for i, ds := range m.DataSources {
		ds.Address = strings.ToLower(ds.Address)
		normalized.DataSources[i] = ds
	}
	return json.Marshal(&normalized)
}

// ParseManifest validates and decodes canonical manifest bytes.
func ParseManifest(data []byte) (*WillowManifest, error) {
	// Use a decoder with DisallowUnknownFields to mirror the Rust
	// deny_unknown_fields behaviour.
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	var m WillowManifest
	if err := dec.Decode(&m); err != nil {
		return nil, newErr("", fmt.Sprintf("manifest is not valid JSON: %v", err))
	}
	if err := ValidateManifest(&m); err != nil {
		return nil, err
	}
	return &m, nil
}
