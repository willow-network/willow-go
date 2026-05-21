// Package willow — canonical WillowManifest builder.
//
// Mirrors willow_types::consensus::manifest::WillowManifest in the Rust
// workspace. The consensus validator rejects any manifest_content that
// doesn't decode into this exact shape, so SDK callers should build
// their on-chain manifest bytes via SerializeManifest. Each data source
// is either EVM (Address + Abi + StartBlock + Events) or Solana
// (ProgramID + StartSlot + Instructions); the family is dispatched at
// parse time from the Network field.
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
	MaxDataSources     = 64
	MaxEventsPerSource = 32
	MaxNameLen         = 64
	MaxAbiLen          = 64
	MaxDescriptionLen  = 1024
)

// DataSource is one data source in a manifest. Concrete types:
// EvmDataSource, SolanaDataSource.
type DataSource interface {
	dataSourceName() string
	dataSourceNetwork() SupportedChain
	validate(path string) error
	marshalJSON() ([]byte, error)
}

// EvmDataSource is one indexed EVM contract within a manifest.
type EvmDataSource struct {
	Name       string         `json:"name"`
	Network    SupportedChain `json:"network"`
	Address    string         `json:"address"` // 0x + 40 hex (lowercased on serialize)
	Abi        string         `json:"abi"`
	StartBlock uint64         `json:"start_block"`
	Events     []string       `json:"events"`
}

func (d *EvmDataSource) dataSourceName() string             { return d.Name }
func (d *EvmDataSource) dataSourceNetwork() SupportedChain  { return d.Network }
func (d *EvmDataSource) marshalJSON() ([]byte, error) {
	normalized := *d
	normalized.Address = strings.ToLower(d.Address)
	type alias EvmDataSource
	return json.Marshal((*alias)(&normalized))
}

// SolanaDataSource is one indexed Solana program within a manifest.
type SolanaDataSource struct {
	Name         string         `json:"name"`
	Network      SupportedChain `json:"network"`
	ProgramID    string         `json:"program_id"` // base58-encoded 32-byte pubkey
	StartSlot    uint64         `json:"start_slot"`
	Instructions []string       `json:"instructions"` // each 0x + even hex chars (>= 2)
}

func (d *SolanaDataSource) dataSourceName() string            { return d.Name }
func (d *SolanaDataSource) dataSourceNetwork() SupportedChain { return d.Network }
func (d *SolanaDataSource) marshalJSON() ([]byte, error) {
	normalized := *d
	normalized.Instructions = make([]string, len(d.Instructions))
	for i, ix := range d.Instructions {
		normalized.Instructions[i] = strings.ToLower(ix)
	}
	type alias SolanaDataSource
	return json.Marshal((*alias)(&normalized))
}

// WillowManifest is the canonical on-chain manifest shape.
type WillowManifest struct {
	SpecVersion string       `json:"spec_version"`
	Description *string      `json:"description,omitempty"`
	DataSources []DataSource `json:"data_sources"`
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
	addressRe       = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)
	nameRe          = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	eventNameRe     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	eventParamRe    = regexp.MustCompile(`^[A-Za-z0-9_\[\]]+$`)
	discriminatorRe = regexp.MustCompile(`^0x([0-9a-fA-F]{2})+$`)
)

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

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

func validateName(name, path string) error {
	if name == "" {
		return newErr(path+".name", fmt.Sprintf("%s.name must not be empty", path))
	}
	if len(name) > MaxNameLen {
		return newErr(path+".name", fmt.Sprintf("%s.name length %d exceeds maximum %d", path, len(name), MaxNameLen))
	}
	if !nameRe.MatchString(name) {
		return newErr(path+".name", fmt.Sprintf("%s.name %q must be alphanumeric, '-', or '_'", path, name))
	}
	return nil
}

func validateNetworkFamily(ds DataSource, path string, want ChainFamily) error {
	network := ds.dataSourceNetwork()
	if !IsSupportedChain(string(network)) {
		return newErr(path+".network", fmt.Sprintf("%s.network %q is not a canonical chain", path, network))
	}
	if FamilyOf(network) != want {
		return newErr(path+".network", fmt.Sprintf("%s.network %q is %s-family but data source is %s", path, network, FamilyOf(network), want))
	}
	return nil
}

func (d *EvmDataSource) validate(path string) error {
	if err := validateName(d.Name, path); err != nil {
		return err
	}
	if err := validateNetworkFamily(d, path, FamilyEvm); err != nil {
		return err
	}
	if !addressRe.MatchString(d.Address) {
		return newErr(path+".address", fmt.Sprintf("%s.address must be 0x + 40 hex chars (got %q)", path, d.Address))
	}
	if d.Abi == "" {
		return newErr(path+".abi", fmt.Sprintf("%s.abi must not be empty", path))
	}
	if len(d.Abi) > MaxAbiLen {
		return newErr(path+".abi", fmt.Sprintf("%s.abi length %d exceeds maximum %d", path, len(d.Abi), MaxAbiLen))
	}
	if len(d.Events) == 0 {
		return newErr(path+".events", fmt.Sprintf("%s.events must declare at least one event", path))
	}
	if len(d.Events) > MaxEventsPerSource {
		return newErr(path+".events", fmt.Sprintf("%s.events has %d entries (maximum %d)", path, len(d.Events), MaxEventsPerSource))
	}
	for i, sig := range d.Events {
		if err := validateEventSignature(sig, fmt.Sprintf("%s.events[%d]", path, i)); err != nil {
			return err
		}
	}
	return nil
}

func (d *SolanaDataSource) validate(path string) error {
	if err := validateName(d.Name, path); err != nil {
		return err
	}
	if err := validateNetworkFamily(d, path, FamilySolana); err != nil {
		return err
	}
	if d.ProgramID == "" || len(d.ProgramID) < 32 || len(d.ProgramID) > 44 {
		return newErr(path+".program_id", fmt.Sprintf("%s.program_id must be a base58-encoded 32-byte pubkey (got %q)", path, d.ProgramID))
	}
	for _, c := range d.ProgramID {
		if !strings.ContainsRune(base58Alphabet, c) {
			return newErr(path+".program_id", fmt.Sprintf("%s.program_id contains invalid base58 character %q", path, c))
		}
	}
	if len(d.Instructions) == 0 {
		return newErr(path+".instructions", fmt.Sprintf("%s.instructions must declare at least one discriminator", path))
	}
	if len(d.Instructions) > MaxEventsPerSource {
		return newErr(path+".instructions", fmt.Sprintf("%s.instructions has %d entries (maximum %d)", path, len(d.Instructions), MaxEventsPerSource))
	}
	for i, ix := range d.Instructions {
		if !discriminatorRe.MatchString(ix) {
			return newErr(fmt.Sprintf("%s.instructions[%d]", path, i), fmt.Sprintf("%s.instructions[%d] must be 0x + an even, non-zero number of hex chars (got %q)", path, i, ix))
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
	for i, ds := range m.DataSources {
		if err := ds.validate(fmt.Sprintf("data_sources[%d]", i)); err != nil {
			return err
		}
	}
	return nil
}

// SerializeManifest validates and emits the canonical JSON byte form
// that goes on-chain via SubgroveMode.BlockchainIndexing.manifest_content.
func SerializeManifest(m *WillowManifest) ([]byte, error) {
	if err := ValidateManifest(m); err != nil {
		return nil, err
	}
	sources := make([]json.RawMessage, len(m.DataSources))
	for i, ds := range m.DataSources {
		raw, err := ds.marshalJSON()
		if err != nil {
			return nil, err
		}
		sources[i] = raw
	}
	out := struct {
		SpecVersion string            `json:"spec_version"`
		Description *string           `json:"description,omitempty"`
		DataSources []json.RawMessage `json:"data_sources"`
	}{
		SpecVersion: m.SpecVersion,
		Description: m.Description,
		DataSources: sources,
	}
	return json.Marshal(&out)
}

// ParseManifest validates and decodes canonical manifest bytes.
func ParseManifest(data []byte) (*WillowManifest, error) {
	type shell struct {
		SpecVersion string            `json:"spec_version"`
		Description *string           `json:"description,omitempty"`
		DataSources []json.RawMessage `json:"data_sources"`
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	var s shell
	if err := dec.Decode(&s); err != nil {
		return nil, newErr("", fmt.Sprintf("manifest is not valid JSON: %v", err))
	}
	sources := make([]DataSource, len(s.DataSources))
	for i, raw := range s.DataSources {
		var hint struct {
			Network SupportedChain `json:"network"`
		}
		if err := json.Unmarshal(raw, &hint); err != nil {
			return nil, newErr(fmt.Sprintf("data_sources[%d].network", i), fmt.Sprintf("data_sources[%d].network missing: %v", i, err))
		}
		if !IsSupportedChain(string(hint.Network)) {
			return nil, newErr(fmt.Sprintf("data_sources[%d].network", i), fmt.Sprintf("data_sources[%d].network %q is not a canonical chain", i, hint.Network))
		}
		switch FamilyOf(hint.Network) {
		case FamilyEvm:
			var ds EvmDataSource
			dec := json.NewDecoder(strings.NewReader(string(raw)))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&ds); err != nil {
				return nil, newErr(fmt.Sprintf("data_sources[%d]", i), fmt.Sprintf("data_sources[%d]: %v", i, err))
			}
			sources[i] = &ds
		case FamilySolana:
			var ds SolanaDataSource
			dec := json.NewDecoder(strings.NewReader(string(raw)))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&ds); err != nil {
				return nil, newErr(fmt.Sprintf("data_sources[%d]", i), fmt.Sprintf("data_sources[%d]: %v", i, err))
			}
			sources[i] = &ds
		}
	}
	m := &WillowManifest{
		SpecVersion: s.SpecVersion,
		Description: s.Description,
		DataSources: sources,
	}
	if err := ValidateManifest(m); err != nil {
		return nil, err
	}
	return m, nil
}
