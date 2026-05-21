package willow

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func goodEvmManifest() *WillowManifest {
	return &WillowManifest{
		SpecVersion: ManifestSpecVersion,
		DataSources: []DataSource{&EvmDataSource{
			Name:       "UniswapV3Pool",
			Network:    ChainMainnet,
			Address:    "0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640",
			Abi:        "UniswapV3Pool",
			StartBlock: 12369621,
			Events:     []string{"Swap(address,address,int256,int256,uint160,uint128,int24)"},
		}},
	}
}

func goodSolanaManifest() *WillowManifest {
	return &WillowManifest{
		SpecVersion: ManifestSpecVersion,
		DataSources: []DataSource{&SolanaDataSource{
			Name:         "SplToken",
			Network:      ChainSolanaMainnet,
			ProgramID:    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
			StartSlot:    100_000_000,
			Instructions: []string{"0x03"},
		}},
	}
}

func evmAt(t *testing.T, m *WillowManifest, idx int) *EvmDataSource {
	t.Helper()
	d, ok := m.DataSources[idx].(*EvmDataSource)
	if !ok {
		t.Fatalf("data_sources[%d] is %T, expected *EvmDataSource", idx, m.DataSources[idx])
	}
	return d
}

func solanaAt(t *testing.T, m *WillowManifest, idx int) *SolanaDataSource {
	t.Helper()
	d, ok := m.DataSources[idx].(*SolanaDataSource)
	if !ok {
		t.Fatalf("data_sources[%d] is %T, expected *SolanaDataSource", idx, m.DataSources[idx])
	}
	return d
}

func mustFail(t *testing.T, m *WillowManifest, wantField, wantSubstr string) {
	t.Helper()
	err := ValidateManifest(m)
	if err == nil {
		t.Fatalf("expected validation error containing %q", wantSubstr)
	}
	var vErr *ManifestValidationError
	if !errors.As(err, &vErr) {
		t.Fatalf("expected *ManifestValidationError, got %T", err)
	}
	if wantField != "" && vErr.Field != wantField {
		t.Errorf("expected field %q, got %q", wantField, vErr.Field)
	}
	if !strings.Contains(vErr.Message, wantSubstr) {
		t.Errorf("expected error containing %q, got %q", wantSubstr, vErr.Message)
	}
}

func TestRoundTripCanonical(t *testing.T) {
	bytes, err := SerializeManifest(goodEvmManifest())
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	parsed, err := ParseManifest(bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.SpecVersion != ManifestSpecVersion {
		t.Errorf("spec_version round-trip lost: %s", parsed.SpecVersion)
	}
	if len(parsed.DataSources) != 1 || evmAt(t, parsed, 0).Network != ChainMainnet {
		t.Errorf("data_sources round-trip lost: %+v", parsed.DataSources)
	}
}

func TestNormalizesAddressToLowercase(t *testing.T) {
	m := goodEvmManifest()
	evmAt(t, m, 0).Address = "0x88E6A0C2DDD26FEEB64F039A2C41296FCB3F5640"
	out, err := SerializeManifest(m)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	if !strings.Contains(string(out), "0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640") {
		t.Errorf("expected lowercase address in output, got: %s", out)
	}
}

func TestAcceptsEachEvmCanonicalChain(t *testing.T) {
	for _, chain := range SupportedChains {
		if FamilyOf(chain) != FamilyEvm {
			continue
		}
		m := goodEvmManifest()
		evmAt(t, m, 0).Network = chain
		if err := ValidateManifest(m); err != nil {
			t.Errorf("chain %s should validate: %v", chain, err)
		}
	}
}

func TestRejectsUnsupportedChain(t *testing.T) {
	m := goodEvmManifest()
	evmAt(t, m, 0).Network = "frobnitz"
	mustFail(t, m, "data_sources[0].network", "not a canonical chain")
}

func TestRejectsLegacyEthereumAlias(t *testing.T) {
	m := goodEvmManifest()
	evmAt(t, m, 0).Network = "ethereum"
	mustFail(t, m, "data_sources[0].network", "not a canonical chain")
}

func TestRejectsEvmFieldsOnSolanaNetwork(t *testing.T) {
	m := goodEvmManifest()
	evmAt(t, m, 0).Network = ChainSolanaMainnet
	mustFail(t, m, "data_sources[0].network", "is solana-family but data source is evm")
}

func TestRejectsWrongSpecVersion(t *testing.T) {
	m := goodEvmManifest()
	m.SpecVersion = "2.0.0"
	mustFail(t, m, "spec_version", "spec_version")
}

func TestRejectsEmptyDataSources(t *testing.T) {
	m := goodEvmManifest()
	m.DataSources = nil
	mustFail(t, m, "data_sources", "at least one")
}

func TestRejectsMalformedAddress(t *testing.T) {
	m := goodEvmManifest()
	evmAt(t, m, 0).Address = "0x123"
	mustFail(t, m, "data_sources[0].address", "40 hex")
}

func TestRejectsMalformedEventSignature(t *testing.T) {
	m := goodEvmManifest()
	evmAt(t, m, 0).Events = []string{"NotASignature"}
	mustFail(t, m, "data_sources[0].events[0]", "missing '('")

	evmAt(t, m, 0).Events = []string{"Transfer(address, address, uint256)"}
	mustFail(t, m, "data_sources[0].events[0]", "invalid parameter type")
}

func TestRejectsNameWithBadCharset(t *testing.T) {
	m := goodEvmManifest()
	evmAt(t, m, 0).Name = "Has Space"
	mustFail(t, m, "data_sources[0].name", "alphanumeric")
}

func TestRejectsUnknownTopLevelField(t *testing.T) {
	payload := map[string]any{
		"spec_version": "1.0.0",
		"data_sources": []any{map[string]any{
			"name":        "T",
			"network":     "mainnet",
			"address":     "0x0000000000000000000000000000000000000000",
			"abi":         "ERC20",
			"start_block": 0,
			"events":      []string{"Transfer(address,address,uint256)"},
		}},
		"sneaky_extra": 1,
	}
	bytes, _ := json.Marshal(payload)
	if _, err := ParseManifest(bytes); err == nil {
		t.Fatalf("expected ParseManifest to reject unknown top-level field")
	}
}

func TestRejectsUnknownDataSourceField(t *testing.T) {
	payload := map[string]any{
		"spec_version": "1.0.0",
		"data_sources": []any{map[string]any{
			"name":        "T",
			"network":     "mainnet",
			"address":     "0x0000000000000000000000000000000000000000",
			"abi":         "ERC20",
			"start_block": 0,
			"events":      []string{"Transfer(address,address,uint256)"},
			"kind":        "ethereum/contract",
		}},
	}
	bytes, _ := json.Marshal(payload)
	if _, err := ParseManifest(bytes); err == nil {
		t.Fatalf("expected ParseManifest to reject unknown data source field")
	}
}

func TestAttributesErrorsToOffendingField(t *testing.T) {
	m := goodEvmManifest()
	bad := *evmAt(t, m, 0)
	bad.Name = ""
	m.DataSources = append(m.DataSources, &bad)
	err := ValidateManifest(m)
	var vErr *ManifestValidationError
	if !errors.As(err, &vErr) {
		t.Fatalf("expected *ManifestValidationError, got %v", err)
	}
	if vErr.Field != "data_sources[1].name" {
		t.Errorf("expected field 'data_sources[1].name', got %q", vErr.Field)
	}
}

func TestIsSupportedChain(t *testing.T) {
	for _, c := range SupportedChains {
		if !IsSupportedChain(string(c)) {
			t.Errorf("%s should be a supported chain", c)
		}
	}
	for _, bad := range []string{"ethereum", "MAINNET", ""} {
		if IsSupportedChain(bad) {
			t.Errorf("%q should NOT be a supported chain", bad)
		}
	}
}

func TestEvmChainIDRoundTrip(t *testing.T) {
	for _, c := range SupportedChains {
		if FamilyOf(c) != FamilyEvm {
			if _, ok := EvmChainID(c); ok {
				t.Errorf("non-EVM chain %s should not have EVM chain id", c)
			}
			continue
		}
		id, ok := EvmChainID(c)
		if !ok {
			t.Errorf("EVM chain %s should have EVM chain id", c)
			continue
		}
		got, ok := FromEvmChainID(id)
		if !ok || got != c {
			t.Errorf("round-trip: EVM id %d -> %s (wanted %s, ok=%v)", id, got, c, ok)
		}
	}
}

func TestFamilyOf(t *testing.T) {
	if FamilyOf(ChainMainnet) != FamilyEvm {
		t.Errorf("mainnet should be EVM family")
	}
	if FamilyOf(ChainArbitrumOne) != FamilyEvm {
		t.Errorf("arbitrum-one should be EVM family")
	}
	if FamilyOf(ChainSolanaMainnet) != FamilySolana {
		t.Errorf("solana-mainnet should be Solana family")
	}
}

// ---- Solana ----

func TestSolanaRoundTripNativeSpl(t *testing.T) {
	bytes, err := SerializeManifest(goodSolanaManifest())
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	parsed, err := ParseManifest(bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ds := solanaAt(t, parsed, 0)
	if ds.ProgramID != "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" {
		t.Errorf("program_id round-trip lost: %s", ds.ProgramID)
	}
	if len(ds.Instructions) != 1 || ds.Instructions[0] != "0x03" {
		t.Errorf("instructions round-trip lost: %v", ds.Instructions)
	}
}

func TestSolanaAcceptsAnchorAndSystemDiscriminators(t *testing.T) {
	cases := [][]string{
		{"0xc1209b3341d69c81"},                    // anchor
		{"0x02000000"},                            // system program 4-byte tag
		{"0x03", "0x07", "0xc1209b3341d69c81"},   // mixed lengths
	}
	for _, ix := range cases {
		m := goodSolanaManifest()
		solanaAt(t, m, 0).Instructions = ix
		if err := ValidateManifest(m); err != nil {
			t.Errorf("instructions %v should validate: %v", ix, err)
		}
	}
}

func TestSolanaNormalizesDiscriminatorToLowercase(t *testing.T) {
	m := goodSolanaManifest()
	solanaAt(t, m, 0).Instructions = []string{"0xABCD"}
	out, err := SerializeManifest(m)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	if !strings.Contains(string(out), "0xabcd") {
		t.Errorf("expected lowercase discriminator in output, got: %s", out)
	}
}

func TestSolanaRejectsBadDiscriminator(t *testing.T) {
	cases := []string{"0x123", "0x", "03"}
	for _, bad := range cases {
		m := goodSolanaManifest()
		solanaAt(t, m, 0).Instructions = []string{bad}
		mustFail(t, m, "data_sources[0].instructions[0]", "even, non-zero number of hex chars")
	}
}

func TestSolanaRejectsEmptyInstructions(t *testing.T) {
	m := goodSolanaManifest()
	solanaAt(t, m, 0).Instructions = nil
	mustFail(t, m, "data_sources[0].instructions", "at least one discriminator")
}

func TestSolanaRejectsBadProgramID(t *testing.T) {
	m := goodSolanaManifest()
	solanaAt(t, m, 0).ProgramID = "Tokenkeg0feZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" // contains '0'
	mustFail(t, m, "data_sources[0].program_id", "invalid base58 character")

	m.DataSources[0].(*SolanaDataSource).ProgramID = "Token"
	mustFail(t, m, "data_sources[0].program_id", "base58-encoded 32-byte")
}

func TestSolanaRejectsEvmFieldsOnSolanaNetwork(t *testing.T) {
	bad := &EvmDataSource{
		Name:       "Mixed",
		Network:    ChainSolanaMainnet,
		Address:    "0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640",
		Abi:        "Whatever",
		StartBlock: 0,
		Events:     []string{"Transfer(address,address,uint256)"},
	}
	m := &WillowManifest{
		SpecVersion: ManifestSpecVersion,
		DataSources: []DataSource{bad},
	}
	mustFail(t, m, "data_sources[0].network", "solana-family but data source is evm")
}

func TestSolanaMixedManifest(t *testing.T) {
	evm := goodEvmManifest().DataSources[0]
	sol := goodSolanaManifest().DataSources[0]
	m := &WillowManifest{
		SpecVersion: ManifestSpecVersion,
		DataSources: []DataSource{evm, sol},
	}
	if err := ValidateManifest(m); err != nil {
		t.Fatalf("mixed manifest should validate: %v", err)
	}
	bytes, err := SerializeManifest(m)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	parsed, err := ParseManifest(bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, ok := parsed.DataSources[0].(*EvmDataSource); !ok {
		t.Errorf("data_sources[0] should be *EvmDataSource, got %T", parsed.DataSources[0])
	}
	if _, ok := parsed.DataSources[1].(*SolanaDataSource); !ok {
		t.Errorf("data_sources[1] should be *SolanaDataSource, got %T", parsed.DataSources[1])
	}
}
