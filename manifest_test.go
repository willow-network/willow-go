package willow

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func goodManifest() *WillowManifest {
	return &WillowManifest{
		SpecVersion: ManifestSpecVersion,
		DataSources: []EvmDataSource{{
			Name:       "UniswapV3Pool",
			Network:    ChainMainnet,
			Address:    "0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640",
			Abi:        "UniswapV3Pool",
			StartBlock: 12369621,
			Events:     []string{"Swap(address,address,int256,int256,uint160,uint128,int24)"},
		}},
	}
}

func mustValidate(t *testing.T, m *WillowManifest) {
	t.Helper()
	if err := ValidateManifest(m); err != nil {
		t.Fatalf("expected manifest to validate, got: %v", err)
	}
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
	bytes, err := SerializeManifest(goodManifest())
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
	if len(parsed.DataSources) != 1 || parsed.DataSources[0].Network != ChainMainnet {
		t.Errorf("data_sources round-trip lost: %+v", parsed.DataSources)
	}
}

func TestNormalizesAddressToLowercase(t *testing.T) {
	m := goodManifest()
	m.DataSources[0].Address = "0x88E6A0C2DDD26FEEB64F039A2C41296FCB3F5640"
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
		m := goodManifest()
		m.DataSources[0].Network = chain
		if err := ValidateManifest(m); err != nil {
			t.Errorf("chain %s should validate: %v", chain, err)
		}
	}
}

func TestRejectsUnsupportedChain(t *testing.T) {
	m := goodManifest()
	m.DataSources[0].Network = "frobnitz"
	mustFail(t, m, "data_sources[0].network", "not a canonical chain")
}

func TestRejectsLegacyEthereumAlias(t *testing.T) {
	m := goodManifest()
	m.DataSources[0].Network = "ethereum"
	mustFail(t, m, "data_sources[0].network", "not a canonical chain")
}

func TestRejectsSolanaViaEvmBuilder(t *testing.T) {
	m := goodManifest()
	m.DataSources[0].Network = ChainSolanaMainnet
	mustFail(t, m, "data_sources[0].network", "non-EVM")
}

func TestRejectsWrongSpecVersion(t *testing.T) {
	m := goodManifest()
	m.SpecVersion = "2.0.0"
	mustFail(t, m, "spec_version", "spec_version")
}

func TestRejectsEmptyDataSources(t *testing.T) {
	m := goodManifest()
	m.DataSources = nil
	mustFail(t, m, "data_sources", "at least one")
}

func TestRejectsMalformedAddress(t *testing.T) {
	m := goodManifest()
	m.DataSources[0].Address = "0x123"
	mustFail(t, m, "data_sources[0].address", "40 hex")
}

func TestRejectsMalformedEventSignature(t *testing.T) {
	m := goodManifest()
	m.DataSources[0].Events = []string{"NotASignature"}
	mustFail(t, m, "data_sources[0].events[0]", "missing '('")

	m.DataSources[0].Events = []string{"Transfer(address, address, uint256)"}
	mustFail(t, m, "data_sources[0].events[0]", "invalid parameter type")
}

func TestRejectsNameWithBadCharset(t *testing.T) {
	m := goodManifest()
	m.DataSources[0].Name = "Has Space"
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
	m := goodManifest()
	bad := m.DataSources[0]
	bad.Name = ""
	m.DataSources = append(m.DataSources, bad)
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
