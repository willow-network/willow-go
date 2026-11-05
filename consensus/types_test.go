package consensus

import (
	"encoding/json"
	"fmt"
	"math/big"
	"runtime"
	"strings"
	"testing"
)

// The chain's StoreDataTx.data is Vec<u8>: its JSON is an array of byte
// values, the JSON text of the stored object as UTF-8.
func TestDataStoreTxSendsDataAsByteValues(t *testing.T) {
	tx := DataStoreTx{
		SubgroveID:  "sg-1",
		Key:         "doc1",
		Data:        []byte(`{"a":1}`),
		OwnerDid:    "did:willow:a",
		Signature:   []byte{1, 2},
		PublicKeyID: "did:willow:a#key-1",
		Nonce:       7,
	}
	body, err := json.Marshal(map[string]any{"StoreData": tx})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"StoreData":{"subgrove_id":"sg-1","key":"doc1","data":[123,34,97,34,58,49,125],` +
		`"owner_did":"did:willow:a","signature":[1,2],"public_key_id":"did:willow:a#key-1","nonce":7}}`
	if string(body) != want {
		t.Fatalf("got  %s\nwant %s", body, want)
	}
	var back struct {
		StoreData DataStoreTx `json:"StoreData"`
	}
	if err := json.Unmarshal(body, &back); err != nil {
		t.Fatal(err)
	}
	if string(back.StoreData.Data) != `{"a":1}` {
		t.Fatalf("data read back as %q", back.StoreData.Data)
	}
}

func TestUint128IsExact(t *testing.T) {
	for _, s := range []string{"0", "18446744073709551615", "18446744073709551616", "340282366920938463463374607431768211455"} {
		u, err := ParseUint128(s)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if u.String() != s {
			t.Fatalf("%s read as %s", s, u)
		}
		body, err := json.Marshal(u)
		if err != nil || string(body) != s {
			t.Fatalf("%s marshals to %s (%v)", s, body, err)
		}
		var fromNumber, fromString Uint128
		if err := json.Unmarshal([]byte(s), &fromNumber); err != nil || fromNumber != u {
			t.Fatalf("%s from a JSON number: %v (%v)", s, fromNumber, err)
		}
		if err := json.Unmarshal([]byte(`"`+s+`"`), &fromString); err != nil || fromString != u {
			t.Fatalf("%s from a JSON string: %v (%v)", s, fromString, err)
		}
	}
	for _, bad := range []string{"340282366920938463463374607431768211456", "-1", "1.5", "1e3", "", "0x10"} {
		if _, err := ParseUint128(bad); err == nil {
			t.Errorf("%q parsed as a u128", bad)
		}
	}
	if NewUint128(5).appendLittleEndian(nil)[0] != 5 || len(NewUint128(5).appendLittleEndian(nil)) != 16 {
		t.Fatal("u128 is not 16 little-endian bytes")
	}
}

// A u128 has at most 39 digits after its leading zeros. A longer number is
// refused before any big-number work (a decimal parse of n digits takes time
// quadratic in n), allocating next to nothing, and the error doesn't repeat
// it.
func TestUint128RefusesALongNumberCheaply(t *testing.T) {
	max := "340282366920938463463374607431768211455"
	if u, err := ParseUint128(strings.Repeat("0", 1000) + max); err != nil || u.String() != max {
		t.Fatalf("the largest u128 after 1,000 zeros: %v, %v", u, err)
	}
	long := strings.Repeat("9", 1<<20)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := ParseUint128(long)
	runtime.ReadMemStats(&after)
	if err == nil {
		t.Fatal("a 1,048,576-digit number parsed as a u128")
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 64<<10 {
		t.Errorf("refusing a 1,048,576-digit number allocated %d bytes", allocated)
	}
	if len(err.Error()) > 200 {
		t.Errorf("the error repeats the number: %d bytes", len(err.Error()))
	}
	var fromJSON Uint128
	if err := json.Unmarshal([]byte(long), &fromJSON); err == nil || len(err.Error()) > 200 {
		t.Errorf("a 1,048,576-digit JSON number: %d-byte error (%v)", len(fmt.Sprint(err)), err == nil)
	}
	if _, err := Uint128FromBig(new(big.Int).Lsh(big.NewInt(1), 1<<20)); err == nil || len(err.Error()) > 200 {
		t.Errorf("Uint128FromBig(2^1048576): %d-byte error (%v)", len(fmt.Sprint(err)), err == nil)
	}
	for _, bad := range []string{"0x" + max, max + " ", "+" + max, "١٢٣"} {
		if _, err := ParseUint128(bad); err == nil {
			t.Errorf("%q parsed as a u128", bad)
		}
	}
}

// Every field of a registration is sent, nil lists as [] and absent options
// as null, so the chain decodes the values its Config hashes.
func TestRegisterSubgroveTxSendsEveryField(t *testing.T) {
	tx := RegisterSubgroveTx{
		SubgroveID: "sg",
		Mode:       &SubgroveMode{FileStorage: &SubgroveFileStorage{Name: "f", MaxFileSize: 1, ReplicationFactor: 1}},
	}
	body, err := json.Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"description":""`, `"admins":[]`, `"initial_funding":null`,
		`"checkpoint_verification":{"required_tee":null}`, `"privacy":null`, `"initial_owner_key_grant":null`,
		`"template_config":null`, `"confirmation_depth":0`, `"signature":[]`, `"cryptographic_completeness":false`,
		`"writers":[]`, `"free_readers":[]`, `"read_pricing":null`, `"retention_period":0`} {
		if !strings.Contains(string(body), want) {
			t.Errorf("%s lacks %s", body, want)
		}
	}
	if _, err := RegisterSubgroveUnsignedBincode(body); err != nil {
		t.Fatal(err)
	}
}

// A nil Mode is sent as the chain's default DataStorage (the chain refuses a
// null mode), and hashes as an omitted mode does.
func TestRegisterSubgroveTxSendsTheDefaultModeForNil(t *testing.T) {
	tx := RegisterSubgroveTx{
		SubgroveID: "sg",
		Schema:     `{"version":1,"fields":{},"indexes":[],"required_fields":[]}`,
		OwnerDid:   "did:willow:a",
	}
	body, err := json.Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}
	if want := `"mode":{"DataStorage":{"name":"","writers":[],"free_readers":[],"read_pricing":null}}`; !strings.Contains(string(body), want) {
		t.Fatalf("%s lacks %s", body, want)
	}
	sent, err := RegisterSubgroveUnsignedBincode(body)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "mode")
	omitted, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	defaulted, err := RegisterSubgroveUnsignedBincode(omitted)
	if err != nil {
		t.Fatal(err)
	}
	if string(sent) != string(defaulted) {
		t.Fatalf("nil Mode bincode %x, omitted mode %x", sent, defaulted)
	}
}

// AllowedIndexers is the chain's Option<Vec<String>>: nil is sent as null (any
// indexer), and a non-nil list, even an empty one, as that list (only the
// DIDs on it).
func TestPrivacyConfigAllowedIndexersKeepsNilAndEmptyApart(t *testing.T) {
	for _, c := range []struct {
		allowed []string
		want    string
	}{
		{nil, `"allowed_indexers":null`},
		{[]string{}, `"allowed_indexers":[]`},
		{[]string{"did:willow:i"}, `"allowed_indexers":["did:willow:i"]`},
	} {
		body, err := json.Marshal(PrivacyConfig{AllowedIndexers: c.allowed, CommitmentFrequency: NewCommitmentFrequencyEveryUpdate()})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), c.want) {
			t.Errorf("%#v sent as %s, want %s", c.allowed, body, c.want)
		}
	}
}
