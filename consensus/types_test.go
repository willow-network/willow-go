package consensus

import (
	"encoding/json"
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
