package willow

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/willow-network/willow-go/consensus"
)

// testdata/signed_messages_kat_2.json is the chain's known-answer file for the
// second set of signed messages (registrations, key grants and rotations,
// storage-node removals, read pricing, moderation), byte for byte. Each vector
// holds the exact /tx/submit body with an empty signature, the message, a
// RegisterSubgrove's unsigned bincode, and the signatures by the key whose
// seed is 32 bytes of 0x03.
type signedMessageKAT2 struct {
	PrivateKeySeedHex               string       `json:"private_key_seed_hex"`
	PublicKeyID                     string       `json:"public_key_id"`
	Ed25519PublicKeyHex             string       `json:"ed25519_public_key_hex"`
	Secp256k1PublicKeyCompressedHex string       `json:"secp256k1_public_key_compressed_hex"`
	Vectors                         []kat2Vector `json:"vectors"`
}

type kat2Vector struct {
	Name                         string  `json:"name"`
	TransactionJSON              string  `json:"transaction_json"`
	UnsignedBincodeHex           *string `json:"unsigned_bincode_hex"`
	Message                      string  `json:"message"`
	Ed25519SignatureHex          string  `json:"ed25519_signature_hex"`
	Secp256k1Keccak256Hex        string  `json:"secp256k1_keccak256_hex"`
	Secp256k1CompactSignatureHex string  `json:"secp256k1_compact_signature_hex"`
}

func loadSignedMessageKAT2(t *testing.T) *signedMessageKAT2 {
	t.Helper()
	raw, err := os.ReadFile("testdata/signed_messages_kat_2.json")
	if err != nil {
		t.Fatal(err)
	}
	var kat signedMessageKAT2
	if err := json.Unmarshal(raw, &kat); err != nil {
		t.Fatal(err)
	}
	return &kat
}

func (k *signedMessageKAT2) vector(t *testing.T, name string) kat2Vector {
	t.Helper()
	for _, v := range k.Vectors {
		if v.Name == name {
			return v
		}
	}
	t.Fatalf("no vector %q", name)
	return kat2Vector{}
}

// decodeExactly decodes JSON with json.Decoder.UseNumber, so no number goes
// through a float64, and refuses trailing data.
func decodeExactly(t *testing.T, data []byte, out any) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(out); err != nil {
		t.Fatalf("decode %s: %v", data, err)
	}
	if dec.More() {
		t.Fatalf("trailing data in %s", data)
	}
}

// kindAndBody splits a vector's transaction JSON into its kind and the
// transaction's own JSON.
func kindAndBody(t *testing.T, transactionJSON string) (string, json.RawMessage) {
	t.Helper()
	var tx map[string]json.RawMessage
	decodeExactly(t, []byte(transactionJSON), &tx)
	if len(tx) != 1 {
		t.Fatalf("transaction JSON has %d kinds", len(tx))
	}
	for kind, body := range tx {
		return kind, body
	}
	return "", nil
}

// sameJSON reports whether two JSON texts hold the same value, comparing
// numbers by their digits.
func sameJSON(t *testing.T, a, b []byte) bool {
	t.Helper()
	var x, y any
	decodeExactly(t, a, &x)
	decodeExactly(t, b, &y)
	return reflect.DeepEqual(x, y)
}

// checkSignatures signs message with the KAT's key and compares both
// algorithms' signatures with the vector's.
func checkSignatures(t *testing.T, v kat2Vector, message string) {
	t.Helper()
	edSig, err := vectorIdentity(t, Ed25519).Sign([]byte(message))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(edSig) != v.Ed25519SignatureHex {
		t.Errorf("%s Ed25519 signature:\n got %x\nwant %s", v.Name, edSig, v.Ed25519SignatureHex)
	}
	if digest := hex.EncodeToString(keccak256([]byte(message))); digest != v.Secp256k1Keccak256Hex {
		t.Errorf("%s Keccak-256 = %s, want %s", v.Name, digest, v.Secp256k1Keccak256Hex)
	}
	secpID := vectorIdentity(t, Secp256k1)
	der, err := secpID.Sign([]byte(message))
	if err != nil {
		t.Fatal(err)
	}
	if compact := hex.EncodeToString(derToCompact(t, der)); compact != v.Secp256k1CompactSignatureHex {
		t.Errorf("%s secp256k1 signature:\n got %s\nwant %s", v.Name, compact, v.Secp256k1CompactSignatureHex)
	}
}

// Vectors for kinds this SDK neither sends nor builds a message for.
var kat2KindsNotSent = map[string]bool{
	"UpdateSubgroveReadPricing": true,
	"BlockContentHash":          true,
	"UnblockContentHash":        true,
	"ReportContent":             true,
}

func TestSecondSetMessagesAreTheChainsKnownAnswers(t *testing.T) {
	kat := loadSignedMessageKAT2(t)
	edID := vectorIdentity(t, Ed25519)
	secpID := vectorIdentity(t, Secp256k1)
	if kat.PrivateKeySeedHex != strings.Repeat("03", 32) || kat.PublicKeyID != edID.PublicKeyID() ||
		kat.Ed25519PublicKeyHex != edID.KeyPair.PublicKeyHex() ||
		kat.Secp256k1PublicKeyCompressedHex != secpID.KeyPair.PublicKeyHex() {
		t.Fatalf("the vector keys are not the KAT's keys")
	}

	bincodes, messages, refused := 0, 0, 0
	for _, v := range kat.Vectors {
		kind, body := kindAndBody(t, v.TransactionJSON)
		var got string
		var err error
		var sent []byte // the transaction as this SDK sends it, signature empty
		switch kind {
		case "RegisterSubgrove":
			if v.UnsignedBincodeHex == nil {
				t.Fatalf("%s has no unsigned bincode", v.Name)
			}
			unsigned, err := consensus.RegisterSubgroveUnsignedBincode(body)
			if err != nil {
				t.Fatalf("%s: %v", v.Name, err)
			}
			if hex.EncodeToString(unsigned) != *v.UnsignedBincodeHex {
				t.Fatalf("%s unsigned bincode:\n got %x\nwant %s", v.Name, unsigned, *v.UnsignedBincodeHex)
			}
			bincodes++

			var tx consensus.RegisterSubgroveTx
			decodeExactly(t, body, &tx)
			if tx.Mode != nil && tx.Mode.BlockchainIndexing != nil {
				// This SDK can't encode the indexing mode, so it refuses to sign it.
				if msg, err := FormatRegisterSubgroveMessage(&tx); err == nil || !IsValidationError(err) || msg != "" {
					t.Fatalf("%s: got %q, %v; want a refusal", v.Name, msg, err)
				}
				refused++
				continue
			}
			if sent, err = json.Marshal(tx); err != nil {
				t.Fatal(err)
			}
			got, err = FormatRegisterSubgroveMessage(&tx)
			if err != nil {
				t.Fatalf("%s: %v", v.Name, err)
			}
		case "GrantSubgroveKey":
			var tx grantSubgroveKeyRequest
			decodeExactly(t, body, &tx)
			if sent, err = json.Marshal(tx); err != nil {
				t.Fatal(err)
			}
			got, err = FormatGrantSubgroveKeyMessage(tx.SubgroveID, tx.SenderDID, tx.EncryptedKeyGrant, tx.Nonce)
		case "RotateSubgroveKey":
			var tx rotateSubgroveKeyRequest
			decodeExactly(t, body, &tx)
			if sent, err = json.Marshal(tx); err != nil {
				t.Fatal(err)
			}
			got, err = FormatRotateSubgroveKeyMessage(tx.SubgroveID, tx.SenderDID, tx.NewEpoch, tx.NewGrants, tx.Nonce)
		case "UnregisterStorageNode":
			var tx struct {
				NodeDID string `json:"node_did"`
				Nonce   uint64 `json:"nonce"`
			}
			decodeExactly(t, body, &tx)
			got, err = FormatUnregisterStorageNodeMessage(tx.NodeDID, tx.Nonce)
		default:
			if kat2KindsNotSent[kind] {
				continue
			}
			t.Fatalf("vector %q (%s) has no builder here", v.Name, kind)
		}
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		if got != v.Message {
			t.Fatalf("%s message:\n got %q\nwant %q", v.Name, got, v.Message)
		}
		// The SDK's transaction types carry every field of the KAT's
		// transaction, byte for byte, so it sends what the message binds.
		if sent != nil && !bytes.Equal(sent, body) {
			t.Errorf("%s: the SDK's transaction JSON\n %s\nis not the KAT's\n %s", v.Name, sent, body)
		}
		checkSignatures(t, v, got)
		messages++
	}
	if bincodes != 5 || refused != 1 || messages != 7 {
		t.Fatalf("checked %d bincodes, %d messages, %d refusals; want 5, 7 (four registrations, grant, rotation, storage-node removal), 1", bincodes, messages, refused)
	}
}

// A RegisterSubgrove's Config hashes the transaction as the chain decodes it:
// a field left out takes the chain's default, so the bincode is the same.
func TestRegisterSubgroveBincodeFillsTheChainsDefaults(t *testing.T) {
	v := loadSignedMessageKAT2(t).vector(t, "RegisterSubgrove (data, defaults)")
	short := `{"subgrove_id":"sg-1","name":"","schema":"{\"version\":1,\"fields\":{},\"indexes\":[],\"required_fields\":[]}",` +
		`"owner_did":"did:willow:a","signature":[],"public_key_id":"did:willow:a#key-1","nonce":4}`
	unsigned, err := consensus.RegisterSubgroveUnsignedBincode([]byte(short))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(unsigned) != *v.UnsignedBincodeHex {
		t.Fatalf("defaults bincode:\n got %x\nwant %s", unsigned, *v.UnsignedBincodeHex)
	}
	// The signature is hashed empty, whatever the transaction carries.
	_, body := kindAndBody(t, v.TransactionJSON)
	signed := bytes.Replace(body, []byte(`"signature":[]`), []byte(`"signature":[1,2,3]`), 1)
	if unsigned, err = consensus.RegisterSubgroveUnsignedBincode(signed); err != nil || hex.EncodeToString(unsigned) != *v.UnsignedBincodeHex {
		t.Fatalf("signed transaction's bincode: %x, %v", unsigned, err)
	}
	// JSON the chain can't decode is refused, not hashed.
	for name, bad := range map[string]string{
		"null admins":       strings.Replace(string(body), `"admins":[]`, `"admins":null`, 1),
		"no nonce":          strings.Replace(string(body), `,"nonce":4`, ``, 1),
		"no signature":      strings.Replace(string(body), `"signature":[],`, ``, 1),
		"nonce above u64":   strings.Replace(string(body), `"nonce":4`, `"nonce":18446744073709551616`, 1),
		"fractional nonce":  strings.Replace(string(body), `"nonce":4`, `"nonce":4.0`, 1),
		"unknown mode":      strings.Replace(string(body), `"DataStorage"`, `"Storage"`, 1),
		"price as a string": strings.Replace(string(loadKATBody(t, "RegisterSubgrove (data)")), `"price_per_query":1000000000000000`, `"price_per_query":"1000000000000000"`, 1),
	} {
		if _, err := consensus.RegisterSubgroveUnsignedBincode([]byte(bad)); err == nil {
			t.Errorf("%s: hashed %s", name, bad)
		}
	}
}

func loadKATBody(t *testing.T, name string) json.RawMessage {
	t.Helper()
	_, body := kindAndBody(t, loadSignedMessageKAT2(t).vector(t, name).TransactionJSON)
	return body
}

// u128 amounts above 2^64 keep every digit through the SDK's types.
func TestRegisterSubgroveKeepsLargeAmountsExact(t *testing.T) {
	var tx consensus.RegisterSubgroveTx
	decodeExactly(t, loadKATBody(t, "RegisterSubgrove (data)"), &tx)
	if tx.InitialFunding == nil || tx.InitialFunding.String() != "5000000000000000000" {
		t.Fatalf("initial_funding %v", tx.InitialFunding)
	}
	big := `340282366920938463463374607431768211455` // 2^128 - 1
	amount, err := consensus.ParseUint128(big)
	if err != nil {
		t.Fatal(err)
	}
	tx.InitialFunding = &amount
	body, err := json.Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte(`"initial_funding":`+big+`,`)) {
		t.Fatalf("initial_funding not sent exactly: %s", body)
	}
	unsigned, err := consensus.RegisterSubgroveUnsignedBincode(body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(unsigned, append([]byte{1}, bytes.Repeat([]byte{0xff}, 16)...)) {
		t.Fatalf("bincode lacks Some(2^128-1): %x", unsigned)
	}
	if _, err := consensus.ParseUint128("340282366920938463463374607431768211456"); err == nil {
		t.Fatal("2^128 parsed as a u128")
	}
}

func TestSecondSetMessagesRefuseLineBreaksAndInvalidUTF8(t *testing.T) {
	grant := EncryptedKeyGrant{GranteeDID: "did:willow:b", GranteePublicKeyID: "did:willow:b#key-1", GrantedBy: "did:willow:a"}
	withGrant := func(edit func(*EncryptedKeyGrant)) EncryptedKeyGrant {
		g := grant
		edit(&g)
		return g
	}
	register := func(edit func(*consensus.RegisterSubgroveTx)) func() (string, error) {
		return func() (string, error) {
			var tx consensus.RegisterSubgroveTx
			decodeExactly(t, loadKATBody(t, "RegisterSubgrove (data)"), &tx)
			edit(&tx)
			return FormatRegisterSubgroveMessage(&tx)
		}
	}
	cases := map[string]func() (string, error){
		"RegisterSubgrove Subgrove": register(func(tx *consensus.RegisterSubgroveTx) { tx.SubgroveID = "notes\n1" }),
		"RegisterSubgrove Owner":    register(func(tx *consensus.RegisterSubgroveTx) { tx.OwnerDid = "did:willow:a\n" }),
		"GrantSubgroveKey Subgrove": func() (string, error) { return FormatGrantSubgroveKeyMessage("p\n1", "did:willow:a", grant, 1) },
		"GrantSubgroveKey Sender":   func() (string, error) { return FormatGrantSubgroveKeyMessage("p1", "did:willow:a\r\n", grant, 1) },
		"GrantSubgroveKey Grantee": func() (string, error) {
			return FormatGrantSubgroveKeyMessage("p1", "did:willow:a", withGrant(func(g *EncryptedKeyGrant) { g.GranteeDID += "\n" }), 1)
		},
		"GrantSubgroveKey GranteeKey": func() (string, error) {
			return FormatGrantSubgroveKeyMessage("p1", "did:willow:a", withGrant(func(g *EncryptedKeyGrant) { g.GranteePublicKeyID = "\nk" }), 1)
		},
		"GrantSubgroveKey GrantedBy": func() (string, error) {
			return FormatGrantSubgroveKeyMessage("p1", "did:willow:a", withGrant(func(g *EncryptedKeyGrant) { g.GrantedBy += "\nNonce: 2" }), 1)
		},
		"RotateSubgroveKey Subgrove": func() (string, error) { return FormatRotateSubgroveKeyMessage("p\n1", "did:willow:a", 1, nil, 1) },
		"RotateSubgroveKey Sender":   func() (string, error) { return FormatRotateSubgroveKeyMessage("p1", "\n", 1, nil, 1) },
		"RotateSubgroveKey second grant": func() (string, error) {
			return FormatRotateSubgroveKeyMessage("p1", "did:willow:a", 1,
				[]EncryptedKeyGrant{grant, withGrant(func(g *EncryptedKeyGrant) { g.GranteeDID += "\n" })}, 1)
		},
		"UnregisterStorageNode Node": func() (string, error) { return FormatUnregisterStorageNodeMessage("did:willow:s\n", 1) },
		// Not valid UTF-8: the JSON sent would carry U+FFFD instead.
		"GrantSubgroveKey invalid UTF-8": func() (string, error) {
			return FormatGrantSubgroveKeyMessage("p1", "did:willow:\xff", grant, 1)
		},
		"UnregisterStorageNode invalid UTF-8": func() (string, error) { return FormatUnregisterStorageNodeMessage("did:\xc3", 1) },
	}
	for name, build := range cases {
		if msg, err := build(); err == nil || !IsValidationError(err) || msg != "" {
			t.Errorf("%s: got %q, %v; want a validation error", name, msg, err)
		}
	}
	// Name and description are hashed into Config, not written as lines, so
	// they may hold line breaks.
	if _, err := register(func(tx *consensus.RegisterSubgroveTx) { tx.Description = "line one\nline two" })(); err != nil {
		t.Errorf("description with a line break: %v", err)
	}
}

func TestRegisterSubgroveMessageNeedsOneEncodableMode(t *testing.T) {
	var tx consensus.RegisterSubgroveTx
	decodeExactly(t, loadKATBody(t, "RegisterSubgrove (data)"), &tx)
	cases := map[string]*consensus.SubgroveMode{
		"no variant": {},
		"two modes":  {DataStorage: tx.Mode.DataStorage, FileStorage: &consensus.SubgroveFileStorage{Name: "f"}},
		"indexing":   {BlockchainIndexing: &consensus.SubgroveBlockchainIndexing{ManifestContent: []byte("x")}},
	}
	for name, mode := range cases {
		c := tx
		c.Mode = mode
		if msg, err := FormatRegisterSubgroveMessage(&c); !IsValidationError(err) || msg != "" {
			t.Errorf("%s: got %q, %v; want a validation error", name, msg, err)
		}
	}
	if _, err := FormatRegisterSubgroveMessage(nil); !IsValidationError(err) {
		t.Errorf("nil transaction: %v", err)
	}
}

// A nil Mode is the chain's default, DataStorage with an empty name and
// lists: it is sent explicitly (the chain refuses a null mode) and signs as
// the KAT's defaults vector does.
func TestRegisterSubgroveNilModeIsTheChainsDefault(t *testing.T) {
	v := loadSignedMessageKAT2(t).vector(t, "RegisterSubgrove (data, defaults)")
	_, want := kindAndBody(t, v.TransactionJSON)
	var tx consensus.RegisterSubgroveTx
	decodeExactly(t, want, &tx)
	tx.Mode = nil
	body, err := json.Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}
	if !sameJSON(t, body, want) {
		t.Fatalf("nil Mode sent as\n %s\nwant\n %s", body, want)
	}
	message, err := FormatRegisterSubgroveMessage(&tx)
	if err != nil || message != v.Message {
		t.Fatalf("nil Mode message %q, %v; want the KAT's %q", message, err, v.Message)
	}
}

// The chain refuses a DataStorage or FileStorage registration whose schema
// declares indexes or whose subgrove id isn't 1 to 64 ASCII letters, digits,
// '-', or '_' starting with a letter or digit, so the builder refuses both.
func TestRegisterSubgroveMessageRefusesWhatTheChainRefuses(t *testing.T) {
	for _, kat := range []string{"RegisterSubgrove (data)", "RegisterSubgrove (file)"} {
		var tx consensus.RegisterSubgroveTx
		decodeExactly(t, loadKATBody(t, kat), &tx)
		for name, edit := range map[string]func(*consensus.RegisterSubgroveTx){
			"schema index": func(tx *consensus.RegisterSubgroveTx) {
				tx.Schema = `{"version":1,"fields":{"a":"string"},"indexes":[{"name":"by_a","fields":["a"],"unique":false}],"required_fields":[]}`
			},
			"empty id":          func(tx *consensus.RegisterSubgroveTx) { tx.SubgroveID = "" },
			"id over 64":        func(tx *consensus.RegisterSubgroveTx) { tx.SubgroveID = strings.Repeat("a", 65) },
			"id starts with -":  func(tx *consensus.RegisterSubgroveTx) { tx.SubgroveID = "-a" },
			"id starts with _":  func(tx *consensus.RegisterSubgroveTx) { tx.SubgroveID = "_a" },
			"id with a space":   func(tx *consensus.RegisterSubgroveTx) { tx.SubgroveID = "a b" },
			"id with a slash":   func(tx *consensus.RegisterSubgroveTx) { tx.SubgroveID = "a/b" },
			"id with a dot":     func(tx *consensus.RegisterSubgroveTx) { tx.SubgroveID = "a.b" },
			"id not ASCII":      func(tx *consensus.RegisterSubgroveTx) { tx.SubgroveID = "caf\u00e9" },
			"id with line feed": func(tx *consensus.RegisterSubgroveTx) { tx.SubgroveID = "a\n" },
		} {
			c := tx
			edit(&c)
			if msg, err := FormatRegisterSubgroveMessage(&c); !IsValidationError(err) || msg != "" {
				t.Errorf("%s, %s: got %q, %v; want a validation error", kat, name, msg, err)
			}
		}
		for _, id := range []string{"a", "9", "A-b_9", strings.Repeat("z", 64)} {
			c := tx
			c.SubgroveID = id
			if _, err := FormatRegisterSubgroveMessage(&c); err != nil {
				t.Errorf("%s, id %q: %v", kat, id, err)
			}
		}
	}
}

// withLists returns tx with its own copy of the mode, whose writers and free
// readers are set by edit.
func withLists(tx consensus.RegisterSubgroveTx, edit func(writers, freeReaders *[]string)) consensus.RegisterSubgroveTx {
	mode := *tx.Mode
	switch {
	case mode.DataStorage != nil:
		m := *mode.DataStorage
		edit(&m.Writers, &m.FreeReaders)
		mode.DataStorage = &m
	case mode.FileStorage != nil:
		m := *mode.FileStorage
		edit(&m.Writers, &m.FreeReaders)
		mode.FileStorage = &m
	}
	tx.Mode = &mode
	return tx
}

// The chain refuses a DataStorage or FileStorage registration whose admins,
// writers, or free readers aren't DIDs ("did:willow:" then letters, digits,
// '-', or '_', at most 128 bytes), or whose schema doesn't parse as its
// SchemaDefinition, so the builder refuses them before signing.
func TestRegisterSubgroveMessageRefusesNonDIDsAndSchemasTheChainCantRead(t *testing.T) {
	notDIDs := map[string]string{
		"no prefix":       "alice",
		"another method":  "did:key:abc",
		"empty body":      "did:willow:",
		"a colon":         "did:willow:a:b",
		"a space":         "did:willow:a b",
		"not ASCII":       "did:willow:café",
		"over 128 bytes":  "did:willow:" + strings.Repeat("a", 118),
		"upper-case path": "DID:willow:a",
	}
	badSchemas := map[string]string{
		"field type int":          `{"version":1,"fields":{"a":"int"},"indexes":[],"required_fields":[]}`,
		"field type upper-case":   `{"fields":{"a":"String"}}`,
		"field type null":         `{"fields":{"a":null}}`,
		"overwritten bad type":    `{"fields":{"a":"int","a":"string"}}`,
		"fields a list":           `{"fields":[]}`,
		"fields null":             `{"fields":null}`,
		"version a string":        `{"version":"1"}`,
		"version negative":        `{"version":-1}`,
		"version a fraction":      `{"version":1.5}`,
		"version over u32":        `{"version":4294967296}`,
		"version null":            `{"version":null}`,
		"key twice":               `{"version":1,"version":1}`,
		"indexes null":            `{"indexes":null}`,
		"required field a number": `{"required_fields":[1]}`,
		"required_fields null":    `{"required_fields":null}`,
		"empty":                   ``,
		"not JSON":                `{`,
		"a list":                  `[]`,
		"null":                    `null`,
		"two objects":             `{} {}`,
	}
	for _, kat := range []string{"RegisterSubgrove (data)", "RegisterSubgrove (file)"} {
		var tx consensus.RegisterSubgroveTx
		decodeExactly(t, loadKATBody(t, kat), &tx)
		cases := map[string]consensus.RegisterSubgroveTx{}
		for name, did := range notDIDs {
			admin := tx
			admin.Admins = []string{"did:willow:b", did}
			cases["admin, "+name] = admin
			cases["writer, "+name] = withLists(tx, func(w, _ *[]string) { *w = []string{did} })
			cases["free reader, "+name] = withLists(tx, func(_, r *[]string) { *r = []string{"did:willow:c", did} })
		}
		for name, schema := range badSchemas {
			c := tx
			c.Schema = schema
			cases["schema, "+name] = c
		}
		for name, c := range cases {
			if msg, err := FormatRegisterSubgroveMessage(&c); !IsValidationError(err) || msg != "" {
				t.Errorf("%s, %s: got %q, %v; want a validation error", kat, name, msg, err)
			}
		}

		accepted := map[string]consensus.RegisterSubgroveTx{}
		for name, schema := range map[string]string{
			"no keys":         `{}`,
			"every type":      `{"version":2,"fields":{"a":"string","b":"number","c":"boolean","d":"array","e":"object","f":"bytes"},"required_fields":["a"]}`,
			"an unknown key":  `{"fields":{},"name":"ignored","extra":[{"x":null}]}`,
			"whitespace":      " \n{ \"version\" : 0 } \n",
			"an escaped type": `{"fields":{"a":"string"}}`,
		} {
			c := tx
			c.Schema = schema
			accepted["schema, "+name] = c
		}
		longest := "did:willow:" + strings.Repeat("Z", 117)
		accepted["DIDs at the rule's edges"] = withLists(tx, func(w, r *[]string) {
			*w, *r = []string{longest, "did:willow:_"}, []string{"did:willow:-", "did:willow:aZ09-_"}
		})
		for name, c := range accepted {
			if _, err := FormatRegisterSubgroveMessage(&c); err != nil {
				t.Errorf("%s, %s: %v", kat, name, err)
			}
		}
	}
}

// The chain refuses a private DataStorage registration whose initial owner
// key grant isn't key epoch 0 to the owner (a DID), so the builder refuses it
// before signing; without privacy, the chain doesn't read the grant.
func TestRegisterSubgroveMessageRefusesAnInitialGrantTheChainRefuses(t *testing.T) {
	var tx consensus.RegisterSubgroveTx
	decodeExactly(t, loadKATBody(t, "RegisterSubgrove (private, non-ASCII, large nonce)"), &tx)
	if _, err := FormatRegisterSubgroveMessage(&tx); err != nil {
		t.Fatalf("the KAT's grant: %v", err)
	}
	for name, edit := range map[string]func(*consensus.EncryptedKeyGrant){
		"key epoch 1":                           func(g *consensus.EncryptedKeyGrant) { g.KeyEpoch = 1 },
		"to another DID":                        func(g *consensus.EncryptedKeyGrant) { g.GranteeDID = "did:willow:b" },
		"to no one":                             func(g *consensus.EncryptedKeyGrant) { g.GranteeDID = "" },
		"epoch 1 to the owner, another grantor": func(g *consensus.EncryptedKeyGrant) { g.KeyEpoch, g.GrantedBy = 1, "did:willow:b" },
	} {
		grant := *tx.InitialOwnerKeyGrant
		edit(&grant)
		c := tx
		c.InitialOwnerKeyGrant = &grant
		if msg, err := FormatRegisterSubgroveMessage(&c); !IsValidationError(err) || msg != "" {
			t.Errorf("%s: got %q, %v; want a validation error", name, msg, err)
		}
		c.Privacy = nil
		if _, err := FormatRegisterSubgroveMessage(&c); err != nil {
			t.Errorf("%s without privacy: %v", name, err)
		}
	}
	// An owner that isn't a DID can't be the grantee either.
	grant := *tx.InitialOwnerKeyGrant
	grant.GranteeDID = "owner"
	c := tx
	c.OwnerDid, c.InitialOwnerKeyGrant = "owner", &grant
	if _, err := FormatRegisterSubgroveMessage(&c); !IsValidationError(err) {
		t.Errorf("grant to an owner that isn't a DID: %v", err)
	}
}

// ChainSchemaJSON refuses a schema with an index, and doesn't send the
// schema's name or description, which the chain's schema has no place for.
func TestChainSchemaJSONRefusesIndexes(t *testing.T) {
	for name, schema := range map[string]*SchemaDefinition{
		"hash index":    NewSchemaBuilder("S").StringField("a", true).HashIndex("by_a", []string{"a"}).Build(),
		"unique index":  NewSchemaBuilder("S").StringField("a", true).UniqueIndex("by_a", []string{"a"}).Build(),
		"indexed field": NewSchemaBuilder("S").Field("a", "string", true, true).Build(),
	} {
		if got, err := schema.ChainSchemaJSON(); !IsValidationError(err) || got != "" {
			t.Errorf("%s: got %q, %v; want a validation error", name, got, err)
		}
	}
	got, err := NewSchemaBuilder("S").Description("d").StringField("a", true).Build().ChainSchemaJSON()
	if want := `{"version":1,"fields":{"a":"string"},"indexes":[],"required_fields":["a"]}`; err != nil || got != want {
		t.Fatalf("got %q, %v; want %q", got, err, want)
	}
}

// The schema a registration carries parses as the chain's SchemaDefinition:
// {version: u32, fields: map of name to FieldType, indexes, required_fields},
// FieldType one of its lowercase unit variants, and no other key.
func TestChainSchemaJSONIsTheChainsSchemaDefinition(t *testing.T) {
	chainFieldTypes := map[string]bool{"string": true, "number": true, "boolean": true, "array": true, "object": true, "bytes": true}
	schema := NewSchemaBuilder("S").StringField("s", true).IntField("i", false).FloatField("f", false).
		BoolField("b", true).ArrayField("a", "string", false).ObjectField("o", false).
		Field("n", "Number", false, false).Field("x", "bytes", false, false).Field("l", "array", false, false).
		Field("ig", "integer", false, false).Field("bo", "boolean", false, false).Build()
	for _, s := range []*SchemaDefinition{schema, {}} {
		text, err := s.ChainSchemaJSON()
		if err != nil {
			t.Fatal(err)
		}
		var parsed struct {
			Version uint32            `json:"version"`
			Fields  map[string]string `json:"fields"`
			Indexes []struct {
				Name   string   `json:"name"`
				Fields []string `json:"fields"`
				Unique bool     `json:"unique"`
			} `json:"indexes"`
			RequiredFields []string `json:"required_fields"`
		}
		dec := json.NewDecoder(strings.NewReader(text))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&parsed); err != nil {
			t.Fatalf("%s: %v", text, err)
		}
		if parsed.Version != 1 || parsed.Fields == nil || parsed.Indexes == nil || parsed.RequiredFields == nil {
			t.Fatalf("%s: want version 1 and every field present", text)
		}
		if len(parsed.Fields) != len(s.Fields) {
			t.Fatalf("%s: %d fields, want %d", text, len(parsed.Fields), len(s.Fields))
		}
		for name, fieldType := range parsed.Fields {
			if !chainFieldTypes[fieldType] {
				t.Errorf("%s: field %s has type %q, not one of the chain's", text, name, fieldType)
			}
		}
	}
	if got, err := schema.ChainSchemaJSON(); err != nil || !strings.Contains(got, `"required_fields":["s","b"]`) {
		t.Fatalf("required fields: %s, %v", got, err)
	}
}

// txServer is a mocked API that reports the account nonce for did:willow:a and
// records each transaction posted to /tx/submit as raw JSON.
func txServer(t *testing.T, accountNonce uint64) (*httptest.Server, *[]map[string]json.RawMessage) {
	t.Helper()
	var txs []map[string]json.RawMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/account/did:willow:a/nonce":
			_, _ = w.Write([]byte(`{"success":true,"data":{"did":"did:willow:a","nonce":` +
				strconv.FormatUint(accountNonce, 10) + `},"error":null}`))
		case r.Method == http.MethodPost && r.URL.Path == "/tx/submit":
			var tx map[string]json.RawMessage
			dec := json.NewDecoder(r.Body)
			dec.UseNumber()
			if err := dec.Decode(&tx); err != nil {
				t.Error(err)
			}
			txs = append(txs, tx)
			_, _ = w.Write([]byte(`{"success":true,"data":{"tx_hash":"AB","code":0,"log":""},"error":null}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &txs
}

// sentTx returns the one transaction sent, of the given kind.
func sentTx(t *testing.T, txs *[]map[string]json.RawMessage, kind string) json.RawMessage {
	t.Helper()
	if len(*txs) != 1 {
		t.Fatalf("sent %d transactions, want 1", len(*txs))
	}
	body, ok := (*txs)[0][kind]
	if !ok || len((*txs)[0]) != 1 {
		t.Fatalf("sent %v, want one %s", (*txs)[0], kind)
	}
	return body
}

// withEmptySignature returns a transaction's JSON with its signature emptied,
// and the signature.
func withEmptySignature(t *testing.T, body json.RawMessage) ([]byte, []byte) {
	t.Helper()
	var fields map[string]json.RawMessage
	decodeExactly(t, body, &fields)
	var signature consensus.ByteArray
	if err := json.Unmarshal(fields["signature"], &signature); err != nil {
		t.Fatal(err)
	}
	fields["signature"] = json.RawMessage(`[]`)
	unsigned, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return unsigned, signature
}

func clientFor(t *testing.T, srv *httptest.Server, alg SignatureAlgorithm) (*Client, *Identity) {
	t.Helper()
	client, err := NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	id := vectorIdentity(t, alg)
	client.SetIdentity(id)
	return client, id
}

// The GrantSubgroveKey a grant sends is signed over the message built from its
// own fields; with the KAT's inputs it is the KAT's transaction and signature.
func TestGrantSubgroveKeySignsTheTransactionItSends(t *testing.T) {
	v := loadSignedMessageKAT2(t).vector(t, "GrantSubgroveKey")
	_, want := kindAndBody(t, v.TransactionJSON)
	var kat grantSubgroveKeyRequest
	decodeExactly(t, want, &kat)
	for _, alg := range []SignatureAlgorithm{Ed25519, Secp256k1} {
		t.Run(string(alg), func(t *testing.T) {
			srv, txs := txServer(t, kat.Nonce-1)
			client, id := clientFor(t, srv, alg)
			if _, err := client.Privacy.GrantSubgroveKey(context.Background(), kat.SubgroveID, kat.EncryptedKeyGrant); err != nil {
				t.Fatal(err)
			}
			unsigned, signature := withEmptySignature(t, sentTx(t, txs, "GrantSubgroveKey"))
			if !sameJSON(t, unsigned, want) {
				t.Fatalf("sent\n %s\nwant\n %s", unsigned, want)
			}
			var tx grantSubgroveKeyRequest
			decodeExactly(t, unsigned, &tx)
			message, err := FormatGrantSubgroveKeyMessage(tx.SubgroveID, tx.SenderDID, tx.EncryptedKeyGrant, tx.Nonce)
			if err != nil {
				t.Fatal(err)
			}
			if ok, err := Verify(alg, id.KeyPair.PublicKey, []byte(message), signature); err != nil || !ok {
				t.Fatalf("signature does not verify over\n%s\n(%v)", message, err)
			}
			if alg == Ed25519 && hex.EncodeToString(signature) != v.Ed25519SignatureHex {
				t.Fatalf("signature %x, want the KAT's %s", signature, v.Ed25519SignatureHex)
			}
		})
	}
}

func TestRotateSubgroveKeySignsTheTransactionItSends(t *testing.T) {
	v := loadSignedMessageKAT2(t).vector(t, "RotateSubgroveKey")
	_, want := kindAndBody(t, v.TransactionJSON)
	var kat rotateSubgroveKeyRequest
	decodeExactly(t, want, &kat)
	for _, alg := range []SignatureAlgorithm{Ed25519, Secp256k1} {
		t.Run(string(alg), func(t *testing.T) {
			srv, txs := txServer(t, kat.Nonce-1)
			client, id := clientFor(t, srv, alg)
			if _, err := client.Privacy.RotateSubgroveKey(context.Background(), kat.SubgroveID, kat.NewEpoch, kat.NewGrants); err != nil {
				t.Fatal(err)
			}
			unsigned, signature := withEmptySignature(t, sentTx(t, txs, "RotateSubgroveKey"))
			if !sameJSON(t, unsigned, want) {
				t.Fatalf("sent\n %s\nwant\n %s", unsigned, want)
			}
			var tx rotateSubgroveKeyRequest
			decodeExactly(t, unsigned, &tx)
			message, err := FormatRotateSubgroveKeyMessage(tx.SubgroveID, tx.SenderDID, tx.NewEpoch, tx.NewGrants, tx.Nonce)
			if err != nil {
				t.Fatal(err)
			}
			if ok, err := Verify(alg, id.KeyPair.PublicKey, []byte(message), signature); err != nil || !ok {
				t.Fatalf("signature does not verify over\n%s\n(%v)", message, err)
			}
			if alg == Ed25519 && hex.EncodeToString(signature) != v.Ed25519SignatureHex {
				t.Fatalf("signature %x, want the KAT's %s", signature, v.Ed25519SignatureHex)
			}
		})
	}
	// A rotation with no grants sends an empty list, which the chain decodes.
	srv, txs := txServer(t, 1)
	client, _ := clientFor(t, srv, Ed25519)
	if _, err := client.Privacy.RotateSubgroveKey(context.Background(), "p1", 2, nil); err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	decodeExactly(t, sentTx(t, txs, "RotateSubgroveKey"), &fields)
	if string(fields["new_grants"]) != "[]" {
		t.Fatalf("new_grants = %s, want []", fields["new_grants"])
	}
}

func TestUnregisterStorageNodeSignsTheTransactionItSends(t *testing.T) {
	v := loadSignedMessageKAT2(t).vector(t, "UnregisterStorageNode")
	_, want := kindAndBody(t, v.TransactionJSON)
	for _, alg := range []SignatureAlgorithm{Ed25519, Secp256k1} {
		t.Run(string(alg), func(t *testing.T) {
			srv, txs := txServer(t, 0)
			client, err := NewClient(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			id := vectorIdentity(t, alg)
			if err := client.Files.UnregisterStorageNode("did:willow:a", fileSigning(id, 14)); err != nil {
				t.Fatal(err)
			}
			unsigned, signature := withEmptySignature(t, sentTx(t, txs, "UnregisterStorageNode"))
			if !sameJSON(t, unsigned, want) {
				t.Fatalf("sent\n %s\nwant\n %s", unsigned, want)
			}
			var tx struct {
				NodeDID string `json:"node_did"`
				Nonce   uint64 `json:"nonce"`
			}
			decodeExactly(t, unsigned, &tx)
			message, err := FormatUnregisterStorageNodeMessage(tx.NodeDID, tx.Nonce)
			if err != nil {
				t.Fatal(err)
			}
			if ok, err := Verify(alg, id.KeyPair.PublicKey, []byte(message), signature); err != nil || !ok {
				t.Fatalf("signature does not verify over\n%s\n(%v)", message, err)
			}
			if alg == Ed25519 && hex.EncodeToString(signature) != v.Ed25519SignatureHex {
				t.Fatalf("signature %x, want the KAT's %s", signature, v.Ed25519SignatureHex)
			}
		})
	}
}

// Registration.RegisterSubgrove sends a RegisterSubgrove transaction with every
// field, signed over the message built from the JSON it sends; with the KAT's
// inputs it is the KAT's transaction and signature.
func TestRegisterSubgroveSignsTheTransactionItSends(t *testing.T) {
	v := loadSignedMessageKAT2(t).vector(t, "RegisterSubgrove (data, defaults)")
	_, want := kindAndBody(t, v.TransactionJSON)
	for _, alg := range []SignatureAlgorithm{Ed25519, Secp256k1} {
		t.Run(string(alg), func(t *testing.T) {
			srv, txs := txServer(t, 3)
			client, id := clientFor(t, srv, alg)
			req := NewSubgroveBuilder("sg-1", "").Owner(id.DID()).Build()
			write, err := client.Registration.RegisterSubgrove(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			if *write != (WriteResult{DID: id.DID(), Nonce: 4, TxHash: "AB"}) {
				t.Fatalf("RegisterSubgrove = %+v", write)
			}
			body := sentTx(t, txs, "RegisterSubgrove")
			unsigned, signature := withEmptySignature(t, body)
			if !sameJSON(t, unsigned, want) {
				t.Fatalf("sent\n %s\nwant\n %s", unsigned, want)
			}
			// The message is rebuilt from the JSON sent, as the chain does.
			bincode, err := consensus.RegisterSubgroveUnsignedBincode(body)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(bincode) != *v.UnsignedBincodeHex {
				t.Fatalf("bincode of the sent transaction:\n got %x\nwant %s", bincode, *v.UnsignedBincodeHex)
			}
			if ok, err := Verify(alg, id.KeyPair.PublicKey, []byte(v.Message), signature); err != nil || !ok {
				t.Fatalf("signature does not verify over\n%s\n(%v)", v.Message, err)
			}
			if alg == Ed25519 && hex.EncodeToString(signature) != v.Ed25519SignatureHex {
				t.Fatalf("signature %x, want the KAT's %s", signature, v.Ed25519SignatureHex)
			}
		})
	}
}

// The request's schema, writers, and readers go into the transaction in the
// chain's form, and the signature covers them.
func TestRegisterSubgroveSendsTheRequestsFields(t *testing.T) {
	srv, txs := txServer(t, 41)
	client, id := clientFor(t, srv, Ed25519)
	schema := NewSchemaBuilder("Note").StringField("title", true).IntField("rank", false).Build()
	req := NewSubgroveBuilder("notes-2", "Notes").Description("Team\nnotes").Schema(*schema).
		AddWriter(id.DID()).AddReader("did:willow:c").Build()
	if _, err := client.Registration.RegisterSubgrove(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	body := sentTx(t, txs, "RegisterSubgrove")
	var tx consensus.RegisterSubgroveTx
	decodeExactly(t, body, &tx)
	wantSchema := `{"version":1,"fields":{"rank":"number","title":"string"},"indexes":[],"required_fields":["title"]}`
	if tx.Schema != wantSchema || tx.Nonce != 42 || tx.Description != "Team\nnotes" ||
		tx.Mode.DataStorage.Name != "Notes" || tx.Mode.DataStorage.Writers[0] != id.DID() ||
		tx.Mode.DataStorage.FreeReaders[0] != "did:willow:c" {
		t.Fatalf("sent %s", body)
	}
	bincode, err := consensus.RegisterSubgroveUnsignedBincode(body)
	if err != nil {
		t.Fatal(err)
	}
	message := "RegisterSubgrove\nSubgrove: notes-2\nOwner: did:willow:a\nConfig: " + sha256Hex(bincode) + "\nNonce: 42"
	if ok, _ := Verify(Ed25519, id.KeyPair.PublicKey, []byte(message), tx.Signature); !ok {
		t.Fatalf("signature does not verify over\n%s", message)
	}

	// Fields the transaction has no place for are refused before anything is sent.
	*txs = nil
	for name, bad := range map[string]*RegisterSubgroveRequest{
		"another owner": NewSubgroveBuilder("s", "S").Owner("did:willow:b").Build(),
		"reward rate":   NewSubgroveBuilder("s", "S").RewardRate(5).Build(),
		"field type":    NewSubgroveBuilder("s", "S").Schema(SchemaDefinition{Fields: []SchemaField{{Name: "x", Type: "date"}}}).Build(),
		"line break":    NewSubgroveBuilder("s\n", "S").Build(),
		"schema index":  NewSubgroveBuilder("s", "S").Schema(*NewSchemaBuilder("S").StringField("x", true).HashIndex("by_x", []string{"x"}).Build()).Build(),
		"indexed field": NewSubgroveBuilder("s", "S").Schema(*NewSchemaBuilder("S").Field("x", "string", true, true).Build()).Build(),
		"subgrove id":   NewSubgroveBuilder("my subgrove", "S").Build(),
	} {
		if _, err := client.Registration.RegisterSubgrove(context.Background(), bad); !IsValidationError(err) {
			t.Errorf("%s: got %v, want a validation error", name, err)
		}
	}
	if len(*txs) != 0 {
		t.Fatalf("sent %d transactions, want none", len(*txs))
	}
}

func sha256Hex(b []byte) string {
	digest := sha256.Sum256(b)
	return hex.EncodeToString(digest[:])
}

// A grant or rotation whose grantee isn't a DID, and a revoke whose subgrove
// id holds ':' or whose revokee or sender isn't a DID, are what the chain
// refuses: the builders refuse them before signing, and the flows send
// nothing.
func TestKeyGrantsAndRevokesTheChainRefusesAreNotSigned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("sent %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	client, err := NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	client.SetIdentity(vectorIdentity(t, Ed25519))
	ctx := context.Background()

	good := EncryptedKeyGrant{
		GranteeDID: "did:willow:b", GranteePublicKeyID: "did:willow:b#key-1",
		EphemeralPublicKey: make([]byte, 32), EncryptedKey: []byte{1}, GrantedBy: "did:willow:a",
	}
	for name, did := range map[string]string{
		"no prefix":      "b",
		"another method": "did:key:b",
		"empty body":     "did:willow:",
		"colon":          "did:willow:b:c",
		"space":          "did:willow:b c",
		"non-ASCII":      "did:willow:bé",
		"over 128 bytes": "did:willow:" + strings.Repeat("a", 118),
	} {
		bad := good
		bad.GranteeDID = did
		refused := func(what string, err error) {
			if !IsValidationError(err) {
				t.Errorf("%s, %s: %v; want a validation error", name, what, err)
			}
		}
		_, err := FormatGrantSubgroveKeyMessage("sg", "did:willow:a", bad, 1)
		refused("grant message", err)
		_, err = FormatRotateSubgroveKeyMessage("sg", "did:willow:a", 1, []EncryptedKeyGrant{good, bad}, 1)
		refused("rotation message", err)
		_, err = client.Privacy.GrantSubgroveKey(ctx, "sg", bad)
		refused("GrantSubgroveKey", err)
		_, err = client.Privacy.RotateSubgroveKey(ctx, "sg", 1, []EncryptedKeyGrant{good, bad})
		refused("RotateSubgroveKey", err)
		_, err = client.Privacy.RevokeSubgroveKey(ctx, "sg", did)
		refused("RevokeSubgroveKey revokee", err)
		_, err = revokeSubgroveKeyMessage("sg", did, "did:willow:a", 1)
		refused("revoke message revokee", err)
		_, err = revokeSubgroveKeyMessage("sg", "did:willow:b", did, 1)
		refused("revoke message sender", err)
	}
	for _, id := range []string{"s:g", ":", ""} {
		if _, err := client.Privacy.RevokeSubgroveKey(ctx, id, "did:willow:b"); !IsValidationError(err) {
			t.Errorf("RevokeSubgroveKey of subgrove %q: %v; want a validation error", id, err)
		}
	}

	// DIDs at the rule's edges sign.
	longest := good
	longest.GranteeDID = "did:willow:" + strings.Repeat("Z", 117)
	if _, err := FormatGrantSubgroveKeyMessage("sg", "did:willow:a", longest, 1); err != nil {
		t.Errorf("a 128-byte grantee: %v", err)
	}
	if _, err := FormatRotateSubgroveKeyMessage("sg", "did:willow:a", 1, []EncryptedKeyGrant{good, longest}, 1); err != nil {
		t.Errorf("a rotation to a 128-byte grantee: %v", err)
	}
	if msg, err := revokeSubgroveKeyMessage("sg-1", "did:willow:b_-9", "did:willow:a", 3); err != nil ||
		msg != "RevokeSubgroveKey:sg-1:did:willow:b_-9:did:willow:a:3" {
		t.Errorf("revoke message = %q, %v", msg, err)
	}
}
