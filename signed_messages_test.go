package willow

import (
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/willow-network/willow-go/consensus"
)

// testdata/signed_messages_kat.json is the chain's known-answer file for the
// messages data and file writes are signed over, byte for byte: the inputs,
// the exact message, and its signatures by the key whose seed is 32 bytes of
// 0x03.
type signedMessageKAT struct {
	PrivateKeySeedHex               string `json:"private_key_seed_hex"`
	PublicKeyID                     string `json:"public_key_id"`
	Ed25519PublicKeyHex             string `json:"ed25519_public_key_hex"`
	Secp256k1PublicKeyCompressedHex string `json:"secp256k1_public_key_compressed_hex"`
	Vectors                         []struct {
		Name   string `json:"name"`
		Inputs struct {
			SubgroveID         string `json:"subgrove_id"`
			Key                string `json:"key"`
			FileKey            string `json:"file_key"`
			OwnerDID           string `json:"owner_did"`
			DataUTF8           string `json:"data_utf8"`
			Filename           string `json:"filename"`
			ContentType        string `json:"content_type"`
			TotalSize          uint64 `json:"total_size"`
			ContentHashHex     string `json:"content_hash_hex"`
			ChunkCount         uint32 `json:"chunk_count"`
			ChunkSize          uint32 `json:"chunk_size"`
			ChunkMerkleRootHex string `json:"chunk_merkle_root_hex"`
			Encryption         *struct {
				KeyEpoch uint64 `json:"key_epoch"`
				NonceHex string `json:"nonce_hex"`
			} `json:"encryption"`
			Nonce uint64 `json:"nonce"`
		} `json:"inputs"`
		Message                      string `json:"message"`
		Ed25519SignatureHex          string `json:"ed25519_signature_hex"`
		Secp256k1Keccak256Hex        string `json:"secp256k1_keccak256_hex"`
		Secp256k1CompactSignatureHex string `json:"secp256k1_compact_signature_hex"`
	} `json:"vectors"`
}

func loadSignedMessageKAT(t *testing.T) *signedMessageKAT {
	t.Helper()
	raw, err := os.ReadFile("testdata/signed_messages_kat.json")
	if err != nil {
		t.Fatal(err)
	}
	var kat signedMessageKAT
	if err := json.Unmarshal(raw, &kat); err != nil {
		t.Fatal(err)
	}
	return &kat
}

func hex32(t *testing.T, s string) [32]byte {
	t.Helper()
	var out [32]byte
	if b := mustHex(t, s); len(b) != 32 || copy(out[:], b) != 32 {
		t.Fatalf("%q is not 32 bytes", s)
	}
	return out
}

// derToCompact turns a DER ECDSA signature into its 64-byte r||s.
func derToCompact(t *testing.T, der []byte) []byte {
	t.Helper()
	var sig struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(der, &sig); err != nil || len(rest) != 0 {
		t.Fatalf("not a DER signature: %x (%v)", der, err)
	}
	out := make([]byte, 64)
	sig.R.FillBytes(out[:32])
	sig.S.FillBytes(out[32:])
	return out
}

// Vectors for kinds this SDK neither sends nor builds a message for.
var katKindsNotSent = map[string]bool{"UpdateData": true, "DeleteData": true}

func TestSignedMessagesAreTheChainsKnownAnswers(t *testing.T) {
	kat := loadSignedMessageKAT(t)
	edID := vectorIdentity(t, Ed25519)
	secpID := vectorIdentity(t, Secp256k1)
	if kat.PrivateKeySeedHex != strings.Repeat("03", 32) || kat.PublicKeyID != edID.PublicKeyID() ||
		kat.Ed25519PublicKeyHex != edID.KeyPair.PublicKeyHex() ||
		kat.Secp256k1PublicKeyCompressedHex != secpID.KeyPair.PublicKeyHex() {
		t.Fatalf("the vector keys are not the KAT's keys")
	}

	checked := 0
	for _, v := range kat.Vectors {
		in := v.Inputs
		var got string
		var err error
		switch v.Name {
		case "StoreData":
			got, err = FormatDataStoreMessage(in.SubgroveID, in.Key, in.OwnerDID, []byte(in.DataUTF8), in.Nonce)
		case "StoreFileManifest", "StoreFileManifest (encrypted)":
			fields := FileManifestFields{
				SubgroveID:      in.SubgroveID,
				FileKey:         in.FileKey,
				OwnerDID:        in.OwnerDID,
				Filename:        in.Filename,
				ContentType:     in.ContentType,
				TotalSize:       in.TotalSize,
				ContentHash:     hex32(t, in.ContentHashHex),
				ChunkCount:      in.ChunkCount,
				ChunkSize:       in.ChunkSize,
				ChunkMerkleRoot: hex32(t, in.ChunkMerkleRootHex),
				Nonce:           in.Nonce,
			}
			if in.Encryption != nil {
				fields.Encryption = &FileEncryption{KeyEpoch: in.Encryption.KeyEpoch}
				if copy(fields.Encryption.Nonce[:], mustHex(t, in.Encryption.NonceHex)) != 24 {
					t.Fatalf("%s: encryption nonce is not 24 bytes", v.Name)
				}
			}
			got, err = FormatStoreFileManifestMessage(fields)
		case "DeleteFileManifest":
			got, err = FormatDeleteFileManifestMessage(in.SubgroveID, in.FileKey, in.OwnerDID, in.Nonce)
		default:
			if katKindsNotSent[v.Name] {
				continue
			}
			t.Fatalf("vector %q has no builder here", v.Name)
		}
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		if got != v.Message {
			t.Fatalf("%s message:\n got %q\nwant %q", v.Name, got, v.Message)
		}

		edSig, err := edID.Sign([]byte(got))
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(edSig) != v.Ed25519SignatureHex {
			t.Errorf("%s Ed25519 signature:\n got %x\nwant %s", v.Name, edSig, v.Ed25519SignatureHex)
		}

		// secp256k1: over the Keccak-256 of the message, RFC 6979, lower-S.
		// The SDK sends DER; its r||s is the KAT's compact signature.
		if digest := hex.EncodeToString(keccak256([]byte(got))); digest != v.Secp256k1Keccak256Hex {
			t.Errorf("%s Keccak-256 = %s, want %s", v.Name, digest, v.Secp256k1Keccak256Hex)
		}
		der, err := secpID.Sign([]byte(got))
		if err != nil {
			t.Fatal(err)
		}
		if compact := hex.EncodeToString(derToCompact(t, der)); compact != v.Secp256k1CompactSignatureHex {
			t.Errorf("%s secp256k1 signature:\n got %s\nwant %s", v.Name, compact, v.Secp256k1CompactSignatureHex)
		}
		for _, sig := range [][]byte{der, mustHex(t, v.Secp256k1CompactSignatureHex)} {
			if ok, err := Verify(Secp256k1, secpID.KeyPair.PublicKey, []byte(got), sig); err != nil || !ok {
				t.Errorf("%s secp256k1 Verify(%x) = %v, %v", v.Name, sig, ok, err)
			}
		}
		checked++
	}
	if checked != 4 {
		t.Fatalf("checked %d vectors, want 4 (StoreData, StoreFileManifest twice, DeleteFileManifest)", checked)
	}
}

func TestSignedMessagesRefuseLineBreaks(t *testing.T) {
	file := func(edit func(*FileManifestFields)) func() (string, error) {
		return func() (string, error) {
			f := FileManifestFields{SubgroveID: "sg", FileKey: "k", OwnerDID: "did:willow:a",
				Filename: "f.png", ContentType: "image/png", Nonce: 1}
			edit(&f)
			return FormatStoreFileManifestMessage(f)
		}
	}
	cases := map[string]func() (string, error){
		"StoreData Subgrove":            func() (string, error) { return FormatDataStoreMessage("s\ng", "k", "did:willow:a", nil, 1) },
		"StoreData Key":                 func() (string, error) { return FormatDataStoreMessage("sg", "k\n", "did:willow:a", nil, 1) },
		"StoreData Owner":               func() (string, error) { return FormatDataStoreMessage("sg", "k", "did:willow:a\n", nil, 1) },
		"StoreFileManifest Subgrove":    file(func(f *FileManifestFields) { f.SubgroveID = "s\ng" }),
		"StoreFileManifest Key":         file(func(f *FileManifestFields) { f.FileKey = "\nk" }),
		"StoreFileManifest Owner":       file(func(f *FileManifestFields) { f.OwnerDID = "did:willow:a\n" }),
		"StoreFileManifest Filename":    file(func(f *FileManifestFields) { f.Filename = "f.png\nNonce: 2" }),
		"StoreFileManifest ContentType": file(func(f *FileManifestFields) { f.ContentType = "image/png\n" }),
		"DeleteFileManifest Subgrove": func() (string, error) {
			return FormatDeleteFileManifestMessage("s\ng", "k", "did:willow:a", 1)
		},
		"DeleteFileManifest Key": func() (string, error) {
			return FormatDeleteFileManifestMessage("sg", "k\n", "did:willow:a", 1)
		},
		"DeleteFileManifest Owner": func() (string, error) {
			return FormatDeleteFileManifestMessage("sg", "k", "\ndid:willow:a", 1)
		},
	}
	for name, build := range cases {
		if msg, err := build(); err == nil || !IsValidationError(err) || msg != "" {
			t.Errorf("%s: got %q, %v; want a validation error", name, msg, err)
		}
	}
	// Data may hold line breaks: only its hash is in the message.
	if _, err := FormatDataStoreMessage("sg", "k", "did:willow:a", []byte("{\n}"), 1); err != nil {
		t.Errorf("data with a line break: %v", err)
	}
}

// txCapture is a mocked API and storage node that records each transaction
// posted to /tx/submit.
func txCapture(t *testing.T) (*httptest.Server, *[]map[string]map[string]json.RawMessage) {
	t.Helper()
	var txs []map[string]map[string]json.RawMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/tx/submit":
			var tx map[string]map[string]json.RawMessage
			if err := json.NewDecoder(r.Body).Decode(&tx); err != nil {
				t.Error(err)
			}
			txs = append(txs, tx)
			_, _ = w.Write([]byte(`{"success":true,"data":{"tx_hash":"AB","code":0,"log":""}}`))
		case strings.HasPrefix(r.URL.Path, "/upload/"):
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &txs
}

// txFields decodes a transaction's fields, failing unless its field names are
// exactly want.
func txFields(t *testing.T, fields map[string]json.RawMessage, want []string, out any) {
	t.Helper()
	var names []string
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	sort.Strings(want)
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("transaction fields %v, want %v", names, want)
	}
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatal(err)
	}
}

func fileSigning(id *Identity, nonce uint64) *FileSigningOptions {
	return &FileSigningOptions{OwnerDID: id.DID(), PublicKeyID: id.PublicKeyID(), SignFunc: id.SignHex, Nonce: nonce}
}

// The StoreFileManifest an upload sends is signed over the message built from
// its own fields, nonce included.
func TestFileUploadSignsTheManifestItSends(t *testing.T) {
	for _, alg := range []SignatureAlgorithm{Ed25519, Secp256k1} {
		t.Run(string(alg), func(t *testing.T) {
			srv, txs := txCapture(t)
			client, err := NewClient(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			id := vectorIdentity(t, alg)
			data := []byte(strings.Repeat("willow", DefaultChunkSize/3)) // two chunks
			if _, err := client.Files.Upload("files-1", "photo.png", "photo.png", data, srv.URL, fileSigning(id, 9)); err != nil {
				t.Fatal(err)
			}
			if len(*txs) != 1 {
				t.Fatalf("sent %d transactions, want 1", len(*txs))
			}
			var tx struct {
				SubgroveID      string              `json:"subgrove_id"`
				FileKey         string              `json:"file_key"`
				Filename        string              `json:"filename"`
				ContentType     string              `json:"content_type"`
				TotalSize       uint64              `json:"total_size"`
				ContentHash     consensus.ByteArray `json:"content_hash"`
				ChunkCount      uint32              `json:"chunk_count"`
				ChunkSize       uint32              `json:"chunk_size"`
				ChunkMerkleRoot consensus.ByteArray `json:"chunk_merkle_root"`
				OwnerDID        string              `json:"owner_did"`
				Signature       consensus.ByteArray `json:"signature"`
				PublicKeyID     string              `json:"public_key_id"`
				Nonce           uint64              `json:"nonce"`
			}
			// No encryption field is sent, so the message's Encryption is none.
			txFields(t, (*txs)[0]["StoreFileManifest"], []string{"subgrove_id", "file_key", "filename",
				"content_type", "total_size", "content_hash", "chunk_count", "chunk_size", "chunk_merkle_root",
				"owner_did", "signature", "public_key_id", "nonce"}, &tx)
			if tx.Nonce != 9 || tx.ChunkCount != 2 || tx.OwnerDID != id.DID() || tx.PublicKeyID != id.PublicKeyID() {
				t.Fatalf("transaction %+v", tx)
			}
			if len(tx.ContentHash) != 32 || len(tx.ChunkMerkleRoot) != 32 {
				t.Fatalf("content_hash %x, chunk_merkle_root %x", tx.ContentHash, tx.ChunkMerkleRoot)
			}
			fields := FileManifestFields{
				SubgroveID:  tx.SubgroveID,
				FileKey:     tx.FileKey,
				OwnerDID:    tx.OwnerDID,
				Filename:    tx.Filename,
				ContentType: tx.ContentType,
				TotalSize:   tx.TotalSize,
				ChunkCount:  tx.ChunkCount,
				ChunkSize:   tx.ChunkSize,
				Nonce:       tx.Nonce,
			}
			copy(fields.ContentHash[:], tx.ContentHash)
			copy(fields.ChunkMerkleRoot[:], tx.ChunkMerkleRoot)
			message, err := FormatStoreFileManifestMessage(fields)
			if err != nil {
				t.Fatal(err)
			}
			if ok, err := Verify(alg, id.KeyPair.PublicKey, []byte(message), tx.Signature); err != nil || !ok {
				t.Fatalf("signature does not verify over\n%s\n(%v)", message, err)
			}
			fields.Nonce++
			other, _ := FormatStoreFileManifestMessage(fields)
			if ok, _ := Verify(alg, id.KeyPair.PublicKey, []byte(other), tx.Signature); ok {
				t.Fatal("signature verifies under another nonce")
			}
		})
	}
}

// The DeleteFileManifest a delete sends is signed over the message built from
// its own fields, nonce included; with the KAT's inputs it is the KAT's.
func TestFileDeleteSignsTheTransactionItSends(t *testing.T) {
	kat := loadSignedMessageKAT(t)
	var wantSig string
	for _, v := range kat.Vectors {
		if v.Name == "DeleteFileManifest" {
			wantSig = v.Ed25519SignatureHex
		}
	}
	for _, alg := range []SignatureAlgorithm{Ed25519, Secp256k1} {
		t.Run(string(alg), func(t *testing.T) {
			srv, txs := txCapture(t)
			client, err := NewClient(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			id := vectorIdentity(t, alg)
			if err := client.Files.Delete("files-1", "photo.png", fileSigning(id, 11)); err != nil {
				t.Fatal(err)
			}
			if len(*txs) != 1 {
				t.Fatalf("sent %d transactions, want 1", len(*txs))
			}
			var tx struct {
				SubgroveID  string              `json:"subgrove_id"`
				FileKey     string              `json:"file_key"`
				OwnerDID    string              `json:"owner_did"`
				Signature   consensus.ByteArray `json:"signature"`
				PublicKeyID string              `json:"public_key_id"`
				Nonce       uint64              `json:"nonce"`
			}
			txFields(t, (*txs)[0]["DeleteFileManifest"], []string{"subgrove_id", "file_key", "owner_did",
				"signature", "public_key_id", "nonce"}, &tx)
			if tx.Nonce != 11 || tx.PublicKeyID != id.PublicKeyID() {
				t.Fatalf("transaction %+v", tx)
			}
			message, err := FormatDeleteFileManifestMessage(tx.SubgroveID, tx.FileKey, tx.OwnerDID, tx.Nonce)
			if err != nil {
				t.Fatal(err)
			}
			if ok, err := Verify(alg, id.KeyPair.PublicKey, []byte(message), tx.Signature); err != nil || !ok {
				t.Fatalf("signature does not verify over\n%s\n(%v)", message, err)
			}
			if alg == Ed25519 && hex.EncodeToString(tx.Signature) != wantSig {
				t.Fatalf("signature %x, want the KAT's %s", tx.Signature, wantSig)
			}
		})
	}
}

// A file write with a line break in a signed text field is refused before
// anything is sent.
func TestFileWritesRefuseLineBreaksBeforeSending(t *testing.T) {
	srv, txs := txCapture(t)
	client, err := NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	signing := fileSigning(vectorIdentity(t, Ed25519), 1)
	if _, err := client.Files.Upload("sg", "k", "a\nb.png", []byte("x"), srv.URL, signing); !IsValidationError(err) {
		t.Errorf("Upload: got %v, want a validation error", err)
	}
	if err := client.Files.Delete("sg", "k\n", signing); !IsValidationError(err) {
		t.Errorf("Delete: got %v, want a validation error", err)
	}
	if len(*txs) != 0 {
		t.Fatalf("sent %d transactions, want none", len(*txs))
	}
}
