package willow

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/willow-network/willow-go/consensus"
)

// Writes the API serves no route for return an unsupported-operation error
// naming the supported path, and send nothing.
func TestUnservedWritesSendNothing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("sent %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	client, err := NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	id := vectorIdentity(t, Ed25519)
	client.SetIdentity(id)
	ctx := context.Background()
	data := map[string]interface{}{"a": 1}

	cases := map[string]struct {
		call func() error
		path string // the supported path the error names
	}{
		"RegisterDID": {func() error { _, err := client.RegisterDID(ctx, id.DidDocument); return err }, "RegisterDid transaction"},
		"Data.Store":  {func() error { return client.Data.Store(ctx, "sg", data) }, "StoreItem"},
		"Data.Update": {func() error { return client.Data.Update(ctx, "sg", "k", data) }, "UpdateData transaction"},
		"Data.Delete": {func() error { return client.Data.Delete(ctx, "sg", "k") }, "DeleteData transaction"},
		"Data.BatchStore": {func() error {
			return client.Data.BatchStore(ctx, "sg", []StoreRequest{{Key: "k", Data: data}})
		}, "StoreItem"},
		"Registration.UpdateSubgrove": {func() error {
			_, err := client.Registration.UpdateSubgrove(ctx, "sg", data)
			return err
		}, "UpdateSubgroveFreeReaders"},
		"Registration.GrantPermission": {func() error {
			return client.Registration.GrantPermission(ctx, &Permission{Did: "did:willow:b", SubgroveID: "sg"})
		}, "RegisterSubgrove transaction"},
		"Registration.RevokePermission": {func() error {
			return client.Registration.RevokePermission(ctx, "did:willow:b", "sg")
		}, "RegisterSubgrove transaction"},
		"Indexing.GetIndexerStatus": {func() error {
			_, err := client.Indexing.GetIndexerStatus(ctx, "did:willow:i", "sg")
			return err
		}, "GetIndexer"},
	}
	for name, c := range cases {
		err := c.call()
		if !IsUnsupported(err) || !strings.Contains(err.Error(), c.path) {
			t.Errorf("%s: got %v, want an unsupported error naming %q", name, err, c.path)
		}
	}
}

// StoreItem sends a StoreData transaction carrying the data's JSON bytes,
// signed over the message built from its own fields; with the chain's KAT
// inputs it is the KAT's signature.
func TestStoreItemSignsTheStoreDataItSends(t *testing.T) {
	kat := loadSignedMessageKAT(t)
	var wantSig string
	for _, v := range kat.Vectors {
		if v.Name == "StoreData" {
			wantSig = v.Ed25519SignatureHex
		}
	}
	for _, alg := range []SignatureAlgorithm{Ed25519, Secp256k1} {
		t.Run(string(alg), func(t *testing.T) {
			srv, txs := txServer(t, 6)
			client, id := clientFor(t, srv, alg)
			if err := client.Data.StoreItem(context.Background(), "sg-1", "doc1",
				map[string]interface{}{"value": 42, "title": "Hello"}); err != nil {
				t.Fatal(err)
			}
			var tx consensus.DataStoreTx
			if err := json.Unmarshal(sentTx(t, txs, "StoreData"), &tx); err != nil {
				t.Fatal(err)
			}
			if string(tx.Data) != `{"title":"Hello","value":42}` || tx.Nonce != 7 || tx.OwnerDid != id.DID() || tx.PublicKeyID != id.PublicKeyID() {
				t.Fatalf("sent %+v (data %q)", tx, tx.Data)
			}
			message, err := FormatDataStoreMessage(tx.SubgroveID, tx.Key, tx.OwnerDid, tx.Data, tx.Nonce)
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

	srv, txs := txServer(t, 6)
	client, _ := clientFor(t, srv, Ed25519)
	if err := client.Data.StoreItem(context.Background(), "sg", "k\n", map[string]interface{}{}); !IsValidationError(err) {
		t.Errorf("key with a line break: %v, want a validation error", err)
	}
	if err := client.Data.StoreItem(context.Background(), "sg", "k", nil); !IsValidationError(err) {
		t.Errorf("nil data: %v, want a validation error", err)
	}
	if len(*txs) != 0 {
		t.Fatalf("sent %d transactions, want none", len(*txs))
	}
}

// DeleteSubgrove sends a DeregisterSubgrove transaction signed over its own
// fields.
func TestDeleteSubgroveSendsADeregisterSubgrove(t *testing.T) {
	srv, txs := txServer(t, 20)
	client, id := clientFor(t, srv, Ed25519)
	if err := client.Registration.DeleteSubgrove(context.Background(), "sg"); err != nil {
		t.Fatal(err)
	}
	var tx consensus.DeregisterSubgroveTx
	if err := json.Unmarshal(sentTx(t, txs, "DeregisterSubgrove"), &tx); err != nil {
		t.Fatal(err)
	}
	if tx.SubgroveID != "sg" || tx.OwnerDid != id.DID() || tx.Nonce != 21 || tx.PublicKeyID != id.PublicKeyID() {
		t.Fatalf("sent %+v", tx)
	}
	message := consensus.DeregisterSubgroveSignMessage(tx.SubgroveID, tx.OwnerDid, tx.Nonce)
	if ok, err := Verify(Ed25519, id.KeyPair.PublicKey, []byte(message), tx.Signature); err != nil || !ok {
		t.Fatalf("signature does not verify over %q (%v)", message, err)
	}
}
