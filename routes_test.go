package willow

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTransactionsGoToTxSubmit(t *testing.T) {
	code := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/tx/submit" {
			t.Errorf("got %s %s, want POST /tx/submit", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		if code == 0 {
			_, _ = w.Write([]byte(`{"success":true,"data":{"tx_hash":"AB","code":0,"log":""}}`))
		} else {
			_, _ = w.Write([]byte(`{"success":true,"data":{"tx_hash":"AB","code":5,"log":"bad nonce"}}`))
		}
	}))
	defer srv.Close()
	client, err := NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.submitTx(context.Background(), map[string]any{"GrantSubgroveKey": map[string]any{}}); err != nil {
		t.Fatalf("accepted tx: %v", err)
	}
	// CheckTx refusals come back as HTTP 200 with a nonzero code.
	code = 5
	err = client.submitTx(context.Background(), map[string]any{"GrantSubgroveKey": map[string]any{}})
	var txErr *TransactionError
	if !errors.As(err, &txErr) || txErr.ErrorCode != 5 {
		t.Fatalf("refused tx: got %v, want a TransactionError with code 5", err)
	}
}

func TestGetPermissionsReadsTheDIDPermissionsRoute(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/did/did:willow:a/permissions" {
			t.Errorf("got %s, want /did/did:willow:a/permissions", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":[{"did":"did:willow:a","subgrove_id":"sg","role":"reader","granted_by":"did:willow:o","granted_at":1000}]}`))
	}))
	defer srv.Close()
	client, err := NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	perms, err := client.Registration.GetPermissions(context.Background(), "did:willow:a")
	if err != nil {
		t.Fatal(err)
	}
	if len(perms) != 1 || perms[0].Role != "reader" || perms[0].SubgroveID != "sg" {
		t.Fatalf("got %+v", perms)
	}
}

func TestMatchedLogsNeedAnIndexer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("matched logs requested from the API: %s", r.URL.Path)
	}))
	defer srv.Close()
	client, err := NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.FetchMatchedLogs(context.Background(), "sg", 7)
	var werr *WillowError
	if !errors.As(err, &werr) || werr.Type != ErrorTypeConfig {
		t.Fatalf("got %v, want a config error", err)
	}
}

// /tx/submit decodes the chain's Transaction type, whose byte fields are JSON
// arrays of numbers.
func TestTransactionByteFieldsAreNumberArrays(t *testing.T) {
	var bodies []map[string]map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/account/did:willow:a/nonce":
			_, _ = w.Write([]byte(`{"success":true,"data":{"did":"did:willow:a","nonce":7}}`))
		case "/upload/sg/f":
			w.WriteHeader(http.StatusOK)
		case "/tx/submit":
			var body map[string]map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			bodies = append(bodies, body)
			_, _ = w.Write([]byte(`{"success":true,"data":{"tx_hash":"AB","code":0,"log":""}}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	client, err := NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	id := vectorIdentity(t, Ed25519)
	client.SetIdentity(id)
	ctx := context.Background()

	if err := client.Privacy.RevokeSubgroveKey(ctx, "sg", "did:willow:b"); err != nil {
		t.Fatal(err)
	}
	if err := client.Privacy.GrantSubgroveKey(ctx, "sg", EncryptedKeyGrant{
		GranteeDID: "did:willow:b", EphemeralPublicKey: []byte{1, 2}, EncryptedKey: []byte{3},
	}); err != nil {
		t.Fatal(err)
	}
	signing := &FileSigningOptions{OwnerDID: "did:willow:a", PublicKeyID: "did:willow:a#key-1",
		SignFunc: func(m []byte) (string, error) { return id.SignHex(m) }, Nonce: 3}
	if err := client.Files.Delete("sg", "f", signing); err != nil {
		t.Fatal(err)
	}
	if err := client.Privacy.RotateSubgroveKey(ctx, "sg", 2, nil); err != nil {
		t.Fatal(err)
	}
	if err := client.Files.UnregisterStorageNode("did:willow:n", signing); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Files.Upload("sg", "f", "f.txt", []byte("hello"), srv.URL, signing); err != nil {
		t.Fatal(err)
	}

	if len(bodies) != 6 {
		t.Fatalf("got %d transactions, want 6", len(bodies))
	}
	isNumberArray := func(v any, n int) bool {
		a, ok := v.([]any)
		if !ok || (n >= 0 && len(a) != n) {
			return false
		}
		for _, x := range a {
			if _, ok := x.(float64); !ok {
				return false
			}
		}
		return true
	}
	revoke := bodies[0]["RevokeSubgroveKey"]
	if !isNumberArray(revoke["signature"], 64) || revoke["nonce"] != float64(8) {
		t.Errorf("RevokeSubgroveKey: signature %v, nonce %v", revoke["signature"], revoke["nonce"])
	}
	grant := bodies[1]["GrantSubgroveKey"]
	keyGrant, _ := grant["encrypted_key_grant"].(map[string]any)
	if !isNumberArray(grant["signature"], 64) || !isNumberArray(keyGrant["ephemeral_public_key"], 2) ||
		!isNumberArray(keyGrant["encrypted_key"], 1) {
		t.Errorf("GrantSubgroveKey byte fields: %v", grant)
	}
	del := bodies[2]["DeleteFileManifest"]
	if !isNumberArray(del["signature"], 64) {
		t.Errorf("DeleteFileManifest signature: %v", del["signature"])
	}
	rotate := bodies[3]["RotateSubgroveKey"]
	if !isNumberArray(rotate["signature"], 64) {
		t.Errorf("RotateSubgroveKey signature: %v", rotate["signature"])
	}
	unregister := bodies[4]["UnregisterStorageNode"]
	if !isNumberArray(unregister["signature"], 64) {
		t.Errorf("UnregisterStorageNode signature: %v", unregister["signature"])
	}
	manifest := bodies[5]["StoreFileManifest"]
	if !isNumberArray(manifest["signature"], 64) || !isNumberArray(manifest["content_hash"], 32) ||
		!isNumberArray(manifest["chunk_merkle_root"], 32) {
		t.Errorf("StoreFileManifest byte fields: %v", manifest)
	}
}

// A transaction is submitted once: after a 5xx it may already be in the mempool.
func TestTransactionsAreNotResubmitted(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"success":false,"data":null,"error":"broadcast failed"}`))
	}))
	defer srv.Close()
	client, err := NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.submitTx(context.Background(), map[string]any{"RevokeSubgroveKey": map[string]any{}}); err == nil {
		t.Fatal("a 502 was reported as success")
	}
	if calls != 1 {
		t.Fatalf("submitted %d times, want 1", calls)
	}
}

func TestKeyGrantReadsUnwrapTheEnvelope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/key-grants/sg/did:willow:a":
			_, _ = w.Write([]byte(`{"success":true,"data":{"grantee_did":"did:willow:a","key_epoch":2,"grantee_public_key_id":"did:willow:a#key-1","ephemeral_public_key":[1,2],"encrypted_key":[3],"granted_by":"did:willow:o","granted_at":5}}`))
		case "/key-grants/sg":
			_, _ = w.Write([]byte(`{"success":true,"data":["did:willow:a","did:willow:b"]}`))
		}
	}))
	defer srv.Close()
	client, err := NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	client.SetIdentity(vectorIdentity(t, Ed25519))
	grant, err := client.Privacy.GetMyKeyGrant(context.Background(), "sg")
	if err != nil || grant.KeyEpoch != 2 || len(grant.EphemeralPublicKey) != 2 || grant.EncryptedKey[0] != 3 {
		t.Fatalf("GetMyKeyGrant = %+v, %v", grant, err)
	}
	grantees, err := client.Privacy.ListKeyGrantees(context.Background(), "sg")
	if err != nil || len(grantees) != 2 {
		t.Fatalf("ListKeyGrantees = %v, %v", grantees, err)
	}
}
