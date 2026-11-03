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

	if len(bodies) != 3 {
		t.Fatalf("got %d transactions, want 3", len(bodies))
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
}
