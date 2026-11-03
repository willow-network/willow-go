package willow

import (
	"context"
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
		_, _ = w.Write([]byte(`{"success":true,"data":[{"did":"did:willow:a","subgrove_id":"sg","role":"Reader","granted_by":"did:willow:o","granted_at":1000}]}`))
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
	if len(perms) != 1 || perms[0].Role != "Reader" || perms[0].SubgroveID != "sg" {
		t.Fatalf("got %+v", perms)
	}
}

func TestMatchedLogsNeedAnIndexer(t *testing.T) {
	client, err := NewClient("http://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.FetchMatchedLogs(context.Background(), "sg", 7); err == nil {
		t.Fatal("matched logs fetched from the API, which does not serve them")
	}
}
