package consensus

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// GetTx sends the tx method's hash as base64 of its 32 bytes, the form
// CometBFT's JSON-RPC reads a byte parameter in (a hex string would be read as
// base64 and name other bytes), and reads the block result back.
func TestGetTxSendsTheHashAsBase64(t *testing.T) {
	const hexHash = "AB01CD02EF03AB01CD02EF03AB01CD02EF03AB01CD02EF03AB01CD02EF03AB01"
	// base64 of the hash's 32 bytes.
	const want = "qwHNAu8DqwHNAu8DqwHNAu8DqwHNAu8DqwHNAu8DqwE="
	var params []map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string                 `json:"method"`
			Params map[string]interface{} `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Method != "tx" {
			t.Errorf("request %+v (%v), want the tx method", req, err)
		}
		params = append(params, req.Params)
		w.Header().Set("Content-Type", "application/json")
		if len(params) == 3 {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"Internal error","data":"tx (AB01) not found"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"hash":"` + hexHash + `","height":"42","index":2,` +
			`"tx_result":{"code":1,"log":"Subgrove not found (nonce 9 spent)","gas_used":"5","gas_wanted":"7","data":null},"tx":"AAE="}}`))
	}))
	defer srv.Close()
	client := NewClient(ClientConfig{RPCURL: srv.URL})

	for _, given := range []string{hexHash, "0x" + strings.ToLower(hexHash)} {
		result, err := client.GetTx(context.Background(), given)
		if err != nil {
			t.Fatalf("GetTx(%s): %v", given, err)
		}
		if result.Status != TransactionStatusFailed || result.Height != 42 || result.Index != 2 ||
			result.Code != 1 || result.Log != "Subgrove not found (nonce 9 spent)" || result.GasUsed != 5 ||
			result.GasWant != 7 || result.Hash != hexHash {
			t.Fatalf("GetTx(%s) = %+v", given, result)
		}
	}
	result, err := client.GetTx(context.Background(), hexHash)
	if err != nil || result.Status != TransactionStatusNotFound {
		t.Fatalf("unknown hash: %+v, %v, want not found", result, err)
	}
	for i, p := range params {
		if p["hash"] != want || p["prove"] != false {
			t.Errorf("request %d params %v, want hash %s (base64 of the 32 bytes)", i, p, want)
		}
	}

	// A hash that isn't 32 bytes of hex sends nothing.
	sent := len(params)
	for _, bad := range []string{"", "xyz", hexHash[:62], hexHash + "00"} {
		if _, err := client.GetTx(context.Background(), bad); err == nil {
			t.Errorf("GetTx(%q) accepted", bad)
		}
	}
	if len(params) != sent {
		t.Fatalf("a bad hash sent a request")
	}
}

// Only CometBFT's not-found answer is a not-found result; another internal
// error (the node indexes no transactions, say) is an error.
func TestGetTxReportsOtherErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"Internal error","data":"transaction indexing is disabled"}}`))
	}))
	defer srv.Close()
	client := NewClient(ClientConfig{RPCURL: srv.URL})
	if result, err := client.GetTx(context.Background(), strings.Repeat("00", 32)); err == nil {
		t.Fatalf("GetTx = %+v, want an error", result)
	}
}

// A result for another transaction than the one asked for, or that names no
// hash, is an error, not that transaction's result.
func TestGetTxRefusesAnotherTransactionsResult(t *testing.T) {
	const asked = "AB01CD02EF03AB01CD02EF03AB01CD02EF03AB01CD02EF03AB01CD02EF03AB01"
	for name, hash := range map[string]string{
		"another hash":         strings.Repeat("CD", 32),
		"a hash 1 byte longer": asked + "00",
		"no hash":              "",
		"a hash not in hex":    strings.Repeat("ZZ", 32),
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"hash":"` + hash + `","height":"42","index":0,` +
				`"tx_result":{"code":0,"log":"","gas_used":"1","gas_wanted":"1","data":null},"tx":"AAE="}}`))
		}))
		result, err := NewClient(ClientConfig{RPCURL: srv.URL}).GetTx(context.Background(), asked)
		srv.Close()
		if err == nil {
			t.Errorf("%s: %+v; want an error", name, result)
		}
	}
}

// A config that leaves Timeout 0 gets DefaultClientConfig's timeout, not
// none; a timeout the config gives is kept.
func TestNewClientDefaultsTheTimeout(t *testing.T) {
	if got := NewClient(ClientConfig{RPCURL: "http://rpc"}).httpClient.Timeout; got != DefaultClientConfig().Timeout {
		t.Errorf("a config without a timeout: %v", got)
	}
	if got := NewClient(ClientConfig{Timeout: time.Second}).httpClient.Timeout; got != time.Second {
		t.Errorf("a config of 1 s: %v", got)
	}
}
