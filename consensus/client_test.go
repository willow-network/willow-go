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

// testBlock is a /block answer as CometBFT writes it: 64-bit integers as
// decimal strings, hashes and addresses in hex, transactions and signatures
// in base64.
const testBlock = `{"jsonrpc":"2.0","id":-1,"result":{"block_id":{"hash":"B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1","parts":{"total":1,"hash":"B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2"}},` +
	`"block":{"header":{"version":{"block":"11"},"chain_id":"test-chain","height":"7","time":"1970-01-01T00:00:01.5Z",` +
	`"last_block_id":{"hash":"A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1","parts":{"total":1,"hash":"A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2"}},` +
	`"last_commit_hash":"C1C1C1C1C1C1C1C1C1C1C1C1C1C1C1C1C1C1C1C1C1C1C1C1C1C1C1C1C1C1C1C1","data_hash":"E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",` +
	`"validators_hash":"C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2","next_validators_hash":"C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2C2",` +
	`"consensus_hash":"C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3","app_hash":"C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4",` +
	`"last_results_hash":"C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5C5","evidence_hash":"E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",` +
	`"proposer_address":"D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1"},"data":{"txs":["AQID","BAU="]},"evidence":{"evidence":[]},` +
	`"last_commit":{"height":"6","round":0,"block_id":{"hash":"A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1","parts":{"total":1,"hash":"A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2"}},` +
	`"signatures":[{"block_id_flag":2,"validator_address":"D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1","timestamp":"1970-01-01T00:00:01.5Z",` +
	`"signature":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw=="},` +
	`{"block_id_flag":1,"validator_address":"","timestamp":"0001-01-01T00:00:00Z","signature":null}]}}}}`

// GetBlock and GetLatestBlock decode the block into typed fields, asking for
// the height given (or none, for the latest).
func TestGetBlockDecodesTheBlock(t *testing.T) {
	var heights []interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string                 `json:"method"`
			Params map[string]interface{} `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Method != "block" {
			t.Errorf("request %+v (%v), want the block method", req, err)
		}
		heights = append(heights, req.Params["height"])
		_, _ = w.Write([]byte(testBlock))
	}))
	defer srv.Close()
	client := NewClient(ClientConfig{RPCURL: srv.URL})

	byHeight, err := client.GetBlock(context.Background(), 7)
	if err != nil {
		t.Fatal(err)
	}
	latest, err := client.GetLatestBlock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, got := range []*BlockResult{byHeight, latest} {
		h := got.Block.Header
		if got.BlockID.Hash != "B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1" || got.BlockID.Parts.Total != 1 ||
			h.Version.Block != 11 || h.ChainID != "test-chain" || h.Height != 7 || !h.Time.Equal(time.Unix(1, 5e8)) ||
			h.LastBlockID.Hash != "A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1" ||
			h.AppHash != "C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4C4" ||
			h.ProposerAddress != "D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1D1" {
			t.Fatalf("block %+v", got)
		}
		if txs := got.Block.Data.Txs; len(txs) != 2 || string(txs[0]) != "\x01\x02\x03" || string(txs[1]) != "\x04\x05" {
			t.Fatalf("transactions %v", txs)
		}
		c := got.Block.LastCommit
		if c == nil || c.Height != 6 || c.Round != 0 || len(c.Signatures) != 2 || c.Signatures[0].BlockIDFlag != 2 ||
			len(c.Signatures[0].Signature) != 64 || c.Signatures[1].Signature != nil {
			t.Fatalf("last commit %+v", c)
		}
	}
	if len(heights) != 2 || heights[0] != "7" || heights[1] != nil {
		t.Fatalf("heights asked for %v, want [7 <nil>]", heights)
	}
}
