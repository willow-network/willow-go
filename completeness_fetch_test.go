package willow

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// authoritativeMatchedLogsBody is the exact /matched-logs response body for
// vector B (block 7), pinned against the cross-language correctness gate in
// completeness_test.go. Each IndexedLog carries many fields; only address,
// topics, and data are bound by the events_commitment, so the others are
// present here to prove they are correctly ignored during parsing.
const authoritativeMatchedLogsBody = `{
  "subgrove_id": "sg", "block_number": 7, "count": 2,
  "matched_logs": [
    { "block_number": 7, "block_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
      "transaction_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
      "transaction_index": 0, "log_index": "0x0",
      "address": "0x4242424242424242424242424242424242424242",
      "topics": ["0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                 "0x1111111111111111111111111111111111111111111111111111111111111111"],
      "data": "0x01020304", "removed": false },
    { "block_number": 7, "block_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
      "transaction_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
      "transaction_index": 0, "log_index": "0x1",
      "address": "0x4343434343434343434343434343434343434343",
      "topics": ["0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
      "data": "0x", "removed": false } ]
}`

// vectorBCommitmentHex is the on-chain events_commitment for vector B.
const vectorBCommitmentHex = "e1544ae919458663e8fce14bdcd06df6a777410c068302c0584dff1587524dfd"

// Gates JSON->Log parsing against the authoritative vector: the served body
// must rebuild exactly the Log set that re-hashes to vector B's commitment.
func TestParseMatchedLogsVectorB(t *testing.T) {
	logs, err := parseMatchedLogs([]byte(authoritativeMatchedLogsBody))
	if err != nil {
		t.Fatalf("parse matched logs: %v", err)
	}
	if len(logs) != 2 {
		t.Fatalf("expected 2 logs, got %d", len(logs))
	}

	want := hexCommitment(t, vectorBCommitmentHex)
	if !VerifyServedEvents(want, 7, logs) {
		t.Fatalf("parsed logs do not re-hash to vector B commitment:\n got %x\nwant %x",
			CanonicalEventSetHash(7, logs), want)
	}
}

// Empty/"0x" data must decode to a zero-length slice, not an error or nil-vs-empty mismatch.
func TestParseMatchedLogsEmptyData(t *testing.T) {
	logs, err := parseMatchedLogs([]byte(authoritativeMatchedLogsBody))
	if err != nil {
		t.Fatalf("parse matched logs: %v", err)
	}
	if len(logs[1].Data) != 0 {
		t.Fatalf(`"0x" data should decode to empty, got %x`, logs[1].Data)
	}
}

// Malformed served logs must be rejected, not silently accepted.
func TestParseMatchedLogsRejectsMalformed(t *testing.T) {
	cases := map[string]string{
		"short address": `{"matched_logs":[{"address":"0x4242","topics":[],"data":"0x"}]}`,
		"short topic":   `{"matched_logs":[{"address":"0x4242424242424242424242424242424242424242","topics":["0xdd"],"data":"0x"}]}`,
		"bad hex data":  `{"matched_logs":[{"address":"0x4242424242424242424242424242424242424242","topics":[],"data":"0xzz"}]}`,
	}
	for name, body := range cases {
		if _, err := parseMatchedLogs([]byte(body)); err == nil {
			t.Fatalf("%s: expected parse error, got nil", name)
		}
	}
}

// completenessTestServer returns an httptest.Server that serves both the
// CometBFT abci_query (POST /) anchor and the indexer matched-logs (GET) route.
// commitmentHex is returned as the events_commitment; matchedBody is returned
// verbatim for the matched-logs GET.
func completenessTestServer(t *testing.T, commitmentHex, matchedBody string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost:
			// CometBFT JSON-RPC abci_query for the events_commitment anchor.
			var req struct {
				Method string `json:"method"`
				Params struct {
					Path string `json:"path"`
				} `json:"params"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode abci_query request: %v", err)
			}
			if req.Method != "abci_query" {
				t.Fatalf("unexpected RPC method %q", req.Method)
			}
			anchor := map[string]interface{}{
				"subgrove_id":       "sg",
				"block_number":      7,
				"events_commitment": commitmentHex,
			}
			anchorJSON, _ := json.Marshal(anchor)
			value := base64.StdEncoding.EncodeToString(anchorJSON)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"response":{"code":0,"log":"","value":"` + value + `"}}}`))

		case r.Method == http.MethodGet && r.URL.Path == "/completeness/sg/7/matched-logs":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(matchedBody))

		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
}

// Full end-to-end mocked path: anchor fetch -> matched-logs fetch -> verify true.
func TestVerifyBlockCompletenessMockedTrue(t *testing.T) {
	server := completenessTestServer(t, vectorBCommitmentHex, authoritativeMatchedLogsBody)
	defer server.Close()

	client, err := NewClient(server.URL,
		WithRPCURL(server.URL),
		WithIndexerURL(server.URL),
	)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	ok, err := client.VerifyBlockCompleteness(context.Background(), "sg", 7)
	if err != nil {
		t.Fatalf("verify block completeness: %v", err)
	}
	if !ok {
		t.Fatal("expected completeness verification to pass for the authoritative vector")
	}
}

// A tampered served set must fail verification with a nil error (the served
// data was reachable, it just did not match the anchor).
func TestVerifyBlockCompletenessMockedTampered(t *testing.T) {
	tampered := `{"subgrove_id":"sg","block_number":7,"count":1,"matched_logs":[
      {"address":"0x4242424242424242424242424242424242424242",
       "topics":["0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"],
       "data":"0x01020304"}]}`
	server := completenessTestServer(t, vectorBCommitmentHex, tampered)
	defer server.Close()

	client, err := NewClient(server.URL, WithRPCURL(server.URL), WithIndexerURL(server.URL))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	ok, err := client.VerifyBlockCompleteness(context.Background(), "sg", 7)
	if err != nil {
		t.Fatalf("tampered set should fail verification, not error: %v", err)
	}
	if ok {
		t.Fatal("expected tampered served set to fail verification")
	}
}

// A missing on-chain anchor (ABCI code != 0) must surface as a not-verifiable error.
func TestVerifyBlockCompletenessNoAnchor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"response":{"code":1,"log":"No events commitment for block 7","value":""}}}`))
	}))
	defer server.Close()

	client, err := NewClient(server.URL, WithRPCURL(server.URL), WithIndexerURL(server.URL))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer client.Close()

	ok, err := client.VerifyBlockCompleteness(context.Background(), "sg", 7)
	if err == nil {
		t.Fatal("expected not-verifiable error when no on-chain anchor exists")
	}
	if ok {
		t.Fatal("expected false result when no anchor")
	}
}
