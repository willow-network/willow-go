package willow

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/willow-network/willow-go/consensus"
	"github.com/willow-network/willow-go/erc8004"
	"github.com/willow-network/willow-go/lightclient"
)

// oversizedServer answers every request with status 200 and "{}" after
// 64 MiB + 1 bytes of leading space: JSON, but more than the SDK reads of an
// answer.
func oversizedServer(t *testing.T) *httptest.Server {
	t.Helper()
	pad := bytes.Repeat([]byte{' '}, 1<<20)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		for i := 0; i < 64; i++ {
			if _, err := w.Write(pad); err != nil {
				return
			}
		}
		_, _ = w.Write([]byte(" {}"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// Every answer the SDK reads, from the API, the CometBFT RPC, or an indexer,
// is refused past 64 MiB, with an error that says so.
func TestAnswersOverTheCapAreRefused(t *testing.T) {
	ctx := context.Background()
	srv := oversizedServer(t)
	client, err := NewClient(srv.URL, WithRPCURL(srv.URL), WithIndexerURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	apiOnly, err := NewClient(srv.URL) // lists indexers rather than naming one
	if err != nil {
		t.Fatal(err)
	}
	query := &GraphQLRequest{Query: "{ items { id } }"}
	chain := consensus.NewClient(consensus.ClientConfig{RPCURL: srv.URL, APIURL: srv.URL, Timeout: time.Minute})
	light, err := lightclient.NewLightClient(lightclient.Config{ChainID: "willow", ValidatorEndpoints: []string{srv.URL}, RPCTimeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	for name, call := range map[string]func() error{
		"an API answer": func() error { _, err := client.Registration.GetSubgrove(ctx, "sg"); return err },
		"a /tx/submit answer": func() error {
			_, err := client.Files.Upload("sg", "f", "f.txt", []byte("x"), srv.URL, nil)
			return err
		},
		"an events_commitment anchor": func() error { _, err := client.FetchEventsCommitment(ctx, "sg", 1); return err },
		"matched logs":                func() error { _, err := client.FetchMatchedLogs(ctx, "sg", 1); return err },
		"a file manifest":             func() error { _, err := client.Files.Metadata("sg", "f"); return err },
		"a file list":                 func() error { _, err := client.Files.List("sg"); return err },
		"the indexer list":            func() error { _, err := apiOnly.Indexers.List(ctx); return err },
		"an indexer's GraphQL answer": func() error { _, err := client.Indexing.QueryUnverified(ctx, "sg", query); return err },
		"a routed answer from the API": func() error {
			_, err := client.Indexing.GraphQLQueryWithSource(ctx, "sg", query, QuerySourceValidator)
			return err
		},
		"a routed answer from an indexer": func() error {
			_, err := client.Indexing.GraphQLQueryWithSource(ctx, "sg", query, QuerySourceIndexer)
			return err
		},
		"a SQL answer":             func() error { _, err := client.Indexing.SqlQuery(ctx, "sg", "SELECT 1", false); return err },
		"an account's nonce state": func() error { _, err := client.queryAccountNonceState(ctx, "did:willow:z1"); return err },
		"an Ethereum state answer": func() error {
			_, err := NewEthOperations(srv.URL, nil).GetState(ctx, "0x"+strings.Repeat("11", 20), nil, 1)
			return err
		},
		"the consensus client's /tx/submit answer": func() error {
			_, err := chain.BroadcastTxSync(ctx, map[string]interface{}{"RegisterSubgrove": map[string]interface{}{}})
			return err
		},
		"a CometBFT RPC answer":       func() error { _, err := chain.GetStatus(ctx); return err },
		"a light client's RPC answer": func() error { return light.InitializeWithTrustOnFirstUse(ctx) },
		"an ERC-8004 answer":          func() error { _, err := erc8004.NewClient(srv.URL).ListAgents(0, 0); return err },
	} {
		if err := call(); err == nil || !strings.Contains(err.Error(), "64 MiB") {
			t.Errorf("%s: %v; want a refusal past 64 MiB", name, err)
		}
	}
}
