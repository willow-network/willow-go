package willow

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/willow-network/willow-go/consensus"
	"github.com/willow-network/willow-go/erc8004"
	"github.com/willow-network/willow-go/lightclient"
)

// paddedServer answers every request with status 200 and "{}" after pad bytes
// of leading space: JSON, of pad+3 bytes. With body set, it answers body
// instead.
type paddedServer struct {
	*httptest.Server
	pad  atomic.Int64
	body atomic.Pointer[[]byte]
}

func newPaddedServer(t *testing.T) *paddedServer {
	t.Helper()
	s := &paddedServer{}
	piece := bytes.Repeat([]byte{' '}, 1<<20)
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		if body := s.body.Load(); body != nil {
			_, _ = w.Write(*body)
			return
		}
		for left := s.pad.Load(); left > 0; {
			n := min(left, int64(len(piece)))
			if _, err := w.Write(piece[:n]); err != nil {
				return
			}
			left -= n
		}
		_, _ = w.Write([]byte(" {}"))
	}))
	t.Cleanup(s.Close)
	return s
}

// Every answer the SDK reads, from the API, the CometBFT RPC, or an indexer,
// is read up to its route's cap and refused one byte past it, with an error
// that names the cap: 4 MiB for an answer the node keeps small, 12 MiB for
// one that carries what one transaction holds, 32 MiB for a block, and 64 MiB
// for an answer whose size the request sets (a query page, GraphQL, SQL,
// matched logs, Ethereum state).
func TestAnswersAreReadUpToTheirRoutesCap(t *testing.T) {
	srv := newPaddedServer(t)
	for _, route := range answerRoutes(t, srv.URL) {
		limit := fmt.Sprintf("%d MiB", route.mib)
		srv.pad.Store(route.mib<<20 + 1)
		if err := route.call(); !errors.Is(err, ErrAnswerTooLarge) || !strings.Contains(err.Error(), limit+" limit") {
			t.Errorf("%s, one byte over %s: %v; want a refusal past %s, ErrAnswerTooLarge", route.name, limit, err, limit)
		}
		srv.pad.Store(route.mib<<20 - 3)
		if err := route.call(); err != nil && strings.Contains(err.Error(), "MiB limit") {
			t.Errorf("%s, %s exactly: %v; want it read", route.name, limit, err)
		}
	}
}

// answerRoute is one route whose answer the SDK reads: its name, its cap in
// MiB, and a call that reads it.
type answerRoute struct {
	name string
	mib  int64
	call func() error
}

// answerRoutes returns every route whose answer the SDK reads, each sent to
// url as the API, the CometBFT RPC, an indexer, and a storage node.
func answerRoutes(t *testing.T, url string) []answerRoute {
	t.Helper()
	ctx := context.Background()
	srv := struct{ URL string }{url}
	client, err := NewClient(srv.URL, WithRPCURL(srv.URL), WithIndexerURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	client.SetIdentity(vectorIdentity(t, Ed25519))
	apiOnly, err := NewClient(srv.URL) // lists indexers rather than naming one
	if err != nil {
		t.Fatal(err)
	}
	apiOnly.SetIdentity(vectorIdentity(t, Ed25519))
	query := &GraphQLRequest{Query: "{ items { id } }"}
	chain := consensus.NewClient(consensus.ClientConfig{RPCURL: srv.URL, APIURL: srv.URL, Timeout: time.Minute})
	light, err := lightclient.NewLightClient(lightclient.Config{ChainID: "willow", ValidatorEndpoints: []string{srv.URL}, RPCTimeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	signing := fileSigning(vectorIdentity(t, Ed25519), 1)
	return []answerRoute{
		{"an API answer", 4, func() error { _, err := client.Registration.GetSubgrove(ctx, "sg"); return err }},
		{"a balance", 4, func() error { _, err := client.Token.GetBalance(ctx, "did:willow:z1"); return err }},
		{"the health check", 4, func() error { _, err := client.Health(ctx); return err }},
		{"a /tx/submit answer", 4, func() error {
			_, err := client.Files.Upload("sg", "f", "f.txt", []byte("x"), srv.URL, signing)
			return err
		}},
		{"an events_commitment anchor", 4, func() error { _, err := client.FetchEventsCommitment(ctx, "sg", 1); return err }},
		{"an account's nonce state", 4, func() error { _, err := client.queryAccountNonceState(ctx, "did:willow:z1"); return err }},
		{"a file manifest", 4, func() error { _, err := client.Files.Metadata("sg", "f"); return err }},
		{"a file list", 4, func() error { _, err := client.Files.List("sg"); return err }},
		{"the indexer list", 4, func() error { _, err := apiOnly.Indexers.List(ctx); return err }},
		{"the consensus client's /tx/submit answer", 4, func() error {
			_, err := chain.BroadcastTxSync(ctx, map[string]interface{}{"RegisterSubgrove": map[string]interface{}{}})
			return err
		}},
		{"a CometBFT status", 4, func() error { _, err := chain.GetStatus(ctx); return err }},
		{"a light client's RPC answer", 4, func() error { return light.InitializeWithTrustOnFirstUse(ctx) }},
		{"an ERC-8004 answer", 4, func() error { _, err := erc8004.NewClient(srv.URL).ListAgents(0, 0); return err }},
		{"a stored value", 12, func() error { _, err := client.Data.Get(ctx, "sg", "k"); return err }},
		{"a key's proof", 12, func() error { _, err := client.Data.GetProof(ctx, "sg", "k"); return err }},
		{"a CometBFT transaction", 12, func() error { _, err := chain.GetTx(ctx, strings.Repeat("ab", 32)); return err }},
		{"a CometBFT block", 32, func() error { _, err := chain.GetBlock(ctx, 1); return err }},
		{"a query page", 64, func() error { _, err := client.Data.QueryUnverified(ctx, "sg", nil); return err }},
		{"a historical query", 64, func() error {
			_, err := client.Data.QueryHistorical(ctx, "sg", "c", &HistoricalQueryRequest{})
			return err
		}},
		{"the API's GraphQL answer", 64, func() error { _, err := apiOnly.Indexing.QueryUnverified(ctx, "sg", query); return err }},
		{"an indexer's GraphQL answer", 64, func() error { _, err := client.Indexing.QueryUnverified(ctx, "sg", query); return err }},
		{"a routed answer from the API", 64, func() error {
			_, err := client.Indexing.GraphQLQueryWithSource(ctx, "sg", query, QuerySourceValidator)
			return err
		}},
		{"a routed answer from an indexer", 64, func() error {
			_, err := client.Indexing.GraphQLQueryWithSource(ctx, "sg", query, QuerySourceIndexer)
			return err
		}},
		{"a SQL answer", 64, func() error { _, err := client.Indexing.SqlQuery(ctx, "sg", "SELECT 1", false); return err }},
		{"matched logs", 64, func() error { _, err := client.FetchMatchedLogs(ctx, "sg", 1); return err }},
		{"an Ethereum state answer", 64, func() error {
			_, err := NewEthOperations(srv.URL, nil).GetState(ctx, "0x"+strings.Repeat("11", 20), nil, 1)
			return err
		}},
	}
}
