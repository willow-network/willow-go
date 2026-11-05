package willow

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/willow-network/willow-go/internal/httpbody"
)

// The SDK decodes at most 2 Mi units of JSON from one answer, each string,
// number, true, false, or null costing one and each array or object eight.
const (
	testValueLimit    = 1 << 21
	testContainerCost = 8
)

// arraysOf returns a JSON array of n empty arrays: 8(n+1) units.
func arraysOf(n int) []byte {
	var b bytes.Buffer
	b.Grow(3*n + 2)
	b.WriteByte('[')
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString("[]")
	}
	b.WriteByte(']')
	return b.Bytes()
}

// Every answer the SDK reads, from the API, the CometBFT RPC, or an indexer,
// is refused before it is decoded when it holds more JSON than the SDK
// decodes; one at the limit is decoded (and may then fail for its shape).
func TestAnswersPastTheValueLimitAreRefused(t *testing.T) {
	srv := newPaddedServer(t)
	over := arraysOf(testValueLimit / testContainerCost) // one array past the limit
	at := arraysOf(testValueLimit/testContainerCost - 1)
	for _, route := range answerRoutes(t, srv.URL) {
		srv.body.Store(&over)
		if err := route.call(); !errors.Is(err, ErrAnswerTooLarge) || !strings.Contains(err.Error(), "than the SDK decodes") {
			t.Errorf("%s, past the value limit: %v; want a refusal, ErrAnswerTooLarge", route.name, err)
		}
		srv.body.Store(&at)
		if err := route.call(); err != nil && strings.Contains(err.Error(), "than the SDK decodes") {
			t.Errorf("%s, at the value limit: %v; want it decoded", route.name, err)
		}
	}
}

// A SQL answer of empty objects, which Go decodes into maps at tens of times
// its length, is refused before it is decoded: reading and refusing a 4 MiB
// one allocates a small multiple of its length, not the ~200 MiB decoding it
// takes.
func TestASQLBombIsRefusedBeforeItIsDecoded(t *testing.T) {
	var b bytes.Buffer
	b.WriteString(`{"columns":[],"rows":[[`)
	for b.Len() < 4<<20 {
		b.WriteString(`{},`)
	}
	b.WriteString(`{}]]}`)
	body := b.Bytes()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	client, err := NewClient("http://127.0.0.1:1", WithIndexerURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	res, err := client.Indexing.SqlQueryWithSource(context.Background(), "sg", "SELECT 1", false, QuerySourceIndexer)
	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc
	t.Logf("a %d-byte answer: allocated %.1f MiB (%.1f times its length)",
		len(body), float64(allocated)/(1<<20), float64(allocated)/float64(len(body)))
	if err == nil || !strings.Contains(err.Error(), "than the SDK decodes") {
		cells := 0
		if res != nil && res.Result != nil && len(res.Result.Rows) > 0 {
			cells = len(res.Result.Rows[0])
		}
		t.Errorf("a SQL answer of %d empty objects: %v; want a refusal", cells, err)
	}
	if bound := uint64(12 * len(body)); allocated > bound {
		t.Errorf("refusing a %d-byte answer allocated %d bytes, over %d", len(body), allocated, bound)
	}
}

// indexerSQLAnswer is a SQL answer of rows rows as an indexer serves it: one
// proof per row, whose bytes are JSON number arrays the SDK doesn't keep.
func indexerSQLAnswer(rows, proofBytes int) []byte {
	numbers := strings.TrimSuffix(strings.Repeat("7,", proofBytes), ",")
	var b bytes.Buffer
	b.WriteString(`{"columns":["id","pool","amount"],"rows":[`)
	for i := 0; i < rows; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `["id-%d","0xabc",%d]`, i, i)
	}
	b.WriteString(`],"proof":{"merkle_proofs":[`)
	for i := 0; i < rows; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"key":"id-%d","merkle_proof":[%s],"value_hash":[1,2,3]}`, i, numbers)
	}
	b.WriteString(`],"state_root":[1,2,3],"block_height":9}}`)
	return b.Bytes()
}

// An indexer attaches a proof to every row whatever the request asks; those
// bytes are JSON numbers the SDK decodes into bytes or skips, so they don't
// count against what it decodes. The rows themselves still do.
func TestAnIndexersSQLAnswerWithItsPerRowProofsIsRead(t *testing.T) {
	body := indexerSQLAnswer(5000, 2000)
	if len(body) >= httpbody.Large {
		t.Fatalf("the answer is %d bytes, past the route's cap", len(body))
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	client, err := NewClient("http://127.0.0.1:1", WithIndexerURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	res, err := client.Indexing.SqlQuery(context.Background(), "sg", "SELECT 1", false)
	if err != nil {
		t.Fatalf("%d bytes, 5000 rows: %v", len(body), err)
	}
	if len(res.Rows) != 5000 || res.Proof == nil || len(res.Proof.MerkleProofs) != 5000 {
		t.Fatalf("read %d rows and %+v", len(res.Rows), res.Proof != nil)
	}
	routed, err := client.Indexing.SqlQueryWithSource(context.Background(), "sg", "SELECT 1", false, QuerySourceIndexer)
	if err != nil || routed.Result == nil || len(routed.Result.Rows) != 5000 {
		t.Fatalf("routed: %v", err)
	}
}

// Numbers count everywhere but under the answer's own top-level proof: rows
// are decoded into interface{}, where a number takes tens of bytes.
func TestNumbersInRowsAndNestedProofsStillCount(t *testing.T) {
	numbers := strings.TrimSuffix(strings.Repeat("0,", httpbody.MaxValues+1), ",")
	for name, body := range map[string]string{
		"rows":        `{"columns":[],"rows":[[` + numbers + `]]}`,
		"nested key":  `{"columns":[],"rows":[[{"proof":[` + numbers + `]}]]}`,
		"after proof": `{"proof":{"block_height":9},"rows":[[` + numbers + `]]}`,
	} {
		if err := httpbody.CheckJSONWithProof([]byte(body)); !errors.Is(err, ErrAnswerTooLarge) {
			t.Errorf("%s: %v; want it refused", name, err)
		}
	}
	if err := httpbody.CheckJSONWithProof([]byte(`{"proof":[` + numbers + `]}`)); err != nil {
		t.Errorf("a proof's numbers: %v", err)
	}
	var containers strings.Builder
	containers.WriteString(`{"proof":{"merkle_proofs":[`)
	for i := 0; i <= httpbody.MaxValues/httpbody.ContainerCost; i++ {
		containers.WriteString(`{},`)
	}
	containers.WriteString(`{}]}}`)
	if err := httpbody.CheckJSONWithProof([]byte(containers.String())); !errors.Is(err, ErrAnswerTooLarge) {
		t.Errorf("a proof's containers: %v; want them to count", err)
	}
}

// Under Auto a size refusal is the answer: the API serves no indexed rows, so
// falling back would report none, with no error.
func TestAutoReturnsAnIndexersSizeRefusalRatherThanFallingBack(t *testing.T) {
	var b bytes.Buffer
	b.WriteString(`{"columns":[],"rows":[[`)
	for i := 0; i <= httpbody.MaxValues/httpbody.ContainerCost; i++ {
		b.WriteString(`{},`)
	}
	b.WriteString(`{}]]}`)
	body := b.Bytes()
	indexer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer indexer.Close()
	fellBack := false
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/indexers") {
			fmt.Fprintf(w, `{"success":true,"data":[{"indexer_did":"did:willow:i","query_endpoint":%q,"status":"active","subgroves":["sg"]}]}`, indexer.URL)
			return
		}
		fellBack = true
		_, _ = w.Write([]byte(`{"columns":[],"rows":[],"total":0}`))
	}))
	defer api.Close()
	client, err := NewClient(api.URL)
	if err != nil {
		t.Fatal(err)
	}
	res, err := client.Indexing.SqlQueryWithSource(context.Background(), "sg", "SELECT 1", false, QuerySourceAuto)
	if !errors.Is(err, ErrAnswerTooLarge) {
		t.Errorf("Auto: %+v, %v; want ErrAnswerTooLarge", res, err)
	}
	if fellBack {
		t.Error("Auto fell back to the API")
	}
}

// An Ethereum answer decodes into typed fields, so its proofs' bytes, JSON
// numbers, count for nothing; a call that touches many slots is limited by
// the route's byte cap.
func TestAnEthereumAnswerOfManyProofBytesIsRead(t *testing.T) {
	numbers := strings.TrimSuffix(strings.Repeat("7,", httpbody.MaxValues+1), ",")
	body := []byte(`{"answer":"AA","state_root":[` + numbers + `],"block_range":[9,9],"state_proofs":[]}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	eth := NewEthOperations(srv.URL, nil)
	env, err := eth.post(context.Background(), "/x", map[string]string{})
	if err != nil {
		t.Fatalf("%d bytes: %v", len(body), err)
	}
	if len(env.StateRoot) != httpbody.MaxValues+1 {
		t.Fatalf("state root of %d", len(env.StateRoot))
	}
}
