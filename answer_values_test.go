package willow

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
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
		if err := route.call(); err == nil || !strings.Contains(err.Error(), "than the SDK decodes") {
			t.Errorf("%s, past the value limit: %v; want a refusal", route.name, err)
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
