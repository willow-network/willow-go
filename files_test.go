package willow

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// fileServer serves manifest from the API's /files route and chunk(i) from
// the storage node's /chunk route, counting the chunks asked for. It drops
// the connection of every chunk asked for past the 64th, so a download that
// asks for too many ends.
func fileServer(t *testing.T, manifest FileManifest, chunk func(i int) []byte) (*Client, string, *int64) {
	t.Helper()
	var asked int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/files/sg/f":
			_ = json.NewEncoder(w).Encode(manifest)
		case strings.HasPrefix(r.URL.Path, "/chunk/sg/f/"):
			if atomic.AddInt64(&asked, 1) > 64 {
				panic(http.ErrAbortHandler)
			}
			var i int
			if err := json.Unmarshal([]byte(strings.TrimPrefix(r.URL.Path, "/chunk/sg/f/")), &i); err != nil {
				t.Error(err)
			}
			_, _ = w.Write(chunk(i))
		default:
			t.Errorf("asked for %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	client, err := NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return client, srv.URL, &asked
}

// fileManifest is the manifest of data split into chunks of chunkSize bytes.
func fileManifest(data []byte, chunkSize int) FileManifest {
	chunks := chunkData(data, chunkSize)
	hashes := make([][32]byte, len(chunks))
	for i, c := range chunks {
		hashes[i] = sha256.Sum256(c)
	}
	content := sha256.Sum256(data)
	root := computeMerkleRoot(hashes)
	return FileManifest{
		FileKey:         "f",
		TotalSize:       uint64(len(data)),
		ContentHash:     hex.EncodeToString(content[:]),
		ChunkCount:      uint32(len(chunks)),
		ChunkSize:       uint32(chunkSize),
		ChunkMerkleRoot: hex.EncodeToString(root[:]),
	}
}

// Download reads the chunks the manifest's sizes make up, and no more: a
// manifest the chain would refuse (no data, over 1 GiB, more than 262,144
// chunks, or a chunk count its total and chunk sizes don't make) is refused
// before any chunk is asked for, and a chunk longer than the manifest makes
// it is refused.
func TestDownloadReadsTheChunksTheManifestMakes(t *testing.T) {
	data := []byte(strings.Repeat("willow", 2000)) // 12,000 bytes: 3 chunks of 4,096
	honest := fileManifest(data, 4096)
	chunks := chunkData(data, 4096)
	client, node, asked := fileServer(t, honest, func(i int) []byte { return chunks[i] })
	got, err := client.Files.Download("sg", "f", node)
	if err != nil || string(got) != string(data) || *asked != 3 {
		t.Fatalf("an honest file: %d bytes, %v, %d chunks asked for", len(got), err, *asked)
	}

	shape := func(count, size uint32, total uint64) FileManifest {
		m := honest
		m.ChunkCount, m.ChunkSize, m.TotalSize = count, size, total
		return m
	}
	for name, m := range map[string]FileManifest{
		"1,000 chunks of a 10-byte file":  shape(1000, 262144, 10),
		"3 chunks of a 1-chunk file":      shape(3, 262144, 12000),
		"1 chunk of a 3-chunk file":       shape(1, 4096, 12000),
		"no chunks":                       shape(0, 4096, 0),
		"no data":                         shape(1, 4096, 0),
		"a chunk size of 0":               shape(3, 0, 12000),
		"2 GiB":                           shape(8192, 262144, 2<<30),
		"300,000 chunks of 1 byte":        shape(300000, 1, 300000),
		"4,294,967,295 chunks of 1 byte":  shape(1<<32-1, 1, 1<<32-1),
		"4,294,967,295 chunks of 4 GiB-1": shape(1<<32-1, 1<<32-1, (1<<32-1)*(1<<32-1)),
	} {
		client, node, asked := fileServer(t, m, func(i int) []byte { return chunks[i%3] })
		if _, err := client.Files.Download("sg", "f", node); err == nil || *asked != 0 {
			t.Errorf("%s: %v, %d chunks asked for; want a refusal before any", name, err, *asked)
		}
	}

	// A chunk longer than the manifest makes it is refused, read no further.
	client, node, _ = fileServer(t, honest, func(i int) []byte { return []byte(strings.Repeat("x", 1<<20)) })
	if _, err := client.Files.Download("sg", "f", node); err == nil || !strings.Contains(err.Error(), "longer than") {
		t.Errorf("a 1 MiB chunk of 4,096 bytes: %v", err)
	}
}
