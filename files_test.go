package willow

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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

// A chunk is read up to 2 MiB, the most the storage node's upload route
// takes, and refused past it, even when the manifest makes it longer.
func TestDownloadReadsAChunkUpTo2MiB(t *testing.T) {
	for _, size := range []int{2 << 20, 2<<20 + 1} {
		data := bytes.Repeat([]byte{'w'}, size)
		client, node, _ := fileServer(t, fileManifest(data, size), func(int) []byte { return data })
		got, err := client.Files.Download("sg", "f", node)
		switch {
		case size == 2<<20 && (err != nil || !bytes.Equal(got, data)):
			t.Errorf("a chunk of 2 MiB: %d bytes, %v", len(got), err)
		case size > 2<<20 && (err == nil || !strings.Contains(err.Error(), "2 MiB limit")):
			t.Errorf("a chunk of 2 MiB + 1: %d bytes, %v; want a refusal past 2 MiB", len(got), err)
		}
	}
}

// Upload and Delete refuse, sending nothing, without signing options that
// name an owner and a SignFunc: the chain refuses a manifest transaction with
// no owner or signature.
func TestFileWritesNeedSigning(t *testing.T) {
	var requests int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requests, 1)
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write([]byte(`{"success":true,"data":{"tx_hash":"AB","code":0,"log":""}}`))
	}))
	t.Cleanup(srv.Close)
	client, err := NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	id := vectorIdentity(t, Ed25519)
	noOwner, noSignFunc := fileSigning(id, 1), fileSigning(id, 1)
	noOwner.OwnerDID, noSignFunc.SignFunc = "", nil
	for name, signing := range map[string]*FileSigningOptions{"no signing": nil, "no owner": noOwner, "no SignFunc": noSignFunc} {
		for write, call := range map[string]func() error{
			"Upload": func() error {
				_, err := client.Files.Upload("sg", "f", "f.txt", []byte("x"), srv.URL, signing)
				return err
			},
			"Delete": func() error { return client.Files.Delete("sg", "f", signing) },
		} {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("%s, %s: panicked: %v", write, name, r)
					}
				}()
				if err := call(); !IsValidationError(err) {
					t.Errorf("%s, %s: %v; want a validation error", write, name, err)
				}
			}()
		}
	}
	if n := atomic.LoadInt64(&requests); n != 0 {
		t.Fatalf("sent %d requests without signing", n)
	}
}

// An upload whose manifest was accepted but whose chunk the storage node
// refuses, or never answers for, fails with a *ChunkUploadError naming the
// chunk and carrying the manifest's submission; the chunks after it aren't
// sent.
func TestUploadReportsAChunkTheStorageNodeRefuses(t *testing.T) {
	var uploads []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		switch {
		case r.URL.Path == "/tx/submit":
			_, _ = w.Write([]byte(`{"success":true,"data":{"tx_hash":"AB12","code":0,"log":""}}`))
		case strings.HasPrefix(r.URL.Path, "/upload/sg/f"):
			uploads = append(uploads, r.URL.Query().Get("chunk_index"))
			if r.URL.Query().Get("chunk_index") == "1" {
				w.WriteHeader(http.StatusInsufficientStorage)
				_, _ = w.Write([]byte(`{"error":"disk full"}`))
			}
		default:
			t.Errorf("asked for %s", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	client, err := NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	id := vectorIdentity(t, Ed25519)
	data := bytes.Repeat([]byte{'w'}, 3*DefaultChunkSize) // three chunks
	_, err = client.Files.Upload("sg", "f", "f.bin", data, srv.URL, fileSigning(id, 9))
	var chunkErr *ChunkUploadError
	if !errors.As(err, &chunkErr) || chunkErr.Chunk != 1 || chunkErr.Manifest == nil || chunkErr.Manifest.ChunkCount != 3 ||
		chunkErr.Submission == nil || chunkErr.Submission.TxHash != "AB12" || chunkErr.Submission.Nonce != 9 ||
		chunkErr.Submission.DID != id.DID() {
		t.Fatalf("a chunk refused with 507: %#v", err)
	}
	if status, ok := IsHTTPError(err); !ok || status != http.StatusInsufficientStorage || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("a chunk refused with 507: %v; want its status and message", err)
	}
	if fmt.Sprint(uploads) != "[0 1]" {
		t.Fatalf("chunks sent %v, want [0 1]", uploads)
	}

	// A storage node that can't be reached fails the first chunk.
	_, err = client.Files.Upload("sg", "f", "f.bin", data, "http://127.0.0.1:1", fileSigning(id, 10))
	if !errors.As(err, &chunkErr) || chunkErr.Chunk != 0 || chunkErr.Submission == nil || chunkErr.Submission.Nonce != 10 {
		t.Fatalf("an unreachable storage node: %#v", err)
	}
}

// Download and Upload talk to the storage node under the client's timeout
// (WithTimeout), not without one.
func TestStorageNodeRequestsTimeOut(t *testing.T) {
	data := []byte("willow")
	manifest := fileManifest(data, DefaultChunkSize)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/files/sg/f":
			_ = json.NewEncoder(w).Encode(manifest)
		case r.URL.Path == "/tx/submit":
			_, _ = w.Write([]byte(`{"success":true,"data":{"tx_hash":"AB","code":0,"log":""}}`))
		default: // the storage node's /chunk and /upload routes stall
			_, _ = io.Copy(io.Discard, r.Body)
			select {
			case <-r.Context().Done():
			case <-time.After(3 * time.Second):
				_, _ = w.Write(data)
			}
		}
	}))
	t.Cleanup(srv.Close)
	client, err := NewClient(srv.URL, WithTimeout(200*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	for name, call := range map[string]func() error{
		"Download": func() error { _, err := client.Files.Download("sg", "f", srv.URL); return err },
		"Upload": func() error {
			_, err := client.Files.Upload("sg", "f", "f.txt", data, srv.URL, fileSigning(vectorIdentity(t, Ed25519), 1))
			return err
		},
	} {
		start := time.Now()
		err := call()
		if took := time.Since(start); err == nil || took > 2*time.Second {
			t.Errorf("%s from a stalled storage node: %v after %v; want a timeout", name, err, took)
		}
	}
}
