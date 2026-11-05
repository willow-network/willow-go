package willow

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/willow-network/willow-go/consensus"
	"github.com/willow-network/willow-go/internal/httpbody"
	"golang.org/x/crypto/chacha20poly1305"
)

const DefaultChunkSize = 262144 // 256 KB

// FileSigningOptions provides transaction signing for file operations.
// When provided, the transaction will include a DID-authenticated signature.
type FileSigningOptions struct {
	OwnerDID    string
	PublicKeyID string
	SignFunc    func(message []byte) (string, error) // returns hex-encoded signature
	// Nonce is the transaction's nonce, which the signed message binds. Take
	// it with Client.NextNonce(ctx, OwnerDID), so that it is free in the
	// account's window and no other write from the client takes it while this
	// one is in flight.
	//
	// A write that fails to submit returns a *WriteError naming the nonce.
	// With MayLand set, its submission may have reached the node and may
	// still land: to send it again, sign it under the same Nonce, so that
	// whichever attempt lands first uses the nonce and the other is refused.
	// Signed under a fresh nonce instead, both attempts can run. Once the
	// nonce is used (the write landed, applied or refused in its block, or
	// its error wraps ErrNonceUsed), read what the write wrote before signing
	// it again under a fresh nonce.
	Nonce uint64
}

// FileManifest represents file metadata stored on-chain.
type FileManifest struct {
	FileKey        string   `json:"file_key"`
	Filename       string   `json:"filename"`
	ContentType    string   `json:"content_type"`
	TotalSize      uint64   `json:"total_size"`
	ContentHash    string   `json:"content_hash"`
	ChunkCount     uint32   `json:"chunk_count"`
	ChunkSize      uint32   `json:"chunk_size"`
	ChunkMerkleRoot string  `json:"chunk_merkle_root"`
	OwnerDID       string   `json:"owner_did"`
	CreatedAt      uint64   `json:"created_at"`
	UpdatedAt      uint64   `json:"updated_at"`
	Encrypted      bool     `json:"encrypted"`
	StorageNodes   []string `json:"storage_nodes"`
}

// FileListResponse is the response from listing files.
type FileListResponse struct {
	Files []FileManifest `json:"files"`
}

// FileOperations provides file storage operations.
type FileOperations struct {
	client *Client
}

// Upload uploads a file to a FileStorage subgrove: it sends the file's
// manifest as a StoreFileManifest transaction signed with signing, then its
// chunks to the storage node. signing must name the owner (OwnerDID) and
// carry a SignFunc: without them Upload sends nothing and returns a
// validation error, as the chain refuses a manifest with no owner or
// signature. A manifest that fails to submit returns a *WriteError (see
// FileSigningOptions.Nonce). Once the manifest's transaction is accepted, a
// chunk the storage node doesn't store (an answer other than 2xx, or a failed
// request) stops the upload with a *ChunkUploadError, which carries the
// manifest, its transaction, and the chunk.
func (f *FileOperations) Upload(subgroveID, fileKey, filename string, data []byte, storageNodeEndpoint string, signing *FileSigningOptions) (*FileManifest, error) {
	if err := checkFileSigning("Upload", signing); err != nil {
		return nil, err
	}
	chunkSize := DefaultChunkSize
	chunks := chunkData(data, chunkSize)
	chunkCount := len(chunks)

	contentHash := sha256.Sum256(data)
	contentHashHex := hex.EncodeToString(contentHash[:])

	chunkHashes := make([][32]byte, len(chunks))
	for i, chunk := range chunks {
		chunkHashes[i] = sha256.Sum256(chunk)
	}
	merkleRoot := computeMerkleRoot(chunkHashes)

	fields := FileManifestFields{
		SubgroveID:      subgroveID,
		FileKey:         fileKey,
		Filename:        filename,
		ContentType:     guessContentType(filename),
		TotalSize:       uint64(len(data)),
		ContentHash:     contentHash,
		ChunkCount:      uint32(chunkCount),
		ChunkSize:       uint32(chunkSize),
		ChunkMerkleRoot: merkleRoot,
	}
	fields.OwnerDID = signing.OwnerDID
	fields.Nonce = signing.Nonce
	publicKeyID := signing.PublicKeyID
	message, err := FormatStoreFileManifestMessage(fields)
	if err != nil {
		return nil, fmt.Errorf("failed to sign store file tx: %w", err)
	}
	sig, err := signing.SignFunc([]byte(message))
	if err != nil {
		return nil, fmt.Errorf("failed to sign store file tx: %w", err)
	}
	signatureBytes, err := decodeSignatureHex(sig)
	if err != nil {
		return nil, err
	}

	// Submit StoreFileManifestTx to consensus, carrying exactly the signed
	// fields.
	manifestTx := map[string]interface{}{
		"StoreFileManifest": map[string]interface{}{
			"subgrove_id":       fields.SubgroveID,
			"file_key":          fields.FileKey,
			"filename":          fields.Filename,
			"content_type":      fields.ContentType,
			"total_size":        fields.TotalSize,
			"content_hash":      consensus.ByteArray(fields.ContentHash[:]),
			"chunk_count":       fields.ChunkCount,
			"chunk_size":        fields.ChunkSize,
			"chunk_merkle_root": consensus.ByteArray(fields.ChunkMerkleRoot[:]),
			"owner_did":         fields.OwnerDID,
			"signature":         signatureBytes,
			"public_key_id":     publicKeyID,
			"nonce":             fields.Nonce,
		},
	}
	txBody, err := json.Marshal(manifestTx)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal manifest tx: %w", err)
	}
	txHash, err := f.client.submitSigned(context.Background(), fields.OwnerDID, fields.Nonce, txBody)
	if err != nil {
		return nil, fmt.Errorf("failed to broadcast manifest tx: %w", err)
	}
	manifest := &FileManifest{
		FileKey:         fileKey,
		Filename:        filename,
		ContentType:     guessContentType(filename),
		TotalSize:       uint64(len(data)),
		ContentHash:     contentHashHex,
		ChunkCount:      uint32(chunkCount),
		ChunkSize:       uint32(chunkSize),
		ChunkMerkleRoot: hex.EncodeToString(merkleRoot[:]),
		StorageNodes:    []string{storageNodeEndpoint},
	}

	// Upload chunks to storage node
	for i, chunk := range chunks {
		url := fmt.Sprintf("%s/upload/%s/%s?chunk_index=%d&chunk_count=%d&content_hash=%s",
			storageNodeEndpoint, subgroveID, fileKey, i, chunkCount, contentHashHex)
		if err := f.uploadChunk(url, chunk); err != nil {
			return nil, &ChunkUploadError{
				Manifest:   manifest,
				Submission: &WriteResult{DID: fields.OwnerDID, Nonce: fields.Nonce, TxHash: txHash},
				Chunk:      i,
				Err:        err,
			}
		}
	}
	return manifest, nil
}

// uploadChunk sends one chunk to the storage node's upload route, returning
// an *HTTPError for an answer other than 2xx.
func (f *FileOperations) uploadChunk(url string, chunk []byte) error {
	resp, err := f.storageClient().Post(url, "application/octet-stream", bytes.NewReader(chunk))
	if err != nil {
		return NewNetworkError("the chunk upload failed", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return NewHTTPError(resp.StatusCode, "the storage node refused the chunk: "+strings.TrimSpace(string(message)))
	}
	return nil
}

// ChunkUploadError is an Upload whose manifest transaction CheckTx accepted
// but whose chunk Chunk the storage node didn't store. The manifest is on
// chain once its transaction lands, which uses its nonce, but the storage
// node doesn't hold the file whole: chunk Chunk failed, and the chunks after
// it weren't sent.
type ChunkUploadError struct {
	// Manifest is the manifest Upload sent, as it returns it on success.
	Manifest *FileManifest
	// Submission is the manifest's transaction: its signer, nonce, and hash.
	Submission *WriteResult
	// Chunk is the index of the chunk the storage node didn't store.
	Chunk int
	// Err is why: the request's error, or an *HTTPError carrying the
	// storage node's status and message.
	Err error
}

// Error implements the error interface.
func (e *ChunkUploadError) Error() string {
	return fmt.Sprintf("the manifest of file %s was accepted (transaction %s, nonce %d of %s), but chunk %d of %d wasn't stored: %v",
		e.Manifest.FileKey, e.Submission.TxHash, e.Submission.Nonce, e.Submission.DID, e.Chunk, e.Manifest.ChunkCount, e.Err)
}

// Unwrap returns Err.
func (e *ChunkUploadError) Unwrap() error {
	return e.Err
}

// storageClient is the HTTP client Upload and Download talk to a storage node
// with: it has the client's timeout (WithTimeout), but not the client's
// transport, which with WithAPIKey sends the API key, meant for the API alone.
func (f *FileOperations) storageClient() *http.Client {
	return &http.Client{Timeout: f.client.httpClient.Timeout}
}

// The chain refuses a file manifest of more than maxFileSize bytes or
// maxChunkCount chunks.
const (
	maxFileSize   = 1 << 30
	maxChunkCount = maxFileSize / 4096
)

// checkFileShape refuses a manifest the chain would refuse for its sizes: no
// data, more than maxFileSize bytes or maxChunkCount chunks, or a ChunkCount
// that chunks of ChunkSize bytes, the last one partial, don't make TotalSize
// with.
func checkFileShape(m *FileManifest) error {
	count, size := uint64(m.ChunkCount), uint64(m.ChunkSize)
	switch {
	case m.TotalSize == 0 || m.TotalSize > maxFileSize:
		return fmt.Errorf("the manifest's file is %d bytes, not 1 to %d", m.TotalSize, maxFileSize)
	case count == 0 || count > maxChunkCount:
		return fmt.Errorf("the manifest's file is %d chunks, not 1 to %d", count, maxChunkCount)
	case m.TotalSize > count*size || m.TotalSize <= (count-1)*size:
		return fmt.Errorf("%d chunks of %d bytes don't make the manifest's %d-byte file", count, size, m.TotalSize)
	}
	return nil
}

// Download downloads a file from a FileStorage subgrove: the chunks its
// manifest (see Metadata) names, each the length the manifest makes it, which
// must hash to the manifest's chunk Merkle root and content hash. It refuses a
// manifest the chain would refuse for its sizes (no data, more than 1 GiB or
// 262,144 chunks, or a chunk count its total and chunk sizes don't make) before
// it asks for any chunk, and a chunk longer than 2 MiB, the most the storage
// node's upload route takes, as it reads it.
func (f *FileOperations) Download(subgroveID, fileKey, storageNodeEndpoint string) ([]byte, error) {
	manifest, err := f.Metadata(subgroveID, fileKey)
	if err != nil {
		return nil, err
	}
	if err := checkFileShape(manifest); err != nil {
		return nil, err
	}

	var fileData []byte
	var chunkHashes [][32]byte
	for i := uint32(0); i < manifest.ChunkCount; i++ {
		url := fmt.Sprintf("%s/chunk/%s/%s/%d?content_hash=%s",
			storageNodeEndpoint, subgroveID, fileKey, i, manifest.ContentHash)
		resp, err := f.storageClient().Get(url)
		if err != nil {
			return nil, fmt.Errorf("failed to download chunk %d: %w", i, err)
		}
		want := uint64(manifest.ChunkSize)
		if i == manifest.ChunkCount-1 {
			want = manifest.TotalSize - uint64(i)*want
		}
		chunk, err := httpbody.ReadAll(io.LimitReader(resp.Body, int64(want)+1), httpbody.Chunk)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to read chunk %d: %w", i, err)
		}
		if uint64(len(chunk)) > want {
			return nil, fmt.Errorf("chunk %d is longer than the %d bytes the manifest makes it", i, want)
		}
		chunkHashes = append(chunkHashes, sha256.Sum256(chunk))
		fileData = append(fileData, chunk...)
	}

	// Verify chunk Merkle root
	computedRoot := computeMerkleRoot(chunkHashes)
	if hex.EncodeToString(computedRoot[:]) != manifest.ChunkMerkleRoot {
		return nil, fmt.Errorf("chunk Merkle root mismatch")
	}

	// Verify content hash
	computedHash := sha256.Sum256(fileData)
	if hex.EncodeToString(computedHash[:]) != manifest.ContentHash {
		return nil, fmt.Errorf("content hash mismatch")
	}

	return fileData, nil
}

// Metadata gets file manifest metadata from the validator API, which answers
// with the manifest itself, not the success/data envelope.
func (f *FileOperations) Metadata(subgroveID, fileKey string) (*FileManifest, error) {
	req, err := f.client.newAPIRequest(context.Background(), http.MethodGet, fmt.Sprintf("/files/%s/%s", subgroveID, fileKey), nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.client.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("file not found: %s", fileKey)
	}

	var manifest FileManifest
	if err := httpbody.Decode(resp.Body, httpbody.Small, &manifest); err != nil {
		return nil, err
	}
	return &manifest, nil
}

// List lists all files in a subgrove.
func (f *FileOperations) List(subgroveID string) ([]FileManifest, error) {
	req, err := f.client.newAPIRequest(context.Background(), http.MethodGet, fmt.Sprintf("/files/%s", subgroveID), nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.client.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// The API answers {files, limit, start_after, has_more}, or {error} with
	// a failure status, without the success/data envelope.
	body, err := httpbody.ReadAll(resp.Body, httpbody.Small)
	if err != nil {
		return nil, NewNetworkError("failed to read /files response", err)
	}
	if resp.StatusCode >= 400 {
		return nil, f.client.handleErrorResponse(resp.StatusCode, body)
	}
	var result FileListResponse
	if err := httpbody.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return result.Files, nil
}

// Delete deletes a file: it sends a DeleteFileManifest transaction signed
// with signing, which must name the owner (OwnerDID) and carry a SignFunc;
// without them Delete sends nothing and returns a validation error. A
// transaction that fails to submit returns a *WriteError (see
// FileSigningOptions.Nonce).
func (f *FileOperations) Delete(subgroveID, fileKey string, signing *FileSigningOptions) error {
	if err := checkFileSigning("Delete", signing); err != nil {
		return err
	}
	ownerDID, publicKeyID, nonce := signing.OwnerDID, signing.PublicKeyID, signing.Nonce
	message, err := FormatDeleteFileManifestMessage(subgroveID, fileKey, ownerDID, nonce)
	if err != nil {
		return fmt.Errorf("failed to sign delete file tx: %w", err)
	}
	sig, err := signing.SignFunc([]byte(message))
	if err != nil {
		return fmt.Errorf("failed to sign delete file tx: %w", err)
	}
	signatureBytes, err := decodeSignatureHex(sig)
	if err != nil {
		return err
	}

	deleteTx := map[string]interface{}{
		"DeleteFileManifest": map[string]interface{}{
			"subgrove_id":   subgroveID,
			"file_key":      fileKey,
			"owner_did":     ownerDID,
			"signature":     signatureBytes,
			"public_key_id": publicKeyID,
			"nonce":         nonce,
		},
	}
	txBody, err := json.Marshal(deleteTx)
	if err != nil {
		return fmt.Errorf("failed to marshal delete tx: %w", err)
	}
	if _, err := f.client.submitSigned(context.Background(), ownerDID, nonce, txBody); err != nil {
		return fmt.Errorf("failed to broadcast delete tx: %w", err)
	}
	return nil
}

// UnregisterStorageNode submits an UnregisterStorageNode transaction to consensus.
// The signing options are required for this transaction: SignFunc signs as
// the node's DID, and Nonce is the transaction's nonce (take it with
// Client.NextNonce(ctx, nodeDID)). It is signed over
// FormatUnregisterStorageNodeMessage, which binds the node and the nonce.
// Without a node DID or a SignFunc it sends nothing and returns a validation
// error.
func (f *FileOperations) UnregisterStorageNode(nodeDID string, signing *FileSigningOptions) error {
	if nodeDID == "" || signing == nil || signing.SignFunc == nil {
		return NewValidationError("UnregisterStorageNode: a node DID and signing options with a SignFunc are required")
	}

	message, err := FormatUnregisterStorageNodeMessage(nodeDID, signing.Nonce)
	if err != nil {
		return fmt.Errorf("failed to sign unregister storage node tx: %w", err)
	}
	sig, err := signing.SignFunc([]byte(message))
	if err != nil {
		return fmt.Errorf("failed to sign unregister storage node tx: %w", err)
	}

	sigBytes, err := decodeSignatureHex(sig)
	if err != nil {
		return err
	}

	tx := map[string]interface{}{
		"UnregisterStorageNode": map[string]interface{}{
			"node_did":      nodeDID,
			"signature":     sigBytes,
			"public_key_id": signing.PublicKeyID,
			"nonce":         signing.Nonce,
		},
	}
	txBody, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("failed to marshal unregister storage node tx: %w", err)
	}
	if _, err := f.client.submitSigned(context.Background(), nodeDID, signing.Nonce, txBody); err != nil {
		return fmt.Errorf("failed to broadcast unregister storage node tx: %w", err)
	}
	return nil
}

// checkFileSigning refuses signing options a file write can't sign with: none,
// or ones without an owner DID or a SignFunc.
func checkFileSigning(op string, signing *FileSigningOptions) error {
	if signing == nil || signing.OwnerDID == "" || signing.SignFunc == nil {
		return NewValidationError(op + ": signing options with an OwnerDID and a SignFunc are required; " +
			"the chain refuses a file manifest transaction with no owner or signature")
	}
	return nil
}

// decodeSignatureHex reads a SignFunc result (hex, optionally 0x-prefixed): the
// chain's transactions carry signatures as bytes.
func decodeSignatureHex(sig string) (consensus.ByteArray, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(sig, "0x"))
	if err != nil {
		return nil, fmt.Errorf("signature is not hex: %w", err)
	}
	return b, nil
}

func chunkData(data []byte, chunkSize int) [][]byte {
	var chunks [][]byte
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, data[i:end])
	}
	return chunks
}

func computeMerkleRoot(hashes [][32]byte) [32]byte {
	if len(hashes) == 0 {
		return [32]byte{}
	}
	// No early return for single-leaf: pad to [leaf, leaf] and hash.
	// This prevents availability proof forgery for single-chunk files.

	current := make([][32]byte, len(hashes))
	copy(current, hashes)
	if len(current) == 1 {
		current = append(current, current[0])
	}

	for len(current) > 1 {
		if len(current)%2 != 0 {
			current = append(current, current[len(current)-1])
		}
		var next [][32]byte
		for i := 0; i < len(current); i += 2 {
			combined := append(current[i][:], current[i+1][:]...)
			next = append(next, sha256.Sum256(combined))
		}
		current = next
	}
	return current[0]
}

// EncryptFile encrypts file data using XChaCha20-Poly1305.
//
// Uses XChaCha20-Poly1305 with a 24-byte nonce to match the Rust SDK and
// consensus layer. Files encrypted with this function are interoperable
// across all Willow SDKs.
//
// Requires: golang.org/x/crypto/chacha20poly1305
func EncryptFile(data []byte, key [32]byte) (ciphertext []byte, nonce [24]byte, err error) {
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, [24]byte{}, fmt.Errorf("failed to create cipher: %w", err)
	}
	if _, err := io.ReadFull(cryptorand.Reader, nonce[:]); err != nil {
		return nil, [24]byte{}, fmt.Errorf("failed to generate nonce: %w", err)
	}
	ciphertext = aead.Seal(nil, nonce[:], data, nil)
	return ciphertext, nonce, nil
}

// DecryptFile decrypts file data using XChaCha20-Poly1305.
//
// Requires: golang.org/x/crypto/chacha20poly1305
func DecryptFile(ciphertext []byte, key [32]byte, nonce [24]byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	plaintext, err := aead.Open(nil, nonce[:], ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}
	return plaintext, nil
}

func guessContentType(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	types := map[string]string{
		".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
		".gif": "image/gif", ".pdf": "application/pdf", ".json": "application/json",
		".txt": "text/plain", ".html": "text/html", ".css": "text/css",
		".js": "application/javascript", ".wasm": "application/wasm",
		".zip": "application/zip", ".mp4": "video/mp4", ".mp3": "audio/mpeg",
	}
	if ct, ok := types[ext]; ok {
		return ct
	}
	return "application/octet-stream"
}
