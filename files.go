package willow

import (
	"bytes"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

const DefaultChunkSize = 262144 // 256 KB

// FileSigningOptions provides transaction signing for file operations.
// When provided, the transaction will include a DID-authenticated signature.
type FileSigningOptions struct {
	OwnerDID    string
	PublicKeyID string
	SignFunc    func(message []byte) (string, error) // returns hex-encoded signature
	Nonce       uint64
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

// Upload uploads a file to a FileStorage subgrove.
// If signing is non-nil, the transaction will be signed with the provided credentials.
func (f *FileOperations) Upload(subgroveID, fileKey, filename string, data []byte, storageNodeEndpoint string, signing *FileSigningOptions) (*FileManifest, error) {
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

	ownerDID := ""
	signature := ""
	publicKeyID := ""
	var nonce uint64

	if signing != nil {
		ownerDID = signing.OwnerDID
		publicKeyID = signing.PublicKeyID
		nonce = signing.Nonce

		message := fmt.Sprintf("store_file:%s:%s:%s:%d",
			subgroveID, fileKey, contentHashHex, len(data))
		sig, err := signing.SignFunc([]byte(message))
		if err != nil {
			return nil, fmt.Errorf("failed to sign store file tx: %w", err)
		}
		signature = sig
	}

	// Submit StoreFileManifestTx to consensus
	manifestTx := map[string]interface{}{
		"StoreFileManifest": map[string]interface{}{
			"subgrove_id":       subgroveID,
			"file_key":          fileKey,
			"filename":          filename,
			"content_type":      guessContentType(filename),
			"total_size":        len(data),
			"content_hash":      contentHashHex,
			"chunk_count":       chunkCount,
			"chunk_size":        chunkSize,
			"chunk_merkle_root": hex.EncodeToString(merkleRoot[:]),
			"owner_did":         ownerDID,
			"signature":         signature,
			"public_key_id":     publicKeyID,
			"nonce":             nonce,
		},
	}
	txBody, err := json.Marshal(manifestTx)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal manifest tx: %w", err)
	}
	txResp, err := http.Post(
		f.client.baseURL.String()+"/broadcast_tx",
		"application/json",
		bytes.NewReader(txBody),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to broadcast manifest tx: %w", err)
	}
	txResp.Body.Close()
	if txResp.StatusCode >= 400 {
		return nil, fmt.Errorf("manifest tx rejected: HTTP %d", txResp.StatusCode)
	}

	// Upload chunks to storage node
	for i, chunk := range chunks {
		url := fmt.Sprintf("%s/upload/%s/%s?chunk_index=%d&chunk_count=%d&content_hash=%s",
			storageNodeEndpoint, subgroveID, fileKey, i, chunkCount, contentHashHex)
		resp, err := http.Post(url, "application/octet-stream", bytes.NewReader(chunk))
		if err != nil {
			return nil, fmt.Errorf("failed to upload chunk %d: %w", i, err)
		}
		resp.Body.Close()
	}

	return &FileManifest{
		FileKey:        fileKey,
		Filename:       filename,
		ContentType:    guessContentType(filename),
		TotalSize:      uint64(len(data)),
		ContentHash:    contentHashHex,
		ChunkCount:     uint32(chunkCount),
		ChunkSize:      uint32(chunkSize),
		ChunkMerkleRoot: hex.EncodeToString(merkleRoot[:]),
		StorageNodes:   []string{storageNodeEndpoint},
	}, nil
}

// Download downloads a file from a FileStorage subgrove.
func (f *FileOperations) Download(subgroveID, fileKey, storageNodeEndpoint string) ([]byte, error) {
	manifest, err := f.Metadata(subgroveID, fileKey)
	if err != nil {
		return nil, err
	}

	var fileData []byte
	var chunkHashes [][32]byte
	for i := uint32(0); i < manifest.ChunkCount; i++ {
		url := fmt.Sprintf("%s/chunk/%s/%s/%d?content_hash=%s",
			storageNodeEndpoint, subgroveID, fileKey, i, manifest.ContentHash)
		resp, err := http.Get(url)
		if err != nil {
			return nil, fmt.Errorf("failed to download chunk %d: %w", i, err)
		}
		chunk, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to read chunk %d: %w", i, err)
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

// Metadata gets file manifest metadata from the validator API.
func (f *FileOperations) Metadata(subgroveID, fileKey string) (*FileManifest, error) {
	url := fmt.Sprintf("%s/files/%s/%s", f.client.baseURL.String(), subgroveID, fileKey)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("file not found: %s", fileKey)
	}

	var manifest FileManifest
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		return nil, err
	}
	return &manifest, nil
}

// List lists all files in a subgrove.
func (f *FileOperations) List(subgroveID string) ([]FileManifest, error) {
	url := fmt.Sprintf("%s/files/%s", f.client.baseURL.String(), subgroveID)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result FileListResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result.Files, nil
}

// Delete deletes a file (submits DeleteFileManifestTx to consensus).
// If signing is non-nil, the transaction will be signed with the provided credentials.
func (f *FileOperations) Delete(subgroveID, fileKey string, signing *FileSigningOptions) error {
	ownerDID := ""
	signature := ""
	publicKeyID := ""
	var nonce uint64

	if signing != nil {
		ownerDID = signing.OwnerDID
		publicKeyID = signing.PublicKeyID
		nonce = signing.Nonce

		message := fmt.Sprintf("delete_file:%s:%s",
			subgroveID, fileKey)
		sig, err := signing.SignFunc([]byte(message))
		if err != nil {
			return fmt.Errorf("failed to sign delete file tx: %w", err)
		}
		signature = sig
	}

	deleteTx := map[string]interface{}{
		"DeleteFileManifest": map[string]interface{}{
			"subgrove_id":   subgroveID,
			"file_key":      fileKey,
			"owner_did":     ownerDID,
			"signature":     signature,
			"public_key_id": publicKeyID,
			"nonce":         nonce,
		},
	}
	txBody, err := json.Marshal(deleteTx)
	if err != nil {
		return fmt.Errorf("failed to marshal delete tx: %w", err)
	}
	resp, err := http.Post(
		f.client.baseURL.String()+"/broadcast_tx",
		"application/json",
		bytes.NewReader(txBody),
	)
	if err != nil {
		return fmt.Errorf("failed to broadcast delete tx: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("delete tx rejected: HTTP %d", resp.StatusCode)
	}
	return nil
}

// UnregisterStorageNode submits an UnregisterStorageNode transaction to consensus.
// The signing options are required for this transaction.
func (f *FileOperations) UnregisterStorageNode(nodeDID string, signing *FileSigningOptions) error {
	if signing == nil {
		return fmt.Errorf("signing options are required to unregister a storage node")
	}

	message := fmt.Sprintf("unregister_storage_node:%s", nodeDID)
	sig, err := signing.SignFunc([]byte(message))
	if err != nil {
		return fmt.Errorf("failed to sign unregister storage node tx: %w", err)
	}

	tx := map[string]interface{}{
		"UnregisterStorageNode": map[string]interface{}{
			"node_did":      nodeDID,
			"signature":     sig,
			"public_key_id": signing.PublicKeyID,
			"nonce":         signing.Nonce,
		},
	}
	txBody, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("failed to marshal unregister storage node tx: %w", err)
	}
	resp, err := http.Post(
		f.client.baseURL.String()+"/broadcast_tx",
		"application/json",
		bytes.NewReader(txBody),
	)
	if err != nil {
		return fmt.Errorf("failed to broadcast unregister storage node tx: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("unregister storage node tx rejected: HTTP %d", resp.StatusCode)
	}
	return nil
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
