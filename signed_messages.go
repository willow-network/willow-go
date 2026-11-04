package willow

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

// The messages data and file writes are signed over. Each is a set of lines
// joined by "\n" (the byte 0x0A, no trailing newline), UTF-8: the kind first,
// then one "Label: value" line per field the transaction writes, the nonce
// last. Text fields go in verbatim. Numbers are unsigned decimal and bytes
// lowercase hex without 0x.
//
// The nonce is the nonce the transaction carries, so build the message after
// choosing it; a retry under another nonce needs a new signature. A write the
// chain refuses in its block after its signature and nonce verify still spends
// that nonce, so retry it signed under the next free nonce.
//
// A text field can't hold the byte 0x0A: the chain refuses such a
// transaction, and these builders return a validation error instead of a
// message.

// FormatDataStoreMessage returns the message a StoreData transaction is signed
// over:
//
//	StoreData
//	Subgrove: <subgroveID>
//	Key: <key>
//	Owner: <ownerDID>
//	DataHash: <hex SHA-256 of data>
//	Nonce: <nonce>
//
// data is the exact bytes the transaction carries in its data field (the JSON
// text as UTF-8).
func FormatDataStoreMessage(subgroveID, key, ownerDID string, data []byte, nonce uint64) (string, error) {
	digest := sha256.Sum256(data)
	return newSignedMessage("StoreData").
		text("Subgrove", subgroveID).
		text("Key", key).
		text("Owner", ownerDID).
		line("DataHash", hex.EncodeToString(digest[:])).
		line("Nonce", strconv.FormatUint(nonce, 10)).
		build()
}

// FileEncryption is a file manifest's encryption metadata: the subgrove key
// epoch and the 24-byte XChaCha20-Poly1305 nonce.
type FileEncryption struct {
	KeyEpoch uint64
	Nonce    [24]byte
}

// FileManifestFields are the fields a StoreFileManifest transaction writes,
// as it carries them.
type FileManifestFields struct {
	SubgroveID      string
	FileKey         string
	OwnerDID        string
	Filename        string
	ContentType     string
	TotalSize       uint64
	ContentHash     [32]byte
	ChunkCount      uint32
	ChunkSize       uint32
	ChunkMerkleRoot [32]byte
	// Encryption is nil for a transaction without encryption metadata.
	Encryption *FileEncryption
	Nonce      uint64
}

// FormatStoreFileManifestMessage returns the message a StoreFileManifest
// transaction is signed over:
//
//	StoreFileManifest
//	Subgrove: <SubgroveID>
//	Key: <FileKey>
//	Owner: <OwnerDID>
//	Filename: <Filename>
//	ContentType: <ContentType>
//	TotalSize: <TotalSize>
//	ContentHash: <hex ContentHash>
//	ChunkCount: <ChunkCount>
//	ChunkSize: <ChunkSize>
//	ChunkMerkleRoot: <hex ChunkMerkleRoot>
//	Encryption: none | <KeyEpoch>:<hex Nonce>
//	Nonce: <Nonce>
func FormatStoreFileManifestMessage(f FileManifestFields) (string, error) {
	encryption := "none"
	if f.Encryption != nil {
		encryption = strconv.FormatUint(f.Encryption.KeyEpoch, 10) + ":" + hex.EncodeToString(f.Encryption.Nonce[:])
	}
	return newSignedMessage("StoreFileManifest").
		text("Subgrove", f.SubgroveID).
		text("Key", f.FileKey).
		text("Owner", f.OwnerDID).
		text("Filename", f.Filename).
		text("ContentType", f.ContentType).
		line("TotalSize", strconv.FormatUint(f.TotalSize, 10)).
		line("ContentHash", hex.EncodeToString(f.ContentHash[:])).
		line("ChunkCount", strconv.FormatUint(uint64(f.ChunkCount), 10)).
		line("ChunkSize", strconv.FormatUint(uint64(f.ChunkSize), 10)).
		line("ChunkMerkleRoot", hex.EncodeToString(f.ChunkMerkleRoot[:])).
		line("Encryption", encryption).
		line("Nonce", strconv.FormatUint(f.Nonce, 10)).
		build()
}

// FormatDeleteFileManifestMessage returns the message a DeleteFileManifest
// transaction is signed over:
//
//	DeleteFileManifest
//	Subgrove: <subgroveID>
//	Key: <fileKey>
//	Owner: <ownerDID>
//	Nonce: <nonce>
func FormatDeleteFileManifestMessage(subgroveID, fileKey, ownerDID string, nonce uint64) (string, error) {
	return newSignedMessage("DeleteFileManifest").
		text("Subgrove", subgroveID).
		text("Key", fileKey).
		text("Owner", ownerDID).
		line("Nonce", strconv.FormatUint(nonce, 10)).
		build()
}

// signedMessage collects a message's lines and the first field refused.
type signedMessage struct {
	lines []string
	err   error
}

func newSignedMessage(kind string) *signedMessage {
	return &signedMessage{lines: []string{kind}}
}

// text adds a text field, refusing one that holds a line break (the byte
// 0x0A, which is also the second byte of "\r\n").
func (m *signedMessage) text(label, value string) *signedMessage {
	if m.err == nil && strings.ContainsRune(value, '\n') {
		m.err = NewValidationError(label + " holds a line break, which a signed field can't")
	}
	return m.line(label, value)
}

// line adds a field whose value can't hold a line break (a number or hex).
func (m *signedMessage) line(label, value string) *signedMessage {
	m.lines = append(m.lines, label+": "+value)
	return m
}

func (m *signedMessage) build() (string, error) {
	if m.err != nil {
		return "", m.err
	}
	return strings.Join(m.lines, "\n"), nil
}
