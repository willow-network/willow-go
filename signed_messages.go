package willow

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/willow-network/willow-go/consensus"
)

// The messages data and file writes, subgrove registrations, key grants and
// rotations, and storage-node removals are signed over. Each is a set of lines
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

// FormatRegisterSubgroveMessage returns the message a RegisterSubgrove
// transaction is signed over:
//
//	RegisterSubgrove
//	Subgrove: <SubgroveID>
//	Owner: <OwnerDid>
//	Config: <hex SHA-256 of the transaction's bincode with an empty signature>
//	Nonce: <Nonce>
//
// Config binds every field of the transaction: it hashes
// consensus.RegisterSubgroveUnsignedBincode of the JSON tx marshals to, which
// is the JSON sent. Build the message from the transaction as it will be sent
// (every field but the signature set, the nonce included), then set Signature.
//
// It refuses a BlockchainIndexing registration: consensus.SubgroveBlockchainIndexing
// doesn't encode the chain's indexing mode, so this SDK signs DataStorage and
// FileStorage registrations only. A nil Mode is the chain's default
// DataStorage. It also refuses what the chain refuses in a DataStorage or
// FileStorage registration: a subgrove id that isn't 1 to 64 ASCII letters,
// digits, '-', or '_' starting with a letter or digit, and a schema that
// declares indexes.
func FormatRegisterSubgroveMessage(tx *consensus.RegisterSubgroveTx) (string, error) {
	if tx == nil {
		return "", NewValidationError("no RegisterSubgrove transaction")
	}
	if tx.Mode != nil {
		modes := 0
		for _, set := range []bool{tx.Mode.DataStorage != nil, tx.Mode.FileStorage != nil, tx.Mode.BlockchainIndexing != nil} {
			if set {
				modes++
			}
		}
		if modes != 1 {
			return "", NewValidationError("RegisterSubgrove needs exactly one mode: DataStorage, FileStorage, or BlockchainIndexing")
		}
		if tx.Mode.BlockchainIndexing != nil {
			return "", NewValidationError("this SDK can't encode a BlockchainIndexing registration, so it won't sign one; it signs DataStorage and FileStorage registrations")
		}
	}
	if err := validateStorageSubgroveID(tx.SubgroveID); err != nil {
		return "", err
	}
	if err := refuseSchemaIndexes(tx.Schema); err != nil {
		return "", err
	}
	body, err := json.Marshal(tx)
	if err != nil {
		return "", NewSerializationError("failed to encode the RegisterSubgrove transaction", err)
	}
	unsigned, err := consensus.RegisterSubgroveUnsignedBincode(body)
	if err != nil {
		return "", NewValidationError(err.Error())
	}
	config := sha256.Sum256(unsigned)
	return newSignedMessage("RegisterSubgrove").
		text("Subgrove", tx.SubgroveID).
		text("Owner", tx.OwnerDid).
		line("Config", hex.EncodeToString(config[:])).
		line("Nonce", strconv.FormatUint(tx.Nonce, 10)).
		build()
}

// validateStorageSubgroveID applies the chain's rule for the id of a
// DataStorage or FileStorage subgrove: 1 to 64 ASCII letters, digits, '-', or
// '_', starting with a letter or digit.
func validateStorageSubgroveID(id string) error {
	if id == "" || len(id) > 64 {
		return NewValidationError(fmt.Sprintf("subgrove id %q must be 1 to 64 characters", id))
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if i == 0 && !alnum {
			return NewValidationError(fmt.Sprintf("subgrove id %q must start with an ASCII letter or digit", id))
		}
		if !alnum && c != '-' && c != '_' {
			return NewValidationError(fmt.Sprintf("subgrove id %q may hold only ASCII letters, digits, '-', and '_'", id))
		}
	}
	return nil
}

// refuseSchemaIndexes refuses a schema (the transaction's schema JSON text)
// that declares indexes, which the chain refuses in a DataStorage or
// FileStorage registration. A schema that doesn't parse is left to the
// encoder and the chain.
func refuseSchemaIndexes(schema string) error {
	var parsed struct {
		Indexes []json.RawMessage `json:"indexes"`
	}
	if json.Unmarshal([]byte(schema), &parsed) == nil && len(parsed.Indexes) > 0 {
		return NewValidationError("the chain doesn't support schema indexes, so a registration whose schema declares them is refused")
	}
	return nil
}

// FormatGrantSubgroveKeyMessage returns the message a GrantSubgroveKey
// transaction is signed over:
//
//	GrantSubgroveKey
//	Subgrove: <subgroveID>
//	Sender: <senderDID>
//	Grantee: <grant.GranteeDID>
//	GranteeKey: <grant.GranteePublicKeyID>
//	KeyEpoch: <grant.KeyEpoch>
//	EphemeralKey: <hex grant.EphemeralPublicKey>
//	EncryptedKey: <hex grant.EncryptedKey>
//	GrantedBy: <grant.GrantedBy>
//	GrantedAt: <grant.GrantedAt>
//	Nonce: <nonce>
func FormatGrantSubgroveKeyMessage(subgroveID, senderDID string, grant EncryptedKeyGrant, nonce uint64) (string, error) {
	return newSignedMessage("GrantSubgroveKey").
		text("Subgrove", subgroveID).
		text("Sender", senderDID).
		grant(grant).
		line("Nonce", strconv.FormatUint(nonce, 10)).
		build()
}

// FormatRotateSubgroveKeyMessage returns the message a RotateSubgroveKey
// transaction is signed over:
//
//	RotateSubgroveKey
//	Subgrove: <subgroveID>
//	Sender: <senderDID>
//	NewEpoch: <newEpoch>
//	Grants: <len(grants)>
//	<for each grant, in order, its seven lines Grantee … GrantedAt, as in
//	FormatGrantSubgroveKeyMessage>
//	Nonce: <nonce>
func FormatRotateSubgroveKeyMessage(subgroveID, senderDID string, newEpoch uint32, grants []EncryptedKeyGrant, nonce uint64) (string, error) {
	m := newSignedMessage("RotateSubgroveKey").
		text("Subgrove", subgroveID).
		text("Sender", senderDID).
		line("NewEpoch", strconv.FormatUint(uint64(newEpoch), 10)).
		line("Grants", strconv.Itoa(len(grants)))
	for _, g := range grants {
		m.grant(g)
	}
	return m.line("Nonce", strconv.FormatUint(nonce, 10)).build()
}

// FormatUnregisterStorageNodeMessage returns the message an
// UnregisterStorageNode transaction is signed over:
//
//	UnregisterStorageNode
//	Node: <nodeDID>
//	Nonce: <nonce>
func FormatUnregisterStorageNodeMessage(nodeDID string, nonce uint64) (string, error) {
	return newSignedMessage("UnregisterStorageNode").
		text("Node", nodeDID).
		line("Nonce", strconv.FormatUint(nonce, 10)).
		build()
}

// grant adds a key grant's seven lines.
func (m *signedMessage) grant(g EncryptedKeyGrant) *signedMessage {
	return m.text("Grantee", g.GranteeDID).
		text("GranteeKey", g.GranteePublicKeyID).
		line("KeyEpoch", strconv.FormatUint(uint64(g.KeyEpoch), 10)).
		line("EphemeralKey", hex.EncodeToString(g.EphemeralPublicKey)).
		line("EncryptedKey", hex.EncodeToString(g.EncryptedKey)).
		text("GrantedBy", g.GrantedBy).
		line("GrantedAt", strconv.FormatUint(g.GrantedAt, 10))
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
// 0x0A, which is also the second byte of "\r\n") or isn't valid UTF-8 (the
// transaction's JSON would carry U+FFFD in its place, so the chain would
// rebuild another message).
func (m *signedMessage) text(label, value string) *signedMessage {
	if m.err == nil && strings.ContainsRune(value, '\n') {
		m.err = NewValidationError(label + " holds a line break, which a signed field can't")
	}
	if m.err == nil && !utf8.ValidString(value) {
		m.err = NewValidationError(label + " is not valid UTF-8")
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
