package willow

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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
// digits, '-', or '_' starting with a letter or digit; admins, writers, or
// free readers that aren't DIDs ("did:willow:" then ASCII letters, digits,
// '-', or '_', at most 128 bytes); a schema that doesn't parse as the chain's
// schema definition (see SchemaDefinition.ChainSchemaJSON) or declares
// indexes; and, in a private DataStorage registration, an initial owner key
// grant that isn't key epoch 0 to the owner.
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
	if err := checkStorageRegistration(tx); err != nil {
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

// validateWillowDID applies the chain's rule for a DID it stores in a
// permission or a key grant: "did:willow:" then one or more ASCII letters,
// digits, '-', or '_', at most 128 bytes in all. label names the field.
func validateWillowDID(did, label string) error {
	body, ok := strings.CutPrefix(did, "did:willow:")
	if !ok {
		return NewValidationError(fmt.Sprintf("%s %q must start with \"did:willow:\"", label, did))
	}
	if len(did) > 128 {
		return NewValidationError(fmt.Sprintf("%s %q is %d bytes, more than 128", label, did, len(did)))
	}
	if body == "" {
		return NewValidationError(fmt.Sprintf("%s %q has nothing after \"did:willow:\"", label, did))
	}
	for i := 0; i < len(body); i++ {
		c := body[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return NewValidationError(fmt.Sprintf("%s %q may hold only ASCII letters, digits, '-', and '_' after \"did:willow:\"", label, did))
		}
	}
	return nil
}

// checkStorageRegistration refuses, before signing, what the chain refuses
// in a DataStorage or FileStorage registration: an id outside its rule;
// admins, writers, or free readers that aren't DIDs; a schema that doesn't
// parse as its schema definition or declares indexes; and, in a private
// DataStorage registration, an initial owner key grant that isn't key epoch 0
// to the owner.
func checkStorageRegistration(tx *consensus.RegisterSubgroveTx) error {
	if err := validateStorageSubgroveID(tx.SubgroveID); err != nil {
		return err
	}
	for _, admin := range tx.Admins {
		if err := validateWillowDID(admin, "admin"); err != nil {
			return err
		}
	}
	var writers, freeReaders []string
	dataStorage := tx.Mode == nil || tx.Mode.DataStorage != nil
	switch {
	case tx.Mode == nil:
	case tx.Mode.DataStorage != nil:
		writers, freeReaders = tx.Mode.DataStorage.Writers, tx.Mode.DataStorage.FreeReaders
	case tx.Mode.FileStorage != nil:
		writers, freeReaders = tx.Mode.FileStorage.Writers, tx.Mode.FileStorage.FreeReaders
	}
	for _, writer := range writers {
		if err := validateWillowDID(writer, "writer"); err != nil {
			return err
		}
	}
	for _, reader := range freeReaders {
		if err := validateWillowDID(reader, "free reader"); err != nil {
			return err
		}
	}
	if err := checkChainSchema(tx.Schema); err != nil {
		return err
	}
	if grant := tx.InitialOwnerKeyGrant; dataStorage && tx.Privacy != nil && grant != nil {
		if grant.KeyEpoch != 0 {
			return NewValidationError(fmt.Sprintf("a private subgrove's initial owner key grant must be key epoch 0, not %d", grant.KeyEpoch))
		}
		if grant.GranteeDID != tx.OwnerDid {
			return NewValidationError(fmt.Sprintf("a private subgrove's initial owner key grant must grant the owner %q, not %q", tx.OwnerDid, grant.GranteeDID))
		}
		if err := validateWillowDID(grant.GranteeDID, "initial owner key grant grantee"); err != nil {
			return err
		}
	}
	return nil
}

// chainFieldTypes are the field types of the chain's schema definition.
var chainFieldTypes = map[string]bool{"string": true, "number": true, "boolean": true, "array": true, "object": true, "bytes": true}

// checkChainSchema refuses a schema (the transaction's schema JSON text) the
// chain refuses in a DataStorage or FileStorage registration: one that doesn't
// parse as its SchemaDefinition, a JSON object whose keys are each optional
// and whose unknown keys are ignored,
//
//	{"version": <u32>, "fields": {"<name>": "string" | "number" | "boolean" | "array" | "object" | "bytes", …},
//	 "indexes": [], "required_fields": ["<name>", …]}
//
// (a known key given twice or as null is refused), and one that declares
// indexes, which the chain doesn't support.
func checkChainSchema(schema string) error {
	invalid := func(format string, args ...interface{}) error {
		return NewValidationError("the schema doesn't parse as the chain's schema definition, which the chain refuses: " + fmt.Sprintf(format, args...))
	}
	entries, err := jsonObjectEntries([]byte(schema))
	if err != nil {
		return invalid("%v", err)
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		switch entry.key {
		case "version", "fields", "indexes", "required_fields":
		default:
			continue
		}
		if seen[entry.key] {
			return invalid("%q appears twice", entry.key)
		}
		seen[entry.key] = true
		value := entry.value
		switch entry.key {
		case "version":
			if _, err := strconv.ParseUint(string(value), 10, 32); err != nil {
				return invalid("version %s isn't an unsigned 32-bit integer", value)
			}
		case "fields":
			fields, err := jsonObjectEntries(value)
			if err != nil {
				return invalid("fields: %v", err)
			}
			for _, field := range fields {
				var fieldType string
				if !bytes.HasPrefix(field.value, []byte(`"`)) || json.Unmarshal(field.value, &fieldType) != nil || !chainFieldTypes[fieldType] {
					return invalid("field %q has type %s; the chain's types are string, number, boolean, array, object, and bytes", field.key, field.value)
				}
			}
		case "indexes":
			var indexes []json.RawMessage
			if !bytes.HasPrefix(value, []byte("[")) || json.Unmarshal(value, &indexes) != nil {
				return invalid("indexes %s isn't a list", value)
			}
			if len(indexes) > 0 {
				return NewValidationError("the chain doesn't support schema indexes, so a registration whose schema declares them is refused")
			}
		case "required_fields":
			var names []json.RawMessage
			if !bytes.HasPrefix(value, []byte("[")) || json.Unmarshal(value, &names) != nil {
				return invalid("required_fields %s isn't a list", value)
			}
			for _, name := range names {
				if !bytes.HasPrefix(name, []byte(`"`)) {
					return invalid("required field %s isn't a string", name)
				}
			}
		}
	}
	return nil
}

// jsonEntry is one member of a JSON object: its key and its value's JSON text.
type jsonEntry struct {
	key   string
	value []byte
}

// jsonObjectEntries reads data as one JSON object (with nothing after it but
// whitespace) and returns its members in order, a key given twice included.
func jsonObjectEntries(data []byte) ([]jsonEntry, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, fmt.Errorf("%s isn't a JSON object", data)
	}
	var entries []jsonEntry
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := tok.(string)
		if !ok {
			return nil, fmt.Errorf("%s isn't a JSON object", data)
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		entries = append(entries, jsonEntry{key: key, value: bytes.TrimSpace(value)})
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%s holds more than one JSON value", data)
	}
	return entries, nil
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
//
// It refuses a grant whose grantee isn't a DID ("did:willow:" then ASCII
// letters, digits, '-', or '_', at most 128 bytes), which the chain refuses.
func FormatGrantSubgroveKeyMessage(subgroveID, senderDID string, grant EncryptedKeyGrant, nonce uint64) (string, error) {
	if err := validateGrantees([]EncryptedKeyGrant{grant}); err != nil {
		return "", err
	}
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
//
// It refuses a rotation with a grant whose grantee isn't a DID, which the
// chain refuses.
func FormatRotateSubgroveKeyMessage(subgroveID, senderDID string, newEpoch uint32, grants []EncryptedKeyGrant, nonce uint64) (string, error) {
	if err := validateGrantees(grants); err != nil {
		return "", err
	}
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

// validateGrantees refuses grants whose grantee isn't a DID, which the chain
// refuses.
func validateGrantees(grants []EncryptedKeyGrant) error {
	for i, g := range grants {
		label := "grantee"
		if len(grants) > 1 {
			label = fmt.Sprintf("grant %d's grantee", i)
		}
		if err := validateWillowDID(g.GranteeDID, label); err != nil {
			return err
		}
	}
	return nil
}

// revokeSubgroveKeyMessage returns the message a RevokeSubgroveKey
// transaction is signed over, "RevokeSubgroveKey:<subgroveID>:<revokeeDID>:
// <senderDID>:<nonce>". It refuses what the chain refuses: a subgrove id
// holding ':', or a revokee or sender that isn't a DID.
func revokeSubgroveKeyMessage(subgroveID, revokeeDID, senderDID string, nonce uint64) (string, error) {
	if err := validateRevoke(subgroveID, revokeeDID, senderDID); err != nil {
		return "", err
	}
	return fmt.Sprintf("RevokeSubgroveKey:%s:%s:%s:%d", subgroveID, revokeeDID, senderDID, nonce), nil
}

// validateRevoke applies the chain's rules for a RevokeSubgroveKey: a subgrove
// id that is set and holds no ':', and a revokee and sender that are DIDs.
func validateRevoke(subgroveID, revokeeDID, senderDID string) error {
	if subgroveID == "" {
		return NewValidationError("RevokeSubgroveKey needs a subgrove id")
	}
	if strings.Contains(subgroveID, ":") {
		return NewValidationError(fmt.Sprintf("subgrove id %q holds ':', which a RevokeSubgroveKey's can't", subgroveID))
	}
	if err := validateWillowDID(revokeeDID, "revokee"); err != nil {
		return err
	}
	return validateWillowDID(senderDID, "sender")
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
