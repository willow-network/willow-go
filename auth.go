package willow

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"golang.org/x/crypto/sha3"
)

// KeyPair represents a cryptographic key pair.
type KeyPair struct {
	Algorithm  SignatureAlgorithm
	PublicKey  []byte
	PrivateKey []byte
}

// PublicKeyHex returns the hex-encoded public key.
func (kp *KeyPair) PublicKeyHex() string {
	return hex.EncodeToString(kp.PublicKey)
}

// PrivateKeyHex returns the hex-encoded private key.
func (kp *KeyPair) PrivateKeyHex() string {
	return hex.EncodeToString(kp.PrivateKey)
}

// GenerateKeyPair generates a new key pair for the specified algorithm.
func GenerateKeyPair(algorithm SignatureAlgorithm) (*KeyPair, error) {
	switch algorithm {
	case Ed25519:
		return generateEd25519KeyPair()
	case Secp256k1:
		return generateSecp256k1KeyPair()
	default:
		return nil, NewCryptoError(fmt.Sprintf("unsupported algorithm: %s", algorithm), nil)
	}
}

func generateEd25519KeyPair() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, NewCryptoError("failed to generate Ed25519 key pair", err)
	}
	return &KeyPair{
		Algorithm:  Ed25519,
		PublicKey:  pub,
		PrivateKey: priv,
	}, nil
}

func generateSecp256k1KeyPair() (*KeyPair, error) {
	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, NewCryptoError("failed to generate secp256k1 key pair", err)
	}
	pubKey := privKey.PubKey()
	return &KeyPair{
		Algorithm:  Secp256k1,
		PublicKey:  pubKey.SerializeCompressed(),
		PrivateKey: privKey.Serialize(),
	}, nil
}

// KeyPairFromPrivateKey creates a KeyPair from an existing private key.
func KeyPairFromPrivateKey(algorithm SignatureAlgorithm, privateKeyHex string) (*KeyPair, error) {
	privateKey, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, NewCryptoError("invalid private key hex", err)
	}

	switch algorithm {
	case Ed25519:
		return keyPairFromEd25519PrivateKey(privateKey)
	case Secp256k1:
		return keyPairFromSecp256k1PrivateKey(privateKey)
	default:
		return nil, NewCryptoError(fmt.Sprintf("unsupported algorithm: %s", algorithm), nil)
	}
}

func keyPairFromEd25519PrivateKey(privateKey []byte) (*KeyPair, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, NewCryptoError(fmt.Sprintf("invalid Ed25519 private key size: expected %d, got %d", ed25519.PrivateKeySize, len(privateKey)), nil)
	}
	priv := ed25519.PrivateKey(privateKey)
	pub := priv.Public().(ed25519.PublicKey)
	return &KeyPair{
		Algorithm:  Ed25519,
		PublicKey:  pub,
		PrivateKey: priv,
	}, nil
}

func keyPairFromSecp256k1PrivateKey(privateKey []byte) (*KeyPair, error) {
	privKey, _ := btcec.PrivKeyFromBytes(privateKey)
	if privKey == nil {
		return nil, NewCryptoError("invalid secp256k1 private key", nil)
	}
	pubKey := privKey.PubKey()
	return &KeyPair{
		Algorithm:  Secp256k1,
		PublicKey:  pubKey.SerializeCompressed(),
		PrivateKey: privKey.Serialize(),
	}, nil
}

// Sign signs a message with the key pair.
func (kp *KeyPair) Sign(message []byte) ([]byte, error) {
	switch kp.Algorithm {
	case Ed25519:
		return signEd25519(kp.PrivateKey, message)
	case Secp256k1:
		return signSecp256k1(kp.PrivateKey, message)
	default:
		return nil, NewCryptoError(fmt.Sprintf("unsupported algorithm: %s", kp.Algorithm), nil)
	}
}

func signEd25519(privateKey, message []byte) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, NewCryptoError("invalid Ed25519 private key size", nil)
	}
	signature := ed25519.Sign(privateKey, message)
	return signature, nil
}

func signSecp256k1(privateKey, message []byte) ([]byte, error) {
	privKey, _ := btcec.PrivKeyFromBytes(privateKey)
	if privKey == nil {
		return nil, NewCryptoError("invalid secp256k1 private key", nil)
	}

	// Hash the message with SHA256 for secp256k1 signing
	hash := sha256Hash(message)
	signature := ecdsa.Sign(privKey, hash)
	return signature.Serialize(), nil
}

// Verify verifies a signature against a message and public key.
func Verify(algorithm SignatureAlgorithm, publicKey, message, signature []byte) (bool, error) {
	switch algorithm {
	case Ed25519:
		return verifyEd25519(publicKey, message, signature)
	case Secp256k1:
		return verifySecp256k1(publicKey, message, signature)
	default:
		return false, NewCryptoError(fmt.Sprintf("unsupported algorithm: %s", algorithm), nil)
	}
}

func verifyEd25519(publicKey, message, signature []byte) (bool, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return false, NewCryptoError("invalid Ed25519 public key size", nil)
	}
	return ed25519.Verify(publicKey, message, signature), nil
}

func verifySecp256k1(publicKey, message, signature []byte) (bool, error) {
	pubKey, err := btcec.ParsePubKey(publicKey)
	if err != nil {
		return false, NewCryptoError("invalid secp256k1 public key", err)
	}

	sig, err := ecdsa.ParseSignature(signature)
	if err != nil {
		return false, NewCryptoError("invalid secp256k1 signature", err)
	}

	hash := sha256Hash(message)
	return sig.Verify(hash, pubKey), nil
}

// Multicodec prefixes for the public-key types embedded in a self-certifying
// Willow DID. See https://github.com/multiformats/multicodec (unsigned-varint
// encoded codes: ed25519-pub = 0xed, secp256k1-pub = 0xe7).
var (
	multicodecEd25519Pub   = []byte{0xED, 0x01} // ed25519-pub
	multicodecSecp256k1Pub = []byte{0xE7, 0x01} // secp256k1-pub
)

// GenerateDID derives a self-certifying Willow DID from a key pair.
//
// The identifier is bound to the public key, so it cannot be chosen:
//
//	did = "did:willow:z" + base58btc( SHA3-256( multicodec_prefix || public_key ) )
//
// where SHA3-256 is FIPS-202 (NOT Keccak-256), the multicodec prefix is
// 0xED01 for Ed25519 and 0xE701 for secp256k1 (hashed over the 33-byte
// compressed key), and the leading 'z' is the multibase base58btc marker.
//
// Because the id is derived from the key, the on-chain RegisterDid check
// accepts a registration only for the exact derived id. A freshly generated
// DID therefore has to be funded (someone transfers at least the registration
// fee to the derived id) BEFORE the holder registers it; see RegisterDID.
func GenerateDID(keyPair *KeyPair) string {
	prefix, pub := didKeyMaterial(keyPair)
	payload := make([]byte, 0, len(prefix)+len(pub))
	payload = append(payload, prefix...)
	payload = append(payload, pub...)
	digest := sha3.Sum256(payload)
	return "did:willow:z" + base58btcEncode(digest[:])
}

// didKeyMaterial returns the multicodec prefix and the public-key bytes used to
// derive a DID. For secp256k1 the key is normalized to its 33-byte compressed
// form so uncompressed keys derive the same id.
func didKeyMaterial(keyPair *KeyPair) ([]byte, []byte) {
	if keyPair.Algorithm == Secp256k1 {
		pub := keyPair.PublicKey
		if len(pub) != 33 {
			if parsed, err := btcec.ParsePubKey(pub); err == nil {
				pub = parsed.SerializeCompressed()
			}
		}
		return multicodecSecp256k1Pub, pub
	}
	// Ed25519 (and default): the 32-byte public key is used as-is.
	return multicodecEd25519Pub, keyPair.PublicKey
}

// base58btcEncode encodes bytes using the Bitcoin/base58btc alphabet, encoding
// each leading 0x00 byte as a leading '1'.
func base58btcEncode(input []byte) string {
	// Count leading zero bytes; each becomes a leading '1'.
	zeros := 0
	for zeros < len(input) && input[zeros] == 0 {
		zeros++
	}

	num := new(big.Int).SetBytes(input)
	base := big.NewInt(58)
	mod := new(big.Int)
	// Built least-significant-digit first, reversed below.
	encoded := make([]byte, 0, len(input)*138/100+1)
	for num.Sign() > 0 {
		num.DivMod(num, base, mod)
		encoded = append(encoded, base58Alphabet[mod.Int64()])
	}
	for i := 0; i < zeros; i++ {
		encoded = append(encoded, base58Alphabet[0])
	}
	for i, j := 0, len(encoded)-1; i < j; i, j = i+1, j-1 {
		encoded[i], encoded[j] = encoded[j], encoded[i]
	}
	return string(encoded)
}

// CreateDidDocument creates a DID document from a key pair.
func CreateDidDocument(keyPair *KeyPair) *DidDocument {
	did := GenerateDID(keyPair)
	now := time.Now().Unix()

	publicKey := PublicKey{
		ID:           fmt.Sprintf("%s#key-1", did),
		Type:         keyPair.Algorithm.KeyType(),
		PublicKeyHex: keyPair.PublicKeyHex(),
	}

	return &DidDocument{
		ID:         did,
		PublicKeys: []PublicKey{publicKey},
		Created:    now,
		Updated:    now,
	}
}

// Identity represents a complete identity with key pair and DID document.
type Identity struct {
	KeyPair     *KeyPair
	DidDocument *DidDocument
}

// NewIdentity creates a new identity with the specified algorithm.
func NewIdentity(algorithm SignatureAlgorithm) (*Identity, error) {
	keyPair, err := GenerateKeyPair(algorithm)
	if err != nil {
		return nil, err
	}

	didDocument := CreateDidDocument(keyPair)

	return &Identity{
		KeyPair:     keyPair,
		DidDocument: didDocument,
	}, nil
}

// IdentityFromPrivateKey creates an identity from an existing private key.
func IdentityFromPrivateKey(algorithm SignatureAlgorithm, privateKeyHex string) (*Identity, error) {
	keyPair, err := KeyPairFromPrivateKey(algorithm, privateKeyHex)
	if err != nil {
		return nil, err
	}

	didDocument := CreateDidDocument(keyPair)

	return &Identity{
		KeyPair:     keyPair,
		DidDocument: didDocument,
	}, nil
}

// DID returns the DID string for this identity.
func (i *Identity) DID() string {
	return i.DidDocument.ID
}

// PublicKeyID returns the public key ID for this identity.
func (i *Identity) PublicKeyID() string {
	if len(i.DidDocument.PublicKeys) > 0 {
		return i.DidDocument.PublicKeys[0].ID
	}
	return ""
}

// Sign signs a message with this identity.
func (i *Identity) Sign(message []byte) ([]byte, error) {
	return i.KeyPair.Sign(message)
}

// SignHex signs a message and returns the hex-encoded signature.
func (i *Identity) SignHex(message []byte) (string, error) {
	sig, err := i.Sign(message)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sig), nil
}

// SignRequest signs a request and returns the authentication headers.
// Message format: {METHOD}:{PATH}:{TIMESTAMP}
func (i *Identity) SignRequest(method, path string) (map[string]string, error) {
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	message := fmt.Sprintf("%s:%s:%s", method, path, timestamp)

	signature, err := i.SignHex([]byte(message))
	if err != nil {
		return nil, err
	}

	return map[string]string{
		"X-DID":           i.DID(),
		"X-Public-Key-ID": i.PublicKeyID(),
		"X-Signature":     signature,
		"X-Timestamp":     timestamp,
	}, nil
}

// FormatRegisterSubgroveMessage formats the message to sign for subgrove registration.
func FormatRegisterSubgroveMessage(req *RegisterSubgroveRequest, nonce uint64) string {
	return fmt.Sprintf("RegisterSubgrove\nSubgrove ID: %s\nName: %s\nOwner: %s\nNonce: %d",
		req.SubgroveID, req.Name, req.OwnerDid, nonce)
}

// FormatTransferMessage formats the message to sign for a transfer.
func FormatTransferMessage(req *TransferRequest, nonce uint64) string {
	return fmt.Sprintf("Transfer\nFrom: %s\nTo: %s\nAmount: %d\nMemo: %s\nNonce: %d",
		req.FromDid, req.ToDid, req.Amount, req.Memo, nonce)
}

// FormatDataStoreMessage formats the message to sign for data storage.
func FormatDataStoreMessage(subgroveID, key string, data []byte) string {
	return fmt.Sprintf("%s:%s:%s", subgroveID, key, string(data))
}
