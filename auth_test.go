package willow

import (
	"strings"
	"testing"
)

func TestNewIdentityEd25519(t *testing.T) {
	identity, err := NewIdentity(Ed25519)
	if err != nil {
		t.Fatalf("Failed to create Ed25519 identity: %v", err)
	}

	// Check DID format
	did := identity.DID()
	if !strings.HasPrefix(did, "did:willow:Ed25519:") {
		t.Errorf("Expected DID to start with 'did:willow:Ed25519:', got %s", did)
	}

	// Check key lengths
	if len(identity.KeyPair.PrivateKey) != 64 {
		t.Errorf("Expected private key length 64, got %d", len(identity.KeyPair.PrivateKey))
	}
	if len(identity.KeyPair.PublicKey) != 32 {
		t.Errorf("Expected public key length 32, got %d", len(identity.KeyPair.PublicKey))
	}

	// Check public key ID
	if identity.PublicKeyID() == "" {
		t.Error("Public key ID should not be empty")
	}

	// Check DID document
	if identity.DidDocument.ID != did {
		t.Errorf("DID document ID mismatch: expected %s, got %s", did, identity.DidDocument.ID)
	}
	if len(identity.DidDocument.PublicKeys) != 1 {
		t.Errorf("Expected 1 public key, got %d", len(identity.DidDocument.PublicKeys))
	}
	if identity.DidDocument.PublicKeys[0].Type != "Ed25519VerificationKey2018" {
		t.Errorf("Expected key type Ed25519VerificationKey2018, got %s", identity.DidDocument.PublicKeys[0].Type)
	}
}

func TestNewIdentitySecp256k1(t *testing.T) {
	identity, err := NewIdentity(Secp256k1)
	if err != nil {
		t.Fatalf("Failed to create Secp256k1 identity: %v", err)
	}

	// Check DID format
	did := identity.DID()
	if !strings.HasPrefix(did, "did:willow:secp256k1:") {
		t.Errorf("Expected DID to start with 'did:willow:secp256k1:', got %s", did)
	}

	// Check key lengths
	if len(identity.KeyPair.PrivateKey) != 32 {
		t.Errorf("Expected private key length 32, got %d", len(identity.KeyPair.PrivateKey))
	}
	if len(identity.KeyPair.PublicKey) != 33 { // Compressed public key
		t.Errorf("Expected public key length 33, got %d", len(identity.KeyPair.PublicKey))
	}

	// Check DID document
	if identity.DidDocument.PublicKeys[0].Type != "EcdsaSecp256k1VerificationKey2019" {
		t.Errorf("Expected key type EcdsaSecp256k1VerificationKey2019, got %s", identity.DidDocument.PublicKeys[0].Type)
	}
}

func TestIdentityUniqueness(t *testing.T) {
	identity1, err := NewIdentity(Ed25519)
	if err != nil {
		t.Fatalf("Failed to create identity 1: %v", err)
	}

	identity2, err := NewIdentity(Ed25519)
	if err != nil {
		t.Fatalf("Failed to create identity 2: %v", err)
	}

	if identity1.DID() == identity2.DID() {
		t.Error("Generated DIDs should be unique")
	}

	if string(identity1.KeyPair.PrivateKey) == string(identity2.KeyPair.PrivateKey) {
		t.Error("Generated private keys should be unique")
	}

	if string(identity1.KeyPair.PublicKey) == string(identity2.KeyPair.PublicKey) {
		t.Error("Generated public keys should be unique")
	}
}

func TestIdentityFromPrivateKey(t *testing.T) {
	// Create original identity
	original, err := NewIdentity(Ed25519)
	if err != nil {
		t.Fatalf("Failed to create original identity: %v", err)
	}

	// Restore from private key
	restored, err := IdentityFromPrivateKey(Ed25519, original.KeyPair.PrivateKeyHex())
	if err != nil {
		t.Fatalf("Failed to restore identity: %v", err)
	}

	// Check DIDs match
	if original.DID() != restored.DID() {
		t.Errorf("Restored DID mismatch: expected %s, got %s", original.DID(), restored.DID())
	}

	// Check public keys match
	if original.KeyPair.PublicKeyHex() != restored.KeyPair.PublicKeyHex() {
		t.Error("Restored public key does not match original")
	}
}

func TestSignAndVerifyEd25519(t *testing.T) {
	identity, err := NewIdentity(Ed25519)
	if err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}

	message := []byte("test message")

	// Sign the message
	signature, err := identity.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// Verify the signature
	valid, err := Verify(Ed25519, identity.KeyPair.PublicKey, message, signature)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}
	if !valid {
		t.Error("Valid signature should verify")
	}

	// Verify with wrong message
	valid, err = Verify(Ed25519, identity.KeyPair.PublicKey, []byte("wrong message"), signature)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}
	if valid {
		t.Error("Signature with wrong message should not verify")
	}
}

func TestSignAndVerifySecp256k1(t *testing.T) {
	identity, err := NewIdentity(Secp256k1)
	if err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}

	message := []byte("test message")

	// Sign the message
	signature, err := identity.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// Verify the signature
	valid, err := Verify(Secp256k1, identity.KeyPair.PublicKey, message, signature)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}
	if !valid {
		t.Error("Valid signature should verify")
	}
}

func TestEd25519SignatureDeterministic(t *testing.T) {
	identity, err := NewIdentity(Ed25519)
	if err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}

	message := []byte("test message")

	sig1, err := identity.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	sig2, err := identity.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	if string(sig1) != string(sig2) {
		t.Error("Ed25519 signatures should be deterministic")
	}
}

func TestSignatureAlgorithmKeyType(t *testing.T) {
	tests := []struct {
		algo     SignatureAlgorithm
		expected string
	}{
		{Ed25519, "Ed25519VerificationKey2018"},
		{Secp256k1, "EcdsaSecp256k1VerificationKey2019"},
		{SignatureAlgorithm("unknown"), ""},
	}

	for _, tt := range tests {
		result := tt.algo.KeyType()
		if result != tt.expected {
			t.Errorf("KeyType(%s) = %s, expected %s", tt.algo, result, tt.expected)
		}
	}
}

func TestFullAuthFlow(t *testing.T) {
	// Simulate full authentication flow
	identity, err := NewIdentity(Ed25519)
	if err != nil {
		t.Fatalf("Failed to create identity: %v", err)
	}

	// Create challenge message (as server would)
	challenge := &AuthenticationChallenge{
		Challenge: "challenge_1234567890",
		Nonce:     "nonce123",
		ExpiresAt: 1234567890,
	}

	// Sign the challenge
	signature, err := SignAuthenticationChallenge(challenge, identity.DID(), identity.KeyPair)
	if err != nil {
		t.Fatalf("Failed to sign challenge: %v", err)
	}

	if signature == "" {
		t.Error("Signature should not be empty")
	}
}

func TestKeyPairMethods(t *testing.T) {
	keyPair, err := GenerateKeyPair(Ed25519)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	pubHex := keyPair.PublicKeyHex()
	if len(pubHex) != 64 { // 32 bytes = 64 hex chars
		t.Errorf("Expected public key hex length 64, got %d", len(pubHex))
	}

	privHex := keyPair.PrivateKeyHex()
	if len(privHex) != 128 { // 64 bytes = 128 hex chars
		t.Errorf("Expected private key hex length 128, got %d", len(privHex))
	}
}

func TestGenerateDID(t *testing.T) {
	keyPair, err := GenerateKeyPair(Ed25519)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	did := GenerateDID(keyPair)
	if !strings.HasPrefix(did, "did:willow:Ed25519:") {
		t.Errorf("Expected DID to start with 'did:willow:Ed25519:', got %s", did)
	}
}

func TestCreateDidDocument(t *testing.T) {
	keyPair, err := GenerateKeyPair(Ed25519)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	doc := CreateDidDocument(keyPair)

	if doc.ID == "" {
		t.Error("DID document ID should not be empty")
	}
	if len(doc.PublicKeys) != 1 {
		t.Errorf("Expected 1 public key, got %d", len(doc.PublicKeys))
	}
	if doc.Created == 0 {
		t.Error("Created timestamp should not be zero")
	}
	if doc.Updated == 0 {
		t.Error("Updated timestamp should not be zero")
	}
}
