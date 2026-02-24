package willow

import "time"

// DevnetTestAccount contains the pre-funded test account credentials
// for local devnet development.
//
// This account is pre-registered and funded in the devnet genesis.
// Use it for SDK testing and development - DO NOT use in production!
//
// Example usage:
//
//	client, _ := willow.NewClient("http://localhost:3031")
//	identity, _ := willow.DEVNET_TEST_ACCOUNT.ToIdentity()
//	client.SetIdentity(identity)
type DevnetTestAccount struct {
	// DID is the decentralized identifier for the test account.
	DID string
	// PrivateKey is the hex-encoded private key - DO NOT USE IN PRODUCTION.
	PrivateKey string
	// PublicKey is the hex-encoded public key.
	PublicKey string
	// PublicKeyID is the key identifier used for authentication.
	PublicKeyID string
}

// DEVNET_TEST_ACCOUNT is the pre-funded test account for local devnet development.
// This account has 10,000 WILL tokens pre-allocated in the genesis.
//
// WARNING: Do not use this account in production!
var DEVNET_TEST_ACCOUNT = DevnetTestAccount{
	DID:         "did:willow:devnet-test",
	PrivateKey:  "b5ecc03536f5e039e3c5bc46ad178d7faf80cee5f063016a4f4084e163409b3c",
	PublicKey:   "c153874d3d284a11e3cb12b524e1a9cc32fef966d56b903c79688a95d5193c8f",
	PublicKeyID: "did:willow:devnet-test#key-1",
}

// ToIdentity converts the test account to an Identity that can be used
// for authentication.
//
// This creates an Identity with the pre-registered devnet-test DID,
// not a newly generated DID from the key.
func (d DevnetTestAccount) ToIdentity() (*Identity, error) {
	// Create key pair from private key
	keyPair, err := KeyPairFromPrivateKey(Ed25519, d.PrivateKey)
	if err != nil {
		return nil, err
	}

	// Create DID document with the pre-registered DID (not generated from key)
	now := time.Now().Unix()
	didDocument := &DidDocument{
		ID: d.DID,
		PublicKeys: []PublicKey{
			{
				ID:           d.PublicKeyID,
				Type:         Ed25519.KeyType(),
				PublicKeyHex: d.PublicKey,
			},
		},
		Created: now,
		Updated: now,
	}

	return &Identity{
		KeyPair:     keyPair,
		DidDocument: didDocument,
	}, nil
}
