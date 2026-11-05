// Registration example for the Willow Go SDK
//
// This example demonstrates:
// - Generating DIDs with different signature algorithms
// - Listing subgroves and reading one
// - Registering a subgrove: a signed RegisterSubgrove transaction
//
// It doesn't register a DID: a DID is registered on chain by a RegisterDid
// transaction, which this SDK doesn't build, so register and fund the
// owner's DID before it signs the subgrove's registration.
//
// Run with: go run ./examples/registration

package main

import (
	"context"
	"fmt"
	"log"

	willow "github.com/willow-network/willow-go"
)

func main() {
	fmt.Println("Willow SDK - Registration Example")
	fmt.Println("==================================")

	ctx := context.Background()

	client, err := willow.NewClient("http://localhost:3031")
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	// 1. Generate an Ed25519 DID (recommended)
	fmt.Println("1. Generating Ed25519 DID (recommended)...")
	ed25519Identity, err := willow.NewIdentity(willow.Ed25519)
	if err != nil {
		log.Fatalf("Failed to generate Ed25519 identity: %v", err)
	}
	fmt.Printf("   DID: %s\n", ed25519Identity.DID())
	fmt.Println("   Algorithm: Ed25519")
	fmt.Printf("   Public Key ID: %s\n", ed25519Identity.PublicKeyID())

	// Willow DIDs are self-certifying: the id is derived from the public key,
	// not chosen. The chain accepts a registration only for the exact derived
	// id, and the fee is paid from that id's own balance, so a new DID must be
	// FUNDED before it can be registered. A DID is registered by a RegisterDid
	// transaction, which this SDK does not build.
	fmt.Println("   Register and fund it with a RegisterDid transaction (not built by this SDK)")
	fmt.Println()

	// 2. Generate Secp256k1 DID (Ethereum-compatible)
	fmt.Println("2. Generating Secp256k1 DID (Ethereum-compatible)...")
	secp256k1Identity, err := willow.NewIdentity(willow.Secp256k1)
	if err != nil {
		log.Fatalf("Failed to generate Secp256k1 identity: %v", err)
	}
	fmt.Printf("   DID: %s\n", secp256k1Identity.DID())
	fmt.Println("   Algorithm: Secp256k1")
	fmt.Printf("   Public Key ID: %s\n", secp256k1Identity.PublicKeyID())

	fmt.Println()

	// 3. Set identity for per-request signing
	fmt.Println("3. Setting identity...")
	client.SetIdentity(ed25519Identity)
	fmt.Printf("   Identity set for: %s\n\n", ed25519Identity.DID())

	// 4. List registered subgroves
	fmt.Println("4. Listing registered subgroves...")
	subgroves, err := client.Registration.ListSubgroves(ctx)
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else if len(subgroves) == 0 {
		fmt.Println("   No subgroves registered yet")
	} else {
		fmt.Printf("   Found %d subgroves:\n", len(subgroves))
		for i, sg := range subgroves {
			if i >= 5 {
				fmt.Printf("   ... and %d more\n", len(subgroves)-5)
				break
			}
			fmt.Printf("   - %s (%s)\n", sg.Name, sg.SubgroveID)
			fmt.Printf("     Owner: %s\n", sg.OwnerDid)
			fmt.Printf("     Writers: %v\n", sg.Writers)
		}
	}

	// 5. Get a specific subgrove
	fmt.Println("\n5. Getting specific subgrove...")
	subgroveID := "test-subgrove"
	sg, err := client.Registration.GetSubgrove(ctx, subgroveID)
	if err != nil {
		fmt.Printf("   Note: %v (subgrove may not exist)\n", err)
	} else {
		// /subgroves/{id} answers with the id, name, and owner;
		// ListSubgroves carries the schema, writers, and free readers.
		fmt.Printf("   Subgrove ID: %s\n", sg.SubgroveID)
		fmt.Printf("   Name: %s\n", sg.Name)
		fmt.Printf("   Owner: %s\n", sg.OwnerDid)
	}

	// 6. Build a subgrove registration request using the SDK builders
	fmt.Println("\n6. Building a registration request...")

	// Schema builder. The chain doesn't support schema indexes, so a schema
	// with one is refused before signing.
	schema := willow.NewSchemaBuilder("User").
		Description("User profile schema").
		StringField("name", true).
		StringField("email", true).
		IntField("age", false).
		Build()
	fmt.Printf("   Schema built: %s with %d fields\n", schema.Name, len(schema.Fields))

	// Subgrove registration request builder
	subgroveReq := willow.NewSubgroveBuilder("users", "Users").
		Description("User profiles").
		Schema(*schema).
		Owner(ed25519Identity.DID()).
		AddWriter(ed25519Identity.DID()).
		Build()
	fmt.Printf("   Subgrove request built: %s\n", subgroveReq.SubgroveID)

	// 7. Submit the registration: a RegisterSubgrove transaction signed by the
	// owner. It needs a registered, funded owner DID.
	fmt.Println("\n7. Submitting registration...")
	if write, err := client.Registration.RegisterSubgrove(ctx, subgroveReq); err != nil {
		fmt.Printf("   Note: %v (likely needs WILL tokens to fund the subgrove)\n", err)
	} else {
		// Submitted: CheckTx accepted it. The subgrove exists once it lands
		// (client.WaitUntilLanded) and its block applies it.
		fmt.Printf("   Submitted %s (nonce %d, tx %s)\n", subgroveReq.SubgroveID, write.Nonce, write.TxHash)
	}

	// 8. Summary
	fmt.Println("\n8. Registration summary...")
	fmt.Println("   DID generation:      willow.NewIdentity(algorithm)")
	fmt.Println("   DID registration:    a RegisterDid transaction (not built by this SDK)")
	fmt.Println("   Subgrove register:   client.Registration.RegisterSubgrove(ctx, req)")
	fmt.Println("   Subgrove list/get:   client.Registration.ListSubgroves / GetSubgrove")

	fmt.Println("\nRegistration example complete!")
}
