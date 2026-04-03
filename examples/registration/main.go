// Registration example for the Willow Go SDK
//
// This example demonstrates:
// - Generating DIDs with different signature algorithms
// - Registering a DID
// - Querying apps and subgroves
//
// Note: Creating apps and subgroves requires submitting transactions
// through the consensus layer. This example shows the read operations
// available through the SDK.
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

	// 1. Generate and register Ed25519 DID (recommended)
	fmt.Println("1. Generating Ed25519 DID (recommended)...")
	ed25519Identity, err := willow.NewIdentity(willow.Ed25519)
	if err != nil {
		log.Fatalf("Failed to generate Ed25519 identity: %v", err)
	}
	fmt.Printf("   DID: %s\n", ed25519Identity.DID())
	fmt.Println("   Algorithm: Ed25519")
	fmt.Printf("   Public Key ID: %s\n", ed25519Identity.PublicKeyID())

	_, err = client.RegisterDID(ctx, ed25519Identity.DidDocument)
	if err != nil {
		fmt.Printf("   Note: %v\n\n", err)
	} else {
		fmt.Println("   Registered successfully")
	}

	// 2. Generate Secp256k1 DID (Ethereum-compatible)
	fmt.Println("2. Generating Secp256k1 DID (Ethereum-compatible)...")
	secp256k1Identity, err := willow.NewIdentity(willow.Secp256k1)
	if err != nil {
		log.Fatalf("Failed to generate Secp256k1 identity: %v", err)
	}
	fmt.Printf("   DID: %s\n", secp256k1Identity.DID())
	fmt.Println("   Algorithm: Secp256k1")
	fmt.Printf("   Public Key ID: %s\n", secp256k1Identity.PublicKeyID())

	_, err = client.RegisterDID(ctx, secp256k1Identity.DidDocument)
	if err != nil {
		fmt.Printf("   Note: %v\n\n", err)
	} else {
		fmt.Println("   Registered successfully")
	}

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
		fmt.Printf("   Subgrove ID: %s\n", sg.SubgroveID)
		fmt.Printf("   Name: %s\n", sg.Name)
		fmt.Printf("   Schema: %s\n", sg.Schema.Name)
		fmt.Printf("   Fields: %d\n", len(sg.Schema.Fields))
	}

	// 8. Demonstrate builders for registration requests
	fmt.Println("\n8. Building registration requests (for reference)...")

	// Schema builder
	schema := willow.NewSchemaBuilder("User").
		Description("User profile schema").
		StringField("name", true).
		StringField("email", true).
		IntField("age", false).
		HashIndex("email_idx", []string{"email"}).
		Build()
	fmt.Printf("   Schema built: %s with %d fields\n", schema.Name, len(schema.Fields))

	// Subgrove registration request builder
	subgroveReq := willow.NewSubgroveBuilder("users", "Users").
		Description("User profiles").
		Schema(*schema).
		Owner(ed25519Identity.DID()).
		RewardRate(1000).
		Build()
	fmt.Printf("   Subgrove request built: %s\n", subgroveReq.SubgroveID)

	// 9. Summary
	fmt.Println("\n9. Registration summary...")
	fmt.Println("   DID generation: willow.NewIdentity(algorithm)")
	fmt.Println("   DID registration: client.RegisterDID(ctx, didDocument)")
	fmt.Println("   Query subgroves: client.Registration.ListSubgroves(ctx)")
	fmt.Println("\n   Note: Creating subgroves requires consensus transactions")
	fmt.Println("   Use the consensus.Client for registration operations.")

	fmt.Println("\nRegistration example complete!")
}
