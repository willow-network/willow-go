// Basic usage example for the Willow Go SDK
//
// This example demonstrates:
// - Creating a client
// - Generating and registering a DID
// - Setting identity for per-request signing
// - Storing and retrieving data with automatic proof verification
//
// Run with: go run ./examples/basic_usage

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	willow "github.com/willow-network/willow-go"
)

func main() {
	fmt.Println("Willow SDK - Basic Usage Example")
	fmt.Println("=================================")

	ctx := context.Background()

	// 1. Create client
	fmt.Println("1. Creating client...")
	client, err := willow.NewClient("http://localhost:3031")
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()
	fmt.Println("   Connected to Willow node")

	// 2. Generate a DID
	fmt.Println("2. Generating Ed25519 DID...")
	identity, err := willow.NewIdentity(willow.Ed25519)
	if err != nil {
		log.Fatalf("Failed to generate identity: %v", err)
	}
	fmt.Printf("   DID: %s\n", identity.DID())
	fmt.Printf("   Public Key ID: %s\n\n", identity.PublicKeyID())

	// 3. Register the DID
	fmt.Println("3. Registering DID...")
	_, err = client.RegisterDID(ctx, identity.DidDocument)
	if err != nil {
		fmt.Printf("   Note: %v\n\n", err)
	} else {
		fmt.Println("   DID registered successfully")
	}

	// 4. Set identity for per-request signing
	fmt.Println("4. Setting identity...")
	client.SetIdentity(identity)
	fmt.Println("   Identity set — all requests will be signed automatically")

	// 5. Store data (requires an existing subgrove)
	fmt.Println("5. Storing data...")
	testData := map[string]interface{}{
		"name":   "Alice",
		"score":  100,
		"active": true,
	}

	err = client.Data.StoreItem(ctx, "users", "alice", testData)
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		fmt.Println("   Data stored successfully")
	}

	// 6. Retrieve data with automatic proof verification
	fmt.Println("\n6. Retrieving data (with proof verification)...")
	response, err := client.Data.Get(ctx, "users", "alice")
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		dataJSON, _ := json.MarshalIndent(response.Data, "   ", "  ")
		fmt.Println("   Data retrieved and verified:")
		fmt.Printf("   %s\n", dataJSON)
	}

	// 7. Retrieve data without verification (faster)
	fmt.Println("\n7. Retrieving data (without verification)...")
	response, err = client.Data.GetUnverified(ctx, "users", "alice")
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		dataJSON, _ := json.MarshalIndent(response.Data, "   ", "  ")
		fmt.Println("   Data retrieved (unverified):")
		fmt.Printf("   %s\n", dataJSON)
	}

	// 8. Get root hash
	fmt.Println("\n8. Getting root hash...")
	rootHash, err := client.GetRootHash(ctx)
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		fmt.Printf("   Root hash: %s\n", rootHash)
	}

	fmt.Println("\nBasic usage example complete!")
}
