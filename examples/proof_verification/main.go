// Proof verification example for the Willow Go SDK
//
// This example demonstrates:
// - What a proof the API returns is of, and what the SDK verifies
// - Unverified reads and queries
// - Proof retrieval
// - Root hash comparison
//
// Run with: go run ./examples/proof_verification

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	willow "github.com/willow-network/willow-go"
)

func main() {
	fmt.Println("Willow SDK - Proof Verification Example")
	fmt.Println("========================================")
	fmt.Println()

	ctx := context.Background()

	// 1. Create client
	fmt.Println("1. Creating client...")
	client, err := willow.NewClient("http://localhost:3031")
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()
	fmt.Println("   Connected to Willow node")
	fmt.Println()

	// 2. Generate and register DID
	fmt.Println("2. Setting up identity...")
	identity, err := willow.NewIdentity(willow.Ed25519)
	if err != nil {
		log.Fatalf("Failed to generate identity: %v", err)
	}
	fmt.Printf("   DID: %s\n", identity.DID())

	// A DID is registered on chain by a RegisterDid transaction, which this
	// SDK does not build; RegisterDID says so.
	if _, err = client.RegisterDID(ctx, identity.DidDocument); err != nil {
		fmt.Printf("   Note: %v\n", err)
	}

	client.SetIdentity(identity)
	fmt.Println("   Identity set — requests will be signed automatically")
	fmt.Println()

	subgroveID := "test-data"

	// 3. Store test data
	fmt.Println("3. Storing test data...")
	testData := map[string]interface{}{
		"message": "This data has a cryptographic proof",
		"value":   42,
		"tags":    []string{"demo", "proof", "verification"},
	}

	err = client.Data.StoreItem(ctx, subgroveID, "test-key", testData)
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		fmt.Println("   Data stored successfully")
	}
	fmt.Println()

	// 4. Get. The API's data route answers with the value alone; step 8
	// fetches the key's proof.
	fmt.Println("4. Get...")
	fmt.Println()

	response, err := client.Data.Get(ctx, subgroveID, "test-key")
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		dataJSON, _ := json.MarshalIndent(response.Data, "   ", "  ")
		fmt.Println("   Data retrieved:")
		fmt.Printf("   %s\n", dataJSON)
	}
	fmt.Println()

	// 5. Get, asking the API for no proof
	fmt.Println("5. GetUnverified...")
	fmt.Println()

	response, err = client.Data.GetUnverified(ctx, subgroveID, "test-key")
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		dataJSON, _ := json.MarshalIndent(response.Data, "   ", "  ")
		fmt.Println("   Data retrieved (no verification):")
		fmt.Printf("   %s\n", dataJSON)
	}
	fmt.Println()

	// 6. Verified query. Data.Query would verify the query's proof against
	// the chain, which this SDK can't do, so it returns an unsupported error
	// and sends nothing.
	fmt.Println("6. Verified query...")
	query := willow.NewQueryBuilder().Limit(5).Build()

	if _, err := client.Data.Query(ctx, subgroveID, query); willow.IsUnsupported(err) {
		fmt.Printf("   Note: %v\n", err)
	}
	fmt.Println()

	// 7. Query without verification
	fmt.Println("7. Query without verification (unverified)...")
	queryResponse, err := client.Data.QueryUnverified(ctx, subgroveID, query)
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		fmt.Printf("   Found %d results\n", len(queryResponse.Results))
	}
	fmt.Println()

	// 8. Proof retrieval. The proof is of the state after block proof.Height,
	// so its root is the app_hash of the CometBFT header at proof.Height+1.
	fmt.Println("8. Proof retrieval...")
	proof, err := client.Data.GetProof(ctx, subgroveID, "test-key")
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		fmt.Printf("   Proof of %d bytes, state after block %d (unverified)\n", len(proof.Proof), proof.Height)
		if err := client.Data.VerifyProof(ctx, proof); willow.IsUnsupported(err) {
			fmt.Printf("   Note: %v\n", err)
		}
	}
	fmt.Println()

	// 9. Root hash comparison
	fmt.Println("9. Root hash comparison...")
	localRoot, err := client.GetRootHash(ctx)
	if err != nil {
		fmt.Printf("   Local root: Error - %v\n", err)
	} else {
		if len(localRoot) > 32 {
			fmt.Printf("   Local root:    %s...\n", localRoot[:32])
		} else {
			fmt.Printf("   Local root:    %s\n", localRoot)
		}
	}

	verifiedRoot, err := client.GetVerifiedRootHash(ctx)
	if err != nil {
		fmt.Printf("   Verified root: Error - %v\n", err)
	} else {
		if len(verifiedRoot) > 32 {
			fmt.Printf("   Verified root: %s...\n", verifiedRoot[:32])
		} else {
			fmt.Printf("   Verified root: %s\n", verifiedRoot)
		}

		if localRoot == verifiedRoot {
			fmt.Println("   Node is in sync with consensus")
		} else {
			fmt.Println("   Node has pending changes")
		}
	}
	fmt.Println()

	// 10. Summary
	fmt.Println("10. Proof verification summary")
	fmt.Println()
	fmt.Println("   A proof the API returns is of the state after block Height,")
	fmt.Println("   whose root is the app_hash of the CometBFT header at Height+1.")
	fmt.Println("   Verifying it takes that header verified against the validators'")
	fmt.Println("   commit signatures and a GroveDB verifier that reproduces the")
	fmt.Println("   chain's root. The SDK doesn't provide these, so Data.Query and")
	fmt.Println("   Data.VerifyProof return an unsupported error, and Get,")
	fmt.Println("   GetUnverified, QueryUnverified, and GetProof return what the")
	fmt.Println("   API sends, unverified.")
	fmt.Println()

	fmt.Println("Proof verification example complete!")
}
