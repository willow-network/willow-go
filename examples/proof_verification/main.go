// Proof verification example for the Willow Go SDK
//
// This example demonstrates:
// - Automatic proof verification (default behavior)
// - Comparing verified vs unverified operations
// - Manual proof retrieval and verification
// - Root hash comparison
// - Light client configuration for trustless verification
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

	_, err = client.RegisterDID(ctx, identity.DidDocument)
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		fmt.Println("   DID registered")
	}

	_, err = client.Authenticate(ctx, identity)
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		fmt.Println("   Authenticated successfully")
	}
	fmt.Println()

	appID := "proof-demo"
	subgroveID := "test-data"

	// 3. Store test data
	fmt.Println("3. Storing test data...")
	testData := map[string]interface{}{
		"message": "This data has a cryptographic proof",
		"value":   42,
		"tags":    []string{"demo", "proof", "verification"},
	}

	err = client.Data.StoreItem(ctx, appID, subgroveID, "test-key", testData)
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		fmt.Println("   Data stored successfully")
	}
	fmt.Println()

	// 4. Get with automatic verification (default)
	fmt.Println("4. Get with automatic verification...")
	fmt.Println("   The SDK automatically:")
	fmt.Println("   - Requests the data with proof from the API")
	fmt.Println("   - Verifies the proof against the light client (if configured)")
	fmt.Println("   - Compares against the consensus root hash")
	fmt.Println("   - Returns error if verification fails")
	fmt.Println()

	response, err := client.Data.Get(ctx, appID, subgroveID, "test-key")
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		dataJSON, _ := json.MarshalIndent(response.Data, "   ", "  ")
		fmt.Println("   Data retrieved and VERIFIED:")
		fmt.Printf("   %s\n", dataJSON)
	}
	fmt.Println()

	// 5. Get without verification (faster)
	fmt.Println("5. Get without verification (unverified)...")
	fmt.Println("   Skips all proof verification for maximum performance")
	fmt.Println("   Use only when you trust the node")
	fmt.Println()

	response, err = client.Data.GetUnverified(ctx, appID, subgroveID, "test-key")
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		dataJSON, _ := json.MarshalIndent(response.Data, "   ", "  ")
		fmt.Println("   Data retrieved (no verification):")
		fmt.Printf("   %s\n", dataJSON)
	}
	fmt.Println()

	// 6. Query with verification
	fmt.Println("6. Query with automatic verification...")
	query := willow.NewQueryBuilder().Limit(5).IncludeProof().Build()

	queryResponse, err := client.Data.Query(ctx, appID, subgroveID, query)
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		fmt.Printf("   Found %d results\n", len(queryResponse.Results))
		if len(queryResponse.Proof) > 0 {
			fmt.Println("   Proof was included and verified")
		}
	}
	fmt.Println()

	// 7. Query without verification (for comparison)
	fmt.Println("7. Query without verification (unverified)...")
	queryUnverified := willow.NewQueryBuilder().Limit(5).Build()

	queryResponse, err = client.Data.QueryUnverified(ctx, appID, subgroveID, queryUnverified)
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		fmt.Printf("   Found %d results\n", len(queryResponse.Results))
		fmt.Printf("   Proof included: %v\n", len(queryResponse.Proof) > 0)
	}
	fmt.Println()

	// 8. Manual proof retrieval
	fmt.Println("8. Manual proof retrieval...")
	proof, err := client.Data.GetProof(ctx, appID, subgroveID, "test-key")
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		fmt.Println("   Proof retrieved successfully")
		fmt.Printf("   Proof size: %d bytes\n", len(proof.Proof))
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

	// 10. Light client status
	fmt.Println("10. Light client status...")
	if client.HasLightClient() {
		fmt.Println("   Light client: ENABLED")
		fmt.Println("   All Get() and Query() calls are verified against consensus")
	} else {
		fmt.Println("   Light client: NOT CONFIGURED")
		fmt.Println("   To enable trustless verification, configure a light client:")
		fmt.Println()
		fmt.Println("   lc, _ := lightclient.NewLightClient(lightclient.Config{")
		fmt.Println("       ChainID:      \"willow-chain\",")
		fmt.Println("       TrustOptions: trustOptions,")
		fmt.Println("       PrimaryAddr:  \"http://localhost:26657\",")
		fmt.Println("   })")
		fmt.Println("   client, _ := willow.NewClient(apiURL, willow.WithLightClient(lc))")
	}
	fmt.Println()

	// 11. Summary
	fmt.Println("11. Proof verification summary")
	fmt.Println()
	fmt.Println("   AUTOMATIC VERIFICATION (recommended):")
	fmt.Println("   - Use Get() and Query() methods")
	fmt.Println("   - Proofs verified against consensus root hash")
	fmt.Println("   - Returns error if verification fails")
	fmt.Println("   - Provides cryptographic guarantee of data integrity")
	fmt.Println()
	fmt.Println("   WITH LIGHT CLIENT (trustless):")
	fmt.Println("   - Configure with WithLightClient() option")
	fmt.Println("   - Verifies validator signatures (2/3+ threshold)")
	fmt.Println("   - No trust required in any single node")
	fmt.Println()
	fmt.Println("   SKIP VERIFICATION (use with caution):")
	fmt.Println("   - Use GetUnverified() and QueryUnverified()")
	fmt.Println("   - Maximum performance")
	fmt.Println("   - Only use with trusted nodes")
	fmt.Println()

	fmt.Println("Proof verification example complete!")
}
