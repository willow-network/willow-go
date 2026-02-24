// Light client example for the Willow Go SDK
//
// This example demonstrates:
// - Configuring a light client for trustless verification
// - Verifying data against multiple validators
// - Exporting and importing trusted state
//
// Run with: go run ./examples/light_client

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	willow "github.com/willow-network/willow-go"
	"github.com/willow-network/willow-go/lightclient"
)

func main() {
	fmt.Println("Willow SDK - Light Client Example")
	fmt.Println("==================================")

	ctx := context.Background()

	// 1. Configure light client with multiple validators
	fmt.Println("1. Configuring light client...")
	lcConfig := lightclient.Config{
		ChainID: "willow-testnet",
		ValidatorEndpoints: []string{
			"http://localhost:26657",
			"http://localhost:26757",
			"http://localhost:26857",
		},
		TrustThreshold: lightclient.TrustThreshold{
			Numerator:   2,
			Denominator: 3,
		},
		TrustingPeriod:            24 * time.Hour,
		MaxClockDrift:             10 * time.Second,
		MinValidatorsForConsensus: 2,
		AutoSync:                  true,
		SyncInterval:              5 * time.Minute,
	}

	fmt.Println("   Chain ID: willow-testnet")
	fmt.Println("   Validators: 3 endpoints configured")
	fmt.Println("   Trust threshold: 2/3")
	fmt.Println("   Trusting period: 24 hours")

	// 2. Create light client
	fmt.Println("2. Creating light client...")
	lc, err := lightclient.NewLightClient(lcConfig)
	if err != nil {
		log.Fatalf("Failed to create light client: %v", err)
	}
	lc.Start()
	defer lc.Stop()
	fmt.Println("   Light client: ACTIVE")

	// 3. Create client with light client
	fmt.Println("\n3. Creating Willow client with light client...")
	client, err := willow.NewClient("http://localhost:3031",
		willow.WithLightClient(lc),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	if client.HasLightClient() {
		fmt.Println("   Light client: ENABLED")
	}

	// 4. Set identity
	fmt.Println("\n4. Setting identity...")
	identity, err := willow.NewIdentity(willow.Ed25519)
	if err != nil {
		log.Fatalf("Failed to generate identity: %v", err)
	}

	client.RegisterDID(ctx, identity.DidDocument)
	client.SetIdentity(identity)
	fmt.Printf("   Identity set for: %s\n", identity.DID())

	// 5. Store test data
	fmt.Println("\n5. Storing test data...")
	testData := map[string]interface{}{
		"message":   "This data will be cryptographically verified",
		"timestamp": time.Now().Unix(),
		"verified":  true,
	}

	err = client.Data.StoreItem(ctx, "test-app", "secure-data", "entry-1", testData)
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		fmt.Println("   Data stored")
	}

	// 6. Retrieve with full trustless verification
	fmt.Println("\n6. Retrieving data with trustless verification...")
	fmt.Println("   This verifies:")
	fmt.Println("   - 2/3+ validator signatures on block headers")
	fmt.Println("   - GroveDB Merkle proof against consensus app_hash")
	fmt.Println("   - Data integrity without trusting any single node")

	response, err := client.Data.Get(ctx, "test-app", "secure-data", "entry-1")
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		dataJSON, _ := json.MarshalIndent(response.Data, "   ", "  ")
		fmt.Println("   Data retrieved and CRYPTOGRAPHICALLY VERIFIED:")
		fmt.Printf("   %s\n", dataJSON)
	}

	// 7. Query with verification
	fmt.Println("\n7. Querying with trustless verification...")
	query := willow.NewQueryBuilder().Limit(10).Build()

	queryResponse, err := client.Data.Query(ctx, "test-app", "secure-data", query)
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		fmt.Printf("   Query returned %d documents\n", len(queryResponse.Results))
	}

	// 8. Export trusted state for persistence
	fmt.Println("\n8. Exporting trusted state...")
	state, err := lc.ExportTrustedState()
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		fmt.Printf("   Exported trusted state at height %d\n", state.Header.Height)
		fmt.Println("   State can be persisted and restored later")

		// In production, you would serialize and save this:
		// stateJSON, _ := json.Marshal(state)
		// os.WriteFile("trusted_state.json", stateJSON, 0644)
	}

	// 9. Get sync status
	fmt.Println("\n9. Getting sync status...")
	syncStatus := lc.GetSyncStatus()
	fmt.Printf("   Latest trusted height: %d\n", syncStatus.LatestTrustedHeight)
	fmt.Printf("   Is synced: %v\n", syncStatus.IsSynced)
	if syncStatus.LastSyncError != "" {
		fmt.Printf("   Last error: %s\n", syncStatus.LastSyncError)
	}

	// 10. Show verification comparison
	fmt.Println("\n10. Verification comparison...")
	fmt.Println("\n   LIGHT CLIENT (trustless):")
	fmt.Println("   + Verifies validator signatures (2/3+ threshold)")
	fmt.Println("   + Validates block header chain")
	fmt.Println("   + Verifies proofs against consensus app_hash")
	fmt.Println("   + No trust in any single node required")
	fmt.Println("   - Slightly higher latency")

	fmt.Println("   STANDARD VERIFICATION (root hash):")
	fmt.Println("   + Fast verification")
	fmt.Println("   + Verifies GroveDB proofs locally")
	fmt.Println("   - Trusts that API returns correct root hash")

	fmt.Println("   UNVERIFIED (performance mode):")
	fmt.Println("   + Fastest response times")
	fmt.Println("   - Trusts the node completely")
	fmt.Println("   - Only use with trusted nodes")

	fmt.Println("\nLight client example complete!")
}
