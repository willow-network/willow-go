// Light client example for the Willow Go SDK
//
// This example demonstrates:
// - Configuring a light client that keeps a trusted CometBFT header
// - Fetching a key's proof, and what the SDK does and doesn't verify
// - Exporting trusted state
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

	client.SetIdentity(identity)
	fmt.Printf("   Identity set for: %s\n", identity.DID())

	// 5. Store test data
	fmt.Println("\n5. Storing test data...")
	testData := map[string]interface{}{
		"message":   "This data has a GroveDB proof",
		"timestamp": time.Now().Unix(),
		"verified":  true,
	}

	err = client.Data.StoreItem(ctx, "secure-data", "entry-1", testData)
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		fmt.Println("   Data stored")
	}

	// 6. Retrieve the data, then its proof. The proof is of the state after
	// block proof.Height, whose root is the app_hash of the header at
	// proof.Height+1; the SDK can't verify it against the chain, so
	// VerifyProof returns an unsupported error.
	fmt.Println("\n6. Retrieving data and its proof...")

	response, err := client.Data.Get(ctx, "secure-data", "entry-1")
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		dataJSON, _ := json.MarshalIndent(response.Data, "   ", "  ")
		fmt.Println("   Data retrieved:")
		fmt.Printf("   %s\n", dataJSON)
	}
	if proof, err := client.Data.GetProof(ctx, "secure-data", "entry-1"); err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		fmt.Printf("   Proof of %d bytes, state after block %d (unverified)\n", len(proof.Proof), proof.Height)
		if err := client.Data.VerifyProof(ctx, proof); willow.IsUnsupported(err) {
			fmt.Printf("   Note: %v\n", err)
		}
	}

	// 7. Query: the documents are the API's, unverified
	fmt.Println("\n7. Querying...")
	query := willow.NewQueryBuilder().Limit(10).Build()

	queryResponse, err := client.Data.QueryUnverified(ctx, "secure-data", query)
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		fmt.Printf("   Query returned %d documents (unverified)\n", len(queryResponse.Results))
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

	// 10. What the light client checks
	fmt.Println("\n10. What the light client checks...")
	fmt.Println("   VerifyHeader checks a later header's chain id, height and time,")
	fmt.Println("   the trusting period, clock drift, an adjacent header's")
	fmt.Println("   validator-set hash, and the voting power its commit lists.")
	fmt.Println("   It does not verify commit signatures.")

	fmt.Println("\nLight client example complete!")
}
