// Data operations example for the Willow Go SDK
//
// This example demonstrates:
// - Storing items, each a signed StoreData transaction
// - Reading them back
// - Querying with a filter
// - The writes this SDK doesn't build (update, delete), which return an
//   unsupported error naming the supported path
//
// Run with: go run ./examples/data_operations

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	willow "github.com/willow-network/willow-go"
)

func main() {
	fmt.Println("Willow SDK - Data Operations Example")
	fmt.Println("=====================================")

	ctx := context.Background()

	// Setup: Create client and authenticate. This example has writes in
	// flight together, so it sets the CometBFT RPC URL: the client then reads
	// which nonces above the account nonce are used, and WaitUntilLanded sees
	// a write land even while an earlier one is pending.
	client, err := willow.NewClient("http://localhost:3031",
		willow.WithRPCURL("http://localhost:26657"))
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	identity, err := willow.NewIdentity(willow.Ed25519)
	if err != nil {
		log.Fatalf("Failed to generate identity: %v", err)
	}

	client.SetIdentity(identity)
	fmt.Printf("Identity set for: %s\n\n", identity.DID())

	subgroveID := "products"

	// 1. Store single item
	fmt.Println("1. Storing single item...")
	product1 := map[string]interface{}{
		"name":     "Widget",
		"price":    29.99,
		"category": "electronics",
		"in_stock": true,
	}

	write, err := client.Data.StoreItem(ctx, subgroveID, "product-1", product1)
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		// Submitted: CheckTx accepted it. It is applied, or refused, in its
		// block; wait for its nonce to land before reading it back.
		fmt.Printf("   Submitted product-1 (nonce %d, tx %s)\n", write.Nonce, write.TxHash)
		waitForNonce(ctx, client, write)
	}

	// 2. Store more items. The API has no batch write: each item is its own
	// StoreData transaction under its own nonce, so they can be in flight
	// together (up to 24 per identity) and land in any order. Wait for each
	// nonce to land before reading them. A write whose error has MayLand set
	// is sent again under its own nonce (WithNonce), so it runs at most once.
	fmt.Println("\n2. Storing more items...")
	items := []willow.StoreRequest{
		{
			Key: "product-2",
			Data: map[string]interface{}{
				"name":     "Gadget",
				"price":    49.99,
				"category": "electronics",
				"in_stock": true,
			},
		},
		{
			Key: "product-3",
			Data: map[string]interface{}{
				"name":     "Gizmo",
				"price":    19.99,
				"category": "toys",
				"in_stock": false,
			},
		},
		{
			Key: "product-4",
			Data: map[string]interface{}{
				"name":     "Thingamajig",
				"price":    99.99,
				"category": "electronics",
				"in_stock": true,
			},
		},
	}

	var writes []*willow.WriteResult
	for _, item := range items {
		write, err := client.Data.StoreItem(ctx, subgroveID, item.Key, item.Data)
		var werr *willow.WriteError
		if errors.As(err, &werr) && werr.MayLand {
			write, err = client.Data.StoreItem(ctx, subgroveID, item.Key, item.Data, willow.WithNonce(werr.Nonce))
		}
		if err != nil {
			fmt.Printf("   Note: %s: %v\n", item.Key, err)
			continue
		}
		fmt.Printf("   Submitted %s (nonce %d)\n", item.Key, write.Nonce)
		writes = append(writes, write)
	}
	for _, write := range writes {
		waitForNonce(ctx, client, write)
	}

	// 3. Get (the API's data route carries no proof; GetProof fetches one)
	fmt.Println("\n3. Get...")
	response, err := client.Data.Get(ctx, subgroveID, "product-1")
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		dataJSON, _ := json.MarshalIndent(response.Data, "   ", "  ")
		fmt.Println("   Retrieved:")
		fmt.Printf("   %s\n", dataJSON)
	}

	// 4. Get without verification (faster)
	fmt.Println("\n4. Get without verification (unverified)...")
	response, err = client.Data.GetUnverified(ctx, subgroveID, "product-2")
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		dataJSON, _ := json.MarshalIndent(response.Data, "   ", "  ")
		fmt.Println("   Retrieved (unverified):")
		fmt.Printf("   %s\n", dataJSON)
	}

	// 5. Update data
	fmt.Println("\n5. Updating data...")
	updatedProduct := map[string]interface{}{
		"name":     "Widget Pro",
		"price":    39.99,
		"category": "electronics",
		"in_stock": true,
		"updated":  true,
	}

	err = client.Data.Update(ctx, subgroveID, "product-1", updatedProduct)
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		fmt.Println("   Updated product-1")
	}

	// 6. Query with a filter (the API's /query applies one equality filter).
	// The documents are the API's, unverified.
	fmt.Println("\n6. Query with a filter...")
	query := willow.NewQueryBuilder().
		Equals("category", "electronics").
		Limit(10).
		Build()

	queryResponse, err := client.Data.QueryUnverified(ctx, subgroveID, query)
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		fmt.Printf("   Found %d documents\n", len(queryResponse.Results))
		for _, result := range queryResponse.Results {
			resultJSON, _ := json.Marshal(result.Data)
			fmt.Printf("   - %s\n", resultJSON)
		}
	}

	// 7. Data.Query would verify the query's proof against the chain, which
	// this SDK can't do, so it returns an unsupported error and sends nothing.
	fmt.Println("\n7. Verified query...")
	if _, err := client.Data.Query(ctx, subgroveID, query); willow.IsUnsupported(err) {
		fmt.Printf("   Note: %v\n", err)
	}

	// 8. Delete data
	fmt.Println("\n8. Deleting data...")
	err = client.Data.Delete(ctx, subgroveID, "product-3")
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		fmt.Println("   Deleted product-3")
	}

	// 9. Compare root hashes. Both are the API's values, unverified: the app
	// hash of the latest block as its CometBFT node reports it, and its
	// database's current root.
	fmt.Println("\n9. Comparing root hashes...")
	appHash, err1 := client.GetLatestAppHash(ctx)
	localRoot, err2 := client.GetRootHash(ctx)

	if err1 == nil && err2 == nil {
		fmt.Printf("   Latest app hash: %s...\n", truncate(appHash, 16))
		fmt.Printf("   Local root:      %s...\n", truncate(localRoot, 16))
		if appHash == localRoot {
			fmt.Println("   The node's database root matches the latest app hash")
		} else {
			fmt.Println("   The node's database root differs from the latest app hash")
		}
	} else {
		fmt.Println("   Could not retrieve root hashes")
	}

	fmt.Println("\nData operations example complete!")
}

// waitForNonce waits up to 30 s for the chain to show a write's nonce used:
// the write landed in a block. A write refused in its block also uses its
// nonce, so read what it wrote to know it took effect.
func waitForNonce(ctx context.Context, client *willow.Client, write *willow.WriteResult) {
	waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := client.WaitUntilLanded(waitCtx, write.DID, write.Nonce); err != nil {
		fmt.Printf("   Note: %v\n", err)
		return
	}
	fmt.Printf("   Nonce %d landed\n", write.Nonce)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
