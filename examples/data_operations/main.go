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
	"fmt"
	"log"
	"time"

	willow "github.com/willow-network/willow-go"
)

func main() {
	fmt.Println("Willow SDK - Data Operations Example")
	fmt.Println("=====================================")

	ctx := context.Background()

	// Setup: Create client and authenticate
	client, err := willow.NewClient("http://localhost:3031")
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

	err = client.Data.StoreItem(ctx, subgroveID, "product-1", product1)
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		fmt.Println("   Sent product-1")
		waitForKey(ctx, client, subgroveID, "product-1")
	}

	// 2. Store more items. The API has no batch write: each item is its own
	// StoreData transaction, signed under the account's next nonce, so each is
	// sent after the previous one has landed.
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

	for _, item := range items {
		if err := client.Data.StoreItem(ctx, subgroveID, item.Key, item.Data); err != nil {
			fmt.Printf("   Note: %s: %v\n", item.Key, err)
			continue
		}
		fmt.Printf("   Sent %s\n", item.Key)
		waitForKey(ctx, client, subgroveID, item.Key)
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

	// 9. Compare root hashes
	fmt.Println("\n9. Comparing root hashes...")
	verifiedRoot, err1 := client.GetVerifiedRootHash(ctx)
	localRoot, err2 := client.GetRootHash(ctx)

	if err1 == nil && err2 == nil {
		fmt.Printf("   Verified root: %s...\n", truncate(verifiedRoot, 16))
		fmt.Printf("   Local root:    %s...\n", truncate(localRoot, 16))
		if verifiedRoot == localRoot {
			fmt.Println("   Node is in sync with consensus")
		} else {
			fmt.Println("   Node has pending changes")
		}
	} else {
		fmt.Println("   Could not retrieve root hashes")
	}

	fmt.Println("\nData operations example complete!")
}

// waitForKey polls for a stored key until its write has landed, or 30 s pass.
func waitForKey(ctx context.Context, client *willow.Client, subgroveID, key string) {
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(time.Second) {
		if _, err := client.Data.GetUnverified(ctx, subgroveID, key); err == nil {
			fmt.Printf("   %s landed\n", key)
			return
		}
	}
	fmt.Printf("   %s has not landed after 30 s\n", key)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
