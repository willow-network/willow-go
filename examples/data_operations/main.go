// Data operations example for the Willow Go SDK
//
// This example demonstrates:
// - Storing single items
// - Batch storing multiple items
// - Updating data
// - Deleting data
// - Querying with filters
// - Verified vs unverified operations
//
// Run with: go run ./examples/data_operations

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

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

	client.RegisterDID(ctx, identity.DidDocument)
	client.Authenticate(ctx, identity)
	fmt.Printf("Authenticated as: %s\n\n", identity.DID())

	appID := "example-app"
	subgroveID := "products"

	// 1. Store single item
	fmt.Println("1. Storing single item...")
	product1 := map[string]interface{}{
		"name":     "Widget",
		"price":    29.99,
		"category": "electronics",
		"in_stock": true,
	}

	err = client.Data.StoreItem(ctx, appID, subgroveID, "product-1", product1)
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		fmt.Println("   Stored product-1")
	}

	// 2. Batch store multiple items
	fmt.Println("\n2. Batch storing items...")
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

	err = client.Data.BatchStore(ctx, appID, subgroveID, items)
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		fmt.Println("   Stored 3 products in batch")
	}

	// 3. Get with proof verification (secure by default)
	fmt.Println("\n3. Get with proof verification...")
	response, err := client.Data.Get(ctx, appID, subgroveID, "product-1")
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		dataJSON, _ := json.MarshalIndent(response.Data, "   ", "  ")
		fmt.Println("   Retrieved and VERIFIED:")
		fmt.Printf("   %s\n", dataJSON)
	}

	// 4. Get without verification (faster)
	fmt.Println("\n4. Get without verification (unverified)...")
	response, err = client.Data.GetUnverified(ctx, appID, subgroveID, "product-2")
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

	err = client.Data.Update(ctx, appID, subgroveID, "product-1", updatedProduct)
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		fmt.Println("   Updated product-1")
	}

	// 6. Query with filters (verified)
	fmt.Println("\n6. Query with filters (verified)...")
	query := willow.NewQueryBuilder().
		Equals("category", "electronics").
		Equals("in_stock", true).
		Limit(10).
		Build()

	queryResponse, err := client.Data.Query(ctx, appID, subgroveID, query)
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		fmt.Printf("   Found %d documents\n", len(queryResponse.Results))
		for _, result := range queryResponse.Results {
			resultJSON, _ := json.Marshal(result.Data)
			fmt.Printf("   - %s\n", resultJSON)
		}
	}

	// 7. Query without verification (faster)
	fmt.Println("\n7. Query without verification...")
	query = willow.NewQueryBuilder().Limit(5).Build()

	queryResponse, err = client.Data.QueryUnverified(ctx, appID, subgroveID, query)
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		fmt.Printf("   Found %d documents (unverified)\n", len(queryResponse.Results))
	}

	// 8. Delete data
	fmt.Println("\n8. Deleting data...")
	err = client.Data.Delete(ctx, appID, subgroveID, "product-3")
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

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
