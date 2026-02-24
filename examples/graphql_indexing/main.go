// GraphQL indexing example for the Willow Go SDK
//
// This example demonstrates:
// - Listing available subgroves
// - Querying indexed blockchain data with GraphQL
// - Checking subgrove indexing status
// - Listing indexers
//
// Run with: go run ./examples/graphql_indexing

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	willow "github.com/willow-network/willow-go"
)

func main() {
	fmt.Println("Willow SDK - GraphQL Indexing Example")
	fmt.Println("======================================")

	ctx := context.Background()

	client, err := willow.NewClient("http://localhost:3031")
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	// 1. List available subgroves
	fmt.Println("1. Listing available subgroves...")
	subgroves, err := client.Indexing.ListSubgroves(ctx)
	if err != nil {
		fmt.Printf("   Note: %v\n\n", err)
	} else if len(subgroves) == 0 {
		fmt.Println("   No subgroves deployed yet")
	} else {
		fmt.Printf("   Found %d subgroves:\n", len(subgroves))
		for _, sg := range subgroves {
			fmt.Printf("   - %s (%s)\n", sg.Name, sg.ID)
			fmt.Printf("     Status: %s\n", sg.Status)
			fmt.Printf("     Current block: %d\n", sg.CurrentBlock)
		}
		fmt.Println()
	}

	// 2. Query a subgrove (example: Uniswap V3)
	fmt.Println("2. Querying subgrove (example: uniswap-v3)...")
	query := `
		query {
			swaps(first: 5, orderBy: timestamp, orderDirection: desc) {
				id
				amount0
				amount1
				timestamp
				pool {
					token0 {
						symbol
					}
					token1 {
						symbol
					}
				}
			}
		}
	`

	response, err := client.Indexing.Execute(ctx, "uniswap-v3", query, nil)
	if err != nil {
		fmt.Printf("   Note: %v (subgrove may not exist)\n\n", err)
	} else {
		fmt.Println("   Query result:")
		if response.Data != nil {
			var prettyJSON map[string]interface{}
			json.Unmarshal(response.Data, &prettyJSON)
			formatted, _ := json.MarshalIndent(prettyJSON, "   ", "  ")
			fmt.Printf("   %s\n", formatted)
		}
		if len(response.Proof) > 0 {
			fmt.Println("   Proof included in response")
		}
		for _, err := range response.Errors {
			fmt.Printf("   Error: %s\n", err.Message)
		}
	}

	// 3. Query with variables
	fmt.Println("\n3. Query with variables...")
	queryWithVars := `
		query GetPool($poolId: ID!) {
			pool(id: $poolId) {
				id
				token0 {
					symbol
					name
				}
				token1 {
					symbol
					name
				}
				liquidity
				volumeUSD
			}
		}
	`

	variables := map[string]interface{}{
		"poolId": "0x8ad599c3a0ff1de082011efddc58f1908eb6e6d8",
	}

	response, err = client.Indexing.Execute(ctx, "uniswap-v3", queryWithVars, variables)
	if err != nil {
		fmt.Printf("   Note: %v\n\n", err)
	} else {
		fmt.Println("   Query result:")
		if response.Data != nil {
			var prettyJSON map[string]interface{}
			json.Unmarshal(response.Data, &prettyJSON)
			formatted, _ := json.MarshalIndent(prettyJSON, "   ", "  ")
			fmt.Printf("   %s\n", formatted)
		}
	}

	// 4. Using the GraphQL query builder
	fmt.Println("\n4. Using GraphQL query builder...")
	req := willow.NewGraphQLQuery(`
		query GetRecentSwaps($first: Int!) {
			swaps(first: $first) {
				id
				timestamp
			}
		}
	`).
		Variable("first", 10).
		OperationName("GetRecentSwaps").
		IncludeProof().
		Build()

	response, err = client.Indexing.Query(ctx, "uniswap-v3", req)
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		fmt.Println("   Query executed with builder")
		if len(response.Proof) > 0 {
			fmt.Println("   Proof included: yes")
		}
	}

	// 5. Get subgrove status
	fmt.Println("\n5. Getting subgrove indexing status...")
	subgrove, err := client.Indexing.GetSubgrove(ctx, "uniswap-v3")
	if err != nil {
		fmt.Printf("   Note: %v\n\n", err)
	} else {
		fmt.Printf("   Subgrove: %s\n", subgrove.ID)
		fmt.Printf("   Network: %s\n", subgrove.Network)
		fmt.Printf("   Start block: %d\n", subgrove.StartBlock)
		fmt.Printf("   Current block: %d\n", subgrove.CurrentBlock)
		fmt.Printf("   Status: %s\n", subgrove.Status)
	}

	// 6. List indexers
	fmt.Println("\n6. Listing indexers...")
	indexers, err := client.Indexing.ListIndexers(ctx)
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else if len(indexers) == 0 {
		fmt.Println("   No indexers registered yet")
	} else {
		fmt.Printf("   Found %d indexers:\n", len(indexers))
		for _, indexer := range indexers {
			fmt.Printf("   - %s\n", indexer.ID)
			fmt.Printf("     Address: %s\n", indexer.Address)
			fmt.Printf("     Stake: %d WILL\n", indexer.Stake)
			fmt.Printf("     Status: %s\n", indexer.Status)
			fmt.Printf("     Performance: %.1f\n", indexer.Performance)
			fmt.Printf("     Subgroves: %v\n", indexer.Subgroves)
		}
	}

	// 7. Execute query and unmarshal result
	fmt.Println("\n7. Execute and unmarshal result...")
	type SwapResult struct {
		Swaps []struct {
			ID        string `json:"id"`
			Timestamp int64  `json:"timestamp"`
		} `json:"swaps"`
	}

	var result SwapResult
	err = client.Indexing.ExecuteWithResult(ctx, "uniswap-v3",
		`query { swaps(first: 3) { id timestamp } }`,
		nil,
		&result,
	)
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		fmt.Printf("   Unmarshaled %d swaps:\n", len(result.Swaps))
		for _, swap := range result.Swaps {
			fmt.Printf("   - %s (ts: %d)\n", swap.ID[:20]+"...", swap.Timestamp)
		}
	}

	// 8. Comparison with The Graph
	fmt.Println("\n8. Willow vs The Graph...")
	fmt.Println("   Willow advantages:")
	fmt.Println("   + Cryptographic proofs for every query")
	fmt.Println("   + Trustless verification of indexed data")
	fmt.Println("   + No fisherman disputes needed")
	fmt.Println("   + Instant finality on results")
	fmt.Println("   + Native proof verification in SDK")

	fmt.Println("\nGraphQL indexing example complete!")
}
