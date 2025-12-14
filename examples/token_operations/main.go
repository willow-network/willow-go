// Token operations example for the Willow Go SDK
//
// This example demonstrates:
// - Getting token information
// - Querying balances
// - Getting fee schedules
// - Estimating fees
// - Listing validators
//
// Run with: go run ./examples/token_operations

package main

import (
	"context"
	"fmt"
	"log"

	willow "github.com/willow-network/willow-go"
)

func main() {
	fmt.Println("Willow SDK - Token Operations Example")
	fmt.Println("======================================")

	ctx := context.Background()

	client, err := willow.NewClient("http://localhost:3031")
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	// Authenticate for operations that require it
	identity, err := willow.NewIdentity(willow.Ed25519)
	if err != nil {
		log.Fatalf("Failed to generate identity: %v", err)
	}
	client.RegisterDID(ctx, identity.DidDocument)
	client.Authenticate(ctx, identity)
	fmt.Printf("Authenticated as: %s\n\n", identity.DID())

	// 1. Get token information
	fmt.Println("1. Getting token information...")
	tokenInfo, err := client.Token.GetInfo(ctx)
	if err != nil {
		fmt.Printf("   Note: %v\n\n", err)
	} else {
		fmt.Printf("   Token Name: %s\n", tokenInfo.Name)
		fmt.Printf("   Symbol: %s\n", tokenInfo.Symbol)
		fmt.Printf("   Decimals: %d\n", tokenInfo.Decimals)
		fmt.Printf("   Total Supply: %d\n", tokenInfo.TotalSupply)
		fmt.Printf("   Circulating Supply: %d\n\n", tokenInfo.CirculatingSupply)
	}

	// 2. Get balance for a DID
	fmt.Println("2. Getting balance for authenticated user...")
	balance, err := client.Token.GetMyBalance(ctx)
	if err != nil {
		fmt.Printf("   Note: %v\n\n", err)
	} else {
		fmt.Printf("   ID: %s\n", balance.ID)
		fmt.Printf("   Balance: %d\n", balance.Balance)
		fmt.Printf("   Available: %d\n", balance.Available)
		fmt.Printf("   Locked: %d\n\n", balance.Locked)
	}

	// 3. Get balance for a specific DID
	fmt.Println("3. Getting balance for specific DID...")
	targetDID := "did:willow:Ed25519:abc12345"
	balance, err = client.Token.GetBalance(ctx, targetDID)
	if err != nil {
		fmt.Printf("   Note: %v\n\n", err)
	} else {
		fmt.Printf("   Balance for %s: %d\n\n", targetDID, balance.Balance)
	}

	// 4. Get app balance
	fmt.Println("4. Getting balance for an app...")
	appID := "my-app"
	appBalance, err := client.Token.GetAppBalance(ctx, appID)
	if err != nil {
		fmt.Printf("   Note: %v\n\n", err)
	} else {
		fmt.Printf("   App: %s\n", appID)
		fmt.Printf("   Balance: %d\n", appBalance.Balance)
		fmt.Printf("   Available: %d\n\n", appBalance.Available)
	}

	// 5. Get fee schedule
	fmt.Println("5. Getting fee schedule...")
	fees, err := client.Token.GetFeeSchedule(ctx)
	if err != nil {
		fmt.Printf("   Note: %v\n\n", err)
	} else {
		fmt.Printf("   Storage fee per byte: %d\n", fees.StorageFeePerByte)
		fmt.Printf("   Query fee base: %d\n", fees.QueryFeeBase)
		fmt.Printf("   Query fee per result: %d\n", fees.QueryFeePerResult)
		fmt.Printf("   Transaction fee base: %d\n\n", fees.TransactionFeeBase)
	}

	// 6. Estimate storage fee
	fmt.Println("6. Estimating storage fees...")
	sizes := []uint64{1024, 10240, 102400, 1048576} // 1KB, 10KB, 100KB, 1MB
	for _, size := range sizes {
		fee, err := client.Token.EstimateStorageFee(ctx, size)
		if err != nil {
			fmt.Printf("   Note: %v\n", err)
			break
		}
		fmt.Printf("   %s: %d WILL\n", formatSize(size), fee)
	}

	// 7. Estimate query fee
	fmt.Println("\n7. Estimating query fees...")
	resultCounts := []uint64{10, 100, 1000}
	for _, count := range resultCounts {
		fee, err := client.Token.EstimateQueryFee(ctx, count)
		if err != nil {
			fmt.Printf("   Note: %v\n", err)
			break
		}
		fmt.Printf("   %d results: %d WILL\n", count, fee)
	}

	// 8. List validators
	fmt.Println("\n8. Listing validators...")
	validators, err := client.Validators.List(ctx)
	if err != nil {
		fmt.Printf("   Note: %v\n\n", err)
	} else if len(validators) == 0 {
		fmt.Println("   No validators found")
	} else {
		fmt.Printf("   Found %d validators:\n", len(validators))
		for _, v := range validators {
			fmt.Printf("   - %s\n", v.Moniker)
			fmt.Printf("     Address: %s\n", truncate(v.Address, 20))
			fmt.Printf("     Voting Power: %d\n", v.VotingPower)
			fmt.Printf("     Status: %s\n", v.Status)
			fmt.Printf("     Commission: %.2f%%\n", v.Commission*100)
		}
	}

	// 9. Get active validators
	fmt.Println("\n9. Getting active validators only...")
	activeValidators, err := client.Validators.GetActive(ctx)
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		fmt.Printf("   Active validators: %d\n", len(activeValidators))
	}

	// 10. Get total voting power
	fmt.Println("\n10. Getting total voting power...")
	totalPower, err := client.Validators.GetTotalVotingPower(ctx)
	if err != nil {
		fmt.Printf("   Note: %v\n", err)
	} else {
		fmt.Printf("   Total voting power: %d\n", totalPower)
	}

	// 11. Summary of token operations
	fmt.Println("\n11. Token operations summary...")
	fmt.Println("   Token info: client.Token.GetInfo(ctx)")
	fmt.Println("   Get balance: client.Token.GetBalance(ctx, did)")
	fmt.Println("   Get my balance: client.Token.GetMyBalance(ctx)")
	fmt.Println("   Get app balance: client.Token.GetAppBalance(ctx, appID)")
	fmt.Println("   Fee schedule: client.Token.GetFeeSchedule(ctx)")
	fmt.Println("   Estimate storage: client.Token.EstimateStorageFee(ctx, bytes)")
	fmt.Println("   Estimate query: client.Token.EstimateQueryFee(ctx, results)")
	fmt.Println("\n   Note: Token transfers require consensus transactions")
	fmt.Println("   Use the consensus.Client for transfer operations.")

	fmt.Println("\nToken operations example complete!")
}

func formatSize(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.0f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
