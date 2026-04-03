# Willow Go SDK

Official Go SDK for interacting with the Willow network - a decentralized data infrastructure protocol providing blockchain indexing and structured data storage with cryptographic proof verification.

## Installation

```bash
go get github.com/willow-network/willow-go
```

## Features

- **Identity Management**: DID generation, registration, and authentication
- **Data Operations**: Store, retrieve, update, and delete data with proof verification
- **Subgrove Management**: Register and manage subgroves
- **Token Operations**: Query balances and fee schedules
- **GraphQL Indexing**: Query indexed blockchain data
- **File Storage**: Upload, download, list, and delete files with chunk Merkle verification
- **File Encryption**: XChaCha20-Poly1305 encryption/decryption for private files
- **Light Client**: Trustless verification using CometBFT light client
- **GroveDB Proofs**: Cryptographic proof verification for all queries

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"

    willow "github.com/willow-network/willow-go"
)

func main() {
    ctx := context.Background()

    // Create a new client
    client, err := willow.NewClient("http://localhost:3031")
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    // Generate a new identity
    identity, err := willow.NewIdentity(willow.Ed25519)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Generated DID: %s\n", identity.DID())

    // Register the DID
    _, err = client.RegisterDID(ctx, identity.DidDocument)
    if err != nil {
        log.Fatal(err)
    }

    // Set identity for per-request signing
    client.SetIdentity(identity)

    fmt.Println("Identity set, requests will be signed automatically")
}
```

## Usage Examples

### Creating a Client

```go
// Simple client
client, err := willow.NewClient("http://localhost:3031")

// With options
client, err := willow.NewClient("http://localhost:3031",
    willow.WithTimeout(60 * time.Second),
    willow.WithRetryConfig(willow.RetryConfig{
        MaxRetries:     5,
        InitialBackoff: 200 * time.Millisecond,
        MaxBackoff:     10 * time.Second,
        BackoffFactor:  2.0,
    }),
)

// Using builder pattern
client, err := willow.Builder("http://localhost:3031").
    WithTimeout(30 * time.Second).
    Build()
```

### Identity Management

```go
// Generate Ed25519 identity
identity, err := willow.NewIdentity(willow.Ed25519)

// Generate secp256k1 identity
identity, err := willow.NewIdentity(willow.Secp256k1)

// Restore from private key
identity, err := willow.IdentityFromPrivateKey(willow.Ed25519, privateKeyHex)

// Register DID
doc, err := client.RegisterDID(ctx, identity.DidDocument)

// Set identity for per-request signing
client.SetIdentity(identity)

// Check if identity is set
if client.HasIdentity() {
    fmt.Println("Identity is set, requests will be signed")
}
```

### Data Operations

```go
// Store data
err := client.Data.Store(ctx, "users", map[string]interface{}{
    "name":  "Alice",
    "email": "alice@example.com",
})

// Store with specific key
err := client.Data.StoreItem(ctx, "users", "user-123", data)

// Get data (with automatic proof verification if light client enabled)
response, err := client.Data.Get(ctx, "users", "user-123")

// Get without verification (faster)
response, err := client.Data.GetUnverified(ctx, "users", "user-123")

// Update data
err := client.Data.Update(ctx, "users", "user-123", updatedData)

// Delete data
err := client.Data.Delete(ctx, "users", "user-123")

// Batch store
items := []willow.StoreRequest{
    {Key: "user-1", Data: user1Data},
    {Key: "user-2", Data: user2Data},
}
err := client.Data.BatchStore(ctx, "users", items)
```

### Querying Data

```go
// Using query builder
query := willow.NewQueryBuilder().
    Equals("status", "active").
    GreaterThan("age", 18).
    SortDesc("created_at").
    Limit(10).
    Build()

response, err := client.Data.Query(ctx, "users", query)

// Full-text search
query := willow.NewQueryBuilder().
    Search([]string{"name", "bio"}, "developer").
    Build()

response, err := client.Data.Query(ctx, "users", query)
```

### Subgrove Management

```go
// Create a schema using builder
schema := willow.NewSchemaBuilder("User").
    Description("User profile schema").
    StringField("name", true).
    StringField("email", true).
    IntField("age", false).
    HashIndex("email_idx", []string{"email"}).
    Build()

// Register a subgrove
subgroveReq := willow.NewSubgroveBuilder("users", "Users").
    Description("User profiles").
    Schema(*schema).
    Owner(identity.DID()).
    Build()

subgrove, err := client.Registration.RegisterSubgrove(ctx, subgroveReq)
```

### GraphQL Queries

```go
// Execute a GraphQL query
response, err := client.Indexing.Execute(ctx, "uniswap-v3",
    `query GetSwaps($first: Int!) {
        swaps(first: $first, orderBy: timestamp, orderDirection: desc) {
            id
            timestamp
            amountUSD
            token0 { symbol }
            token1 { symbol }
        }
    }`,
    map[string]interface{}{"first": 10},
)

// Using query builder
query := willow.NewGraphQLQuery(`query { pools { id } }`).
    Variable("first", 100).
    IncludeProof().
    Build()

response, err := client.Indexing.Query(ctx, "uniswap-v3", query)

// Execute and unmarshal directly
var result struct {
    Swaps []struct {
        ID        string `json:"id"`
        Timestamp int64  `json:"timestamp"`
    } `json:"swaps"`
}

err := client.Indexing.ExecuteWithResult(ctx, "uniswap-v3", query, vars, &result)
```

### Light Client for Trustless Verification

```go
import "github.com/willow-network/willow-go/lightclient"

// Create light client
lc, err := lightclient.NewLightClient(lightclient.Config{
    ChainID:            "willow-mainnet",
    ValidatorEndpoints: []string{
        "http://validator1:26657",
        "http://validator2:26657",
    },
    TrustingPeriod: 24 * time.Hour,
    AutoSync:       true,
})

// Start background sync
lc.Start()
defer lc.Stop()

// Create client with light client
client, err := willow.NewClient("http://localhost:3031",
    willow.WithLightClient(lc),
)

// Now all Get/Query operations automatically verify proofs!
response, err := client.Data.Get(ctx, "users", "user-123")
// Proof is verified against the light client's trusted state
```

### Consensus Client

```go
import "github.com/willow-network/willow-go/consensus"

// Create consensus client
consensusClient := consensus.NewClient(consensus.ClientConfig{
    RPCURL:  "http://localhost:26657",
    Timeout: 30 * time.Second,
})

// Broadcast transaction
tx := consensus.TransferTx{
    FromDid: identity.DID(),
    ToDid:   "did:willow:Ed25519:...",
    Amount:  1000,
    // ... signature fields
}

result, err := consensusClient.BroadcastTxSync(ctx, map[string]interface{}{
    "Transfer": tx,
})

// Query transaction
txResult, err := consensusClient.GetTx(ctx, result.TxHash)
```

### Token Operations

```go
// Get token info
info, err := client.Token.GetInfo(ctx)
fmt.Printf("Token: %s (%s)\n", info.Name, info.Symbol)

// Get balance
balance, err := client.Token.GetBalance(ctx, identity.DID())
fmt.Printf("Balance: %d\n", balance.Balance)

// Get fee schedule
fees, err := client.Token.GetFeeSchedule(ctx)
fmt.Printf("Base TX cost: %s wei\n", fees.BaseTxCost)
fmt.Printf("Cost per byte: %s wei\n", fees.CostPerByte)

// Estimate fees
storageFee, err := client.Token.EstimateStorageFee(ctx, 1024) // 1KB write
```

## Error Handling

```go
response, err := client.Data.Get(ctx, "users", "user-123")
if err != nil {
    // Check error types
    if willow.IsNotFound(err) {
        fmt.Println("User not found")
    } else if willow.IsNotAuthenticated(err) {
        fmt.Println("Please call SetIdentity() first")
    } else if statusCode, ok := willow.IsHTTPError(err); ok {
        fmt.Printf("HTTP error: %d\n", statusCode)
    } else {
        fmt.Printf("Error: %v\n", err)
    }
}
```

## Configuration

### Environment Variables

The SDK respects these environment variables:

- `WILLOW_API_URL`: Default API URL
- `WILLOW_RPC_URL`: Default CometBFT RPC URL
- `WILLOW_CHAIN_ID`: Default chain ID

### Retry Configuration

```go
config := willow.RetryConfig{
    MaxRetries:     3,                   // Maximum retry attempts
    InitialBackoff: 100 * time.Millisecond, // Initial backoff duration
    MaxBackoff:     5 * time.Second,     // Maximum backoff duration
    BackoffFactor:  2.0,                 // Backoff multiplier
}

client, err := willow.NewClient(url, willow.WithRetryConfig(config))
```

## Examples

The SDK includes several examples demonstrating common use cases:

```bash
# Basic usage - DID generation, authentication, data storage
go run ./examples/basic_usage

# Data operations - CRUD, queries, batch operations
go run ./examples/data_operations

# Light client - Trustless verification with multiple validators
go run ./examples/light_client

# Registration - DIDs, subgroves
go run ./examples/registration

# GraphQL indexing - Query indexed blockchain data
go run ./examples/graphql_indexing

# Token operations - Balances, fees, validators
go run ./examples/token_operations
```

## Testing

```bash
# Run tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run integration tests (requires running node)
go test -tags=integration ./...
```

## License

MIT License - see LICENSE file for details.
