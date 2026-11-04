# Willow Go SDK

Official Go SDK for interacting with the Willow network - a decentralized data infrastructure protocol providing blockchain indexing and structured data storage with cryptographic proof verification.

## Installation

```bash
go get github.com/willow-network/willow-go
```

## Features

- **Identity Management**: DID generation and request signing
- **Data Operations**: Store data as signed transactions, read it, and fetch and verify its proofs
- **Subgrove Management**: Register and deregister subgroves as signed transactions
- **Token Operations**: Query balances and fee schedules
- **GraphQL Indexing**: Query indexed blockchain data
- **File Storage**: Upload, download, list, and delete files with chunk Merkle verification
- **File Encryption**: XChaCha20-Poly1305 encryption/decryption for private files
- **Light Client**: Trustless verification using CometBFT light client
- **GroveDB Proofs**: Cryptographic proof verification for all queries

## Transaction submission

Transactions submitted through this SDK go to the API server's
`POST /tx/submit` endpoint. The server accepts the JSON-encoded
transaction, bincode-encodes it (the chain's on-the-wire format), and
forwards to CometBFT's `broadcast_tx_sync`. `APIURL` is therefore
**required** whenever you submit a tx; `RPCURL` is only used for
read-only RPC queries (status, block, validators) and may be omitted
or pointed at the same endpoint.

`BroadcastTxAsync` and `BroadcastTxCommit` were removed from
`consensus.Client` — `/tx/submit` only exposes sync semantics.
Callers that need fire-and-forget or wait-for-commit should layer
that on top of `BroadcastTxSync` + `GetTx` polling.

Every write is a transaction: the API serves no REST route that writes data,
subgroves, DIDs, or permissions. The write methods this SDK builds no
transaction for (`RegisterDID`, `Data.Store`, `Data.Update`, `Data.Delete`,
`Data.BatchStore`, `Registration.UpdateSubgrove`, `GrantPermission`, and
`RevokePermission`) send nothing and return an error naming the supported
path, for which `willow.IsUnsupported(err)` is true.

## API responses

Most API routes answer `{"success": bool, "data": ..., "error": ...}`. The
client returns `data`, decoded into the method's result, and turns
`success: false` into an error carrying the API's message, with a 2xx status
or a 4xx one (`willow.IsNotFound(err)` for a missing key, DID, or subgrove);
a 5xx answer is retried, then reported by its status.
`/health`, `/graphql`, `/sql`, `/files`, and `/historical/query` answer with
their result directly. u128 amounts (balances, stakes, fees, supplies) arrive
as JSON numbers beyond 64 bits and are read exactly: as `consensus.Uint128`,
or as decimal strings in `TokenInfo` and `FeeSchedule`.

## Signed transactions

The kinds below are signed over a message of lines joined by `\n` (no
trailing newline): the kind first, then `Label: value` lines binding every
field the transaction writes, the nonce last. Numbers are unsigned decimal
and bytes lowercase hex. A signed text field can't hold a line break or
invalid UTF-8: the builders return a validation error instead. The nonce in
the message is the nonce the transaction carries, so a message is built after
the nonce is chosen and a retry under another nonce is signed anew. A write
refused in its block after its signature and nonce verify still spends that
nonce. (RevokeSubgroveKey and DeregisterSubgrove sign
`RevokeSubgroveKey:<subgrove>:<revokee>:<sender>:<nonce>` and
`DeregisterSubgrove:<subgrove>:<owner>:<nonce>`, which bind every field.)

The client's write methods take the nonce one past the account nonce at
`/account/{did}/nonce`. Until a write lands, the next write would take the
same nonce, which the chain holds for the pending transaction, so a DID's
writes go one at a time, each after the previous has landed. To have several
in flight, sign them under distinct unused nonces from the account's window
(up to 24 above the account nonce) and send them with
`consensus.Client.BroadcastTxSync`.

| Kind | Builder | Lines after the kind |
|---|---|---|
| StoreData | `FormatDataStoreMessage` | `Subgrove`, `Key`, `Owner`, `DataHash` (SHA-256 of the data bytes sent), `Nonce` |
| StoreFileManifest | `FormatStoreFileManifestMessage` | `Subgrove`, `Key`, `Owner`, `Filename`, `ContentType`, `TotalSize`, `ContentHash`, `ChunkCount`, `ChunkSize`, `ChunkMerkleRoot`, `Encryption`, `Nonce` |
| DeleteFileManifest | `FormatDeleteFileManifestMessage` | `Subgrove`, `Key`, `Owner`, `Nonce` |
| RegisterSubgrove | `FormatRegisterSubgroveMessage` | `Subgrove`, `Owner`, `Config`, `Nonce` |
| GrantSubgroveKey | `FormatGrantSubgroveKeyMessage` | `Subgrove`, `Sender`, the grant's `Grantee`, `GranteeKey`, `KeyEpoch`, `EphemeralKey`, `EncryptedKey`, `GrantedBy`, `GrantedAt`, `Nonce` |
| RotateSubgroveKey | `FormatRotateSubgroveKeyMessage` | `Subgrove`, `Sender`, `NewEpoch`, `Grants` (the count), each grant's seven lines in order, `Nonce` |
| UnregisterStorageNode | `FormatUnregisterStorageNodeMessage` | `Node`, `Nonce` |

A RegisterSubgrove's `Config` is the hex SHA-256 of the registration's
bincode (bincode 1.x: fixed-width little-endian integers, u64 lengths) with
an empty signature, so it binds every field: `consensus.RegisterSubgroveUnsignedBincode`
computes it from the exact JSON sent. `consensus.RegisterSubgroveTx` sends
every field, nil lists as `[]` and absent options as `null`, so the chain
decodes the values the hash covers. The SDK signs DataStorage and FileStorage
registrations; it refuses to sign a BlockchainIndexing one, whose mode its
types don't encode.

Ed25519 signs the message's UTF-8 bytes. secp256k1 signs their Keccak-256
(low-S; the SDK sends DER, and the chain also accepts 64-byte compact r||s).

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

    // Willow DIDs are self-certifying: the id is derived from the public key
    // as did:willow:z<base58btc(SHA3-256(multicodec_prefix || public_key))>.
    // A DID is registered on chain by a RegisterDid transaction, which this
    // SDK does not build; it must be funded first, since the fee is paid from
    // its own balance.
    fmt.Printf("Generated DID: %s\n", identity.DID())

    // Set identity for per-request signing
    client.SetIdentity(identity)

    // Read the chain's state root
    root, err := client.GetVerifiedRootHash(ctx)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Verified root hash:", root)
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

// Read a registered DID's document
info, err := client.GetDID(ctx, identity.DID())

// Set identity for per-request signing
client.SetIdentity(identity)

// Check if identity is set
if client.HasIdentity() {
    fmt.Println("Identity is set, requests will be signed")
}
```

### Request Signing

With an identity set, the client signs each read of subgrove data it sends to the API (`GET /data/{sg}/{key}`, `GET /proof/{sg}/{key}`, the key-grant reads under `/key-grants` and `/proof/key-grant`, and `POST /query`, `/sql`, and `/graphql`) with a one-time nonce over the whole request. Only this form carries the DID's read rights: a Reader permission on a subgrove, or a place on a priced subgrove's free-reader list. Other requests it signs use the older form below, which the server also accepts in the first 30 s after it restarts, when it refuses nonce-signed requests.

The headers are `X-DID`, `X-Public-Key-ID`, `X-Signature`, `X-Timestamp`, and `X-Nonce`. The signature is over eight lines:

```
willow-request-v2
<DID>
<public key id>
<METHOD>
<path and query, exactly as sent>
<Unix timestamp>
<nonce>
<hex SHA-256 of the body>
```

- The server accepts a timestamp up to 300 s old and 30 s ahead of its clock, and each (DID, nonce) once. The client signs each retry with a new nonce.
- A nonce is 16 to 128 characters of `A-Z a-z 0-9 - _`. `NewRequestNonce` makes one of 32 hex characters.
- Ed25519 signatures are sent as hex. secp256k1 signatures are over the Keccak-256 of the message and are sent as `0x`-prefixed hex.
- Requests sent to an indexer (`WithIndexerURL`) are not signed this way.

To sign a request you send yourself:

```go
headers, err := identity.SignRequestWithNonce("POST", "/query/my-subgrove", body)
```

`identity.SignRequest(method, path)` makes the older `{METHOD}:{PATH}:{TIMESTAMP}` form, over the path without its query string. It proves the DID but carries none of its read rights, and it can be replayed with any body until the timestamp expires.

### Data Operations

```go
// Store an object under a key: a StoreData transaction signed by the
// identity, carrying the object's JSON text as bytes
err := client.Data.StoreItem(ctx, "users", "user-123", map[string]interface{}{
    "name":  "Alice",
    "email": "alice@example.com",
})

// Read the stored value (the API's data route carries no proof)
response, err := client.Data.Get(ctx, "users", "user-123")

// Fetch the key's GroveDB proof; VerifyProof checks its root against the
// light client's trusted app hash
proof, err := client.Data.GetProof(ctx, "users", "user-123")
err = client.Data.VerifyProof(ctx, proof)
```

`StoreItem` returns once the chain's CheckTx accepts the transaction; the
write is applied, or refused, in its block. Each item is its own transaction,
sent after the previous one has landed (see Signed transactions). The SDK
doesn't build UpdateData or DeleteData
transactions, so `Data.Update` and `Data.Delete` return an unsupported
error, as do `Data.Store` (a StoreData needs a key) and `Data.BatchStore`.

### Querying Data

```go
query := willow.NewQueryBuilder().
    Equals("status", "active").
    SortDesc("created_at").
    Limit(10).
    Build()

response, err := client.Data.Query(ctx, "users", query)
for _, result := range response.Results {
    fmt.Println(result.Data) // the matching documents
}
```

The API's `/query` applies one equality filter, a sort on one field, a
limit, and an offset. The client refuses a query it wouldn't apply (more
filters, another operator, full-text search) instead of sending it.

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

// Register a DataStorage subgrove owned by the identity: a RegisterSubgrove
// transaction signed over FormatRegisterSubgroveMessage
subgroveReq := willow.NewSubgroveBuilder("users", "Users").
    Description("User profiles").
    Schema(*schema).
    Owner(identity.DID()).
    AddWriter(identity.DID()).
    Build()

subgrove, err := client.Registration.RegisterSubgrove(ctx, subgroveReq)

// Deregister it (a DeregisterSubgrove transaction; the chain refunds its balance)
err = client.Registration.DeleteSubgrove(ctx, "users")
```

The schema is sent in the chain's form (`SchemaDefinition.ChainSchemaJSON`):
a map of field name to type (`string`, `number`, `boolean`, `array`,
`object`, `bytes`), the required fields, and indexes with their fields and
uniqueness. For a FileStorage or private registration, read pricing, admins,
or initial funding, build a `consensus.RegisterSubgroveTx` and sign it:

```go
tx := &consensus.RegisterSubgroveTx{
    SubgroveID:  "files-1",
    Name:        "Files",
    Schema:      `{"version":1,"fields":{},"indexes":[],"required_fields":[]}`,
    OwnerDid:    identity.DID(),
    Mode: &consensus.SubgroveMode{FileStorage: &consensus.SubgroveFileStorage{
        Name: "Files", MaxFileSize: 100 << 20, ReplicationFactor: 3,
        Writers: []string{identity.DID()},
    }},
    PublicKeyID: identity.PublicKeyID(),
    Nonce:       nonce, // one past the account nonce at /account/{did}/nonce
}
message, err := willow.FormatRegisterSubgroveMessage(tx)
tx.Signature, err = identity.Sign([]byte(message))
result, err := consensusClient.BroadcastTxSync(ctx, map[string]interface{}{"RegisterSubgrove": tx})
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

// Query and VerifyProof check a proof's root against the light client's
// trusted app hash
proof, err := client.Data.GetProof(ctx, "users", "user-123")
err = client.Data.VerifyProof(ctx, proof)
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

// Get balance (u128 amounts in the smallest unit, read exactly)
balance, err := client.Token.GetBalance(ctx, identity.DID())
fmt.Printf("Available: %s, staked: %s\n", balance.Available, balance.Staked)

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
    } else if willow.IsUnsupported(err) {
        fmt.Println(err) // names the supported path
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
