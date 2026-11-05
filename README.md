# Willow Go SDK

Official Go SDK for interacting with the Willow network - a decentralized data infrastructure protocol providing blockchain indexing and structured data storage. See [What the SDK verifies](#what-the-sdk-verifies) for what it checks itself.

## Installation

```bash
go get github.com/willow-network/willow-go
```

## Features

- **Identity Management**: DID generation and request signing
- **Data Operations**: Store data as signed transactions, read it, query it, and fetch its proofs
- **Subgrove Management**: Register and deregister subgroves as signed transactions
- **Token Operations**: Query balances and fee schedules
- **GraphQL Indexing**: Query indexed blockchain data (answers unverified)
- **File Storage**: Upload, download, list, and delete files with chunk Merkle verification
- **File Encryption**: XChaCha20-Poly1305 encryption/decryption for private files
- **Light Client**: Track a trusted CometBFT header (see Proofs and the light client)
- **GroveDB Proofs**: Decode GroveDB proofs and check their envelope (the
  `grovedb` package doesn't verify a proof: its hashing isn't grovedb's, and
  its verify functions are deprecated)

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
path, for which `willow.IsUnsupported(err)` is true; they are deprecated.

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

The SDK reads at most a set number of bytes of each HTTP answer (from the
API, the CometBFT RPC, an indexer, or a storage node), by route, and refuses
a longer one with an error that names the limit. A limit bounds the bytes
read, not the memory decoding them takes, which can be tens of times their
length (a list of empty JSON objects decoded into maps). So the SDK also
counts the JSON in an answer before decoding it, and refuses one that holds
more than 2,097,152 units (each string, number, `true`, `false`, or `null`
costs one, and each array or object eight) or nests deeper than 512 levels.
Measured, an answer under that limit decodes to at most about 80 MiB besides
the bytes of its strings. Honest answers hold far fewer: a SQL answer of
100,000 rows of 10 columns is under 1.9 million. The byte limits, by route,
hold the largest answer the node serves where the node bounds it:

- 4 MiB: answers of fixed shape or short lists: nonces, balances, token
  info, fees, validators, indexers, health, `/tx/submit`, DID documents and
  permissions, key grants, subgrove information, state roots, file
  manifests and file-list pages, ERC-8004 answers, and CometBFT's status,
  commit, validators, and ABCI queries. These answers are a few KB; 4 MiB
  is the chain's `max_tx_bytes`.
- 2 MiB: a file chunk, the most the storage node's upload route takes.
- 12 MiB: `Data.Get`, `Data.GetProof`, and `consensus.Client.GetTx`, which
  carry what one transaction holds (at most 4 MiB), a proof in hex and a
  transaction in base64.
- 32 MiB: `consensus.Client.GetBlock` and `GetLatestBlock` (a block of at
  most 21 MiB, its transactions in base64).
- 64 MiB: answers whose size the request sets, which the node doesn't cap:
  `Data.QueryUnverified` (a page of 100 documents, the default, of up to
  512 KiB each is 50 MiB), `Data.QueryHistorical`, GraphQL and SQL queries,
  `FetchMatchedLogs`, and `EthOperations`. Ask for less (a lower `Limit`,
  fewer slots) when an answer would be over it.

The HTTP clients the SDK makes time out after 30 s (`WithTimeout` sets the
client's, which `Files` also uses with the storage node, and
`consensus.ClientConfig.Timeout` the consensus client's), and the light
client's after `lightclient.Config.RPCTimeout` (10 s by default); a client
you pass (`WithHTTPClient`, `NewEthOperations`) is used as it is.

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
every field, nil lists as `[]`, a nil `Mode` as the chain's default
DataStorage, and other absent options as `null`, so the chain decodes the
values the hash covers. The SDK signs DataStorage and FileStorage
registrations; it refuses to sign a BlockchainIndexing one, whose mode its
types don't encode, and one the chain would refuse for its subgrove id, its
admins, writers, or free readers, its schema, or a private registration's
initial owner key grant (see Subgrove Management).

The key-grant builders and flows refuse what the chain refuses: a grant or
rotation to a grantee that isn't a DID, a rotation with no grants, and a
rotation with a grant whose `KeyEpoch` isn't the rotation's new epoch (the
block refuses that one after CheckTx admits it, and the refusal spends the
nonce).

Ed25519 signs the message's UTF-8 bytes. secp256k1 signs their Keccak-256
(low-S; the SDK sends DER, and the chain also accepts 64-byte compact r||s).

## Nonces

The chain accepts a nonce in `base+1 … base+24` that it hasn't used, where
`base` (the account nonce) advances only over used nonces with no gap below
them. The client keeps, per signing DID, the nonces it has handed out that
haven't landed (each held while a submission under it is in flight, and for
120 s, the longest the node holds a pending transaction's nonce, after CheckTx
accepts it or after it may have reached the node) and the nonces it has seen
used, and each write takes the lowest nonce in the window that is neither,
under a lock, so writes in flight together take distinct nonces. With
`WithRPCURL` it reads which nonces above the base are used from the ABCI query
`/store/account_nonce_state/{did}`; otherwise it reads the base from the
API's `/account/{did}/nonce`. With all 24 held, a write fails with an error
wrapping `willow.ErrNonceWindowFull` and sends nothing: wait for earlier
writes to land.

A write returns a `*willow.WriteResult` (`DID`, `Nonce`, `TxHash`) once
CheckTx accepts it. `client.WaitUntilLanded(ctx, did, nonce)` waits until the
chain shows the nonce used; writes in flight may land in any order, so send a
write that depends on another only after the first has landed. A write
refused in its block also uses its nonce (every kind the SDK sends except
DeregisterSubgrove, whose refusal leaves the nonce unused): read what it
wrote, or look its `TxHash` up with `consensus.Client.GetTx`, to know it took
effect. For a `*willow.WriteError` with `MayLand` set, read what the write
wrote: the API names no transaction hash for a submission that may have
landed. (A CheckTx refusal's hash is on the `*willow.TransactionError` the
`WriteError` wraps.) `client.GetAccountNonce` reads the account's nonce
state, and `client.NextNonce` hands out a nonce for a transaction the client
doesn't build (a file write's `FileSigningOptions.Nonce`, or one sent with
`consensus.Client.BroadcastTxSync`).

Set `WithRPCURL` (the CometBFT RPC endpoint) when writes run concurrently.
Without it the client reads only the base, which advances only over used
nonces with no gap below them: a write that landed above a nonce not yet used
(a write still pending, or one that never landed) doesn't show as landed, so
`WaitUntilLanded` waits for every earlier nonce and fails at the context's
deadline if one never lands. The client may also hand that write's nonce out
again once its 120 s hold lapses; a write then refused as used under it fails
with `willow.ErrNonceUsed` (see below).

```go
client, err := willow.NewClient("http://localhost:3031",
    willow.WithRPCURL("http://localhost:26657"))
```

A nonce stays held while a submission under it is in flight, however long
that takes. A refusal at CheckTx gives its nonce back, unless it is the
node's own error for that nonce saying it is held by a pending transaction
(the write fails and the nonce stays held) or already used, or at or below
the base (the write fails with `willow.ErrNonceUsed` and the nonce is marked
used). Text a refusal only quotes, such as the expected message a signature
mismatch repeats, says nothing about the nonce.

A write whose submission fails in transit (a network error or a 5xx) may
still land: its error is a `*willow.WriteError` with `MayLand` set, naming the
nonce. Send it again under that nonce with `willow.WithNonce`: whichever
attempt lands first uses the nonce and the other is refused, so the write
runs at most once.

```go
write, err := client.Data.StoreItem(ctx, "sg", "k", data)
var werr *willow.WriteError
if errors.As(err, &werr) && werr.MayLand {
    write, err = client.Data.StoreItem(ctx, "sg", "k", data, willow.WithNonce(werr.Nonce))
}
```

Under `WithNonce` the client sends nothing if the chain already shows the
nonce used, and doesn't sign the write again under another nonce if it is
refused as used; either way the error wraps `willow.ErrNonceUsed`: the
earlier attempt may have landed, so read what it wrote before sending the
write again without `WithNonce`. A refusal as held by a pending transaction,
or another `MayLand` error (also how the API reports CometBFT refusing a
transaction identical to one it has already seen), means the earlier attempt
may be pending: wait for the nonce. Sending the write again under a fresh
nonce while the earlier attempt is valid can run it twice. For the same
reason, a write refused as used, with or without `WithNonce`, fails with
`willow.ErrNonceUsed` and is never signed again under another nonce on its
own: the transaction that used the nonce may be this write (an API can
forward an attempt to the chain while answering that its nonce is used), so
read what it wrote before sending it again.

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

    // The latest block's app hash, as the API's CometBFT node reports it.
    // This is the API's value: the SDK doesn't verify it.
    appHash, err := client.GetLatestAppHash(ctx)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Latest app hash (unverified):", appHash)
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

`WithAPIKey` sets the managed tier's key. The client sends it (as
`X-API-Key`) only to the API URL and to the indexer named with
`WithIndexerURL`: never to an indexer it discovers from the API's
`/indexers` list, whose endpoint whoever registered it chooses, nor to the RPC
URL or a storage node. To send the key to an indexer, name it with
`WithIndexerURL`.

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
write, err := client.Data.StoreItem(ctx, "users", "user-123", map[string]interface{}{
    "name":  "Alice",
    "email": "alice@example.com",
})

// Wait for it to land before reading it back
err = client.WaitUntilLanded(ctx, write.DID, write.Nonce)

// Read the stored value (the API's data route carries no proof)
response, err := client.Data.Get(ctx, "users", "user-123")

// Fetch the key's GroveDB proof, with its path, key, and height (unverified)
proof, err := client.Data.GetProof(ctx, "users", "user-123")
```

`StoreItem` returns once the chain's CheckTx accepts the transaction; the
write is applied, or refused, in its block. Each item is its own transaction
under its own nonce, so up to 24 can be in flight per identity; set
`WithRPCURL` when they are, so `WaitUntilLanded` sees each one land (see
Nonces). The SDK doesn't build UpdateData or DeleteData transactions, so
`Data.Update` and `Data.Delete` return an unsupported error, as do
`Data.Store` (a StoreData needs a key) and `Data.BatchStore`.

### Querying Data

```go
query := willow.NewQueryBuilder().
    Equals("status", "active").
    SortDesc("created_at").
    Limit(10).
    Build()

response, err := client.Data.QueryUnverified(ctx, "users", query)
for _, result := range response.Results {
    fmt.Println(result.Data) // the matching documents, as the API returns them
}
```

The API's `/query` applies one equality filter, a sort on one field, a
limit, and an offset. The client refuses a query it wouldn't apply (more
filters, another operator, full-text search) instead of sending it.
`Data.Query` returns an unsupported error and sends nothing, because the SDK
can't verify a query's proof (see Proofs and the light client).

### Subgrove Management

```go
// Create a schema using builder
schema := willow.NewSchemaBuilder("User").
    Description("User profile schema").
    StringField("name", true).
    StringField("email", true).
    IntField("age", false).
    Build()

// Register a DataStorage subgrove owned by the identity: a RegisterSubgrove
// transaction signed over FormatRegisterSubgroveMessage
subgroveReq := willow.NewSubgroveBuilder("users", "Users").
    Description("User profiles").
    Schema(*schema).
    Owner(identity.DID()).
    AddWriter(identity.DID()).
    Build()

write, err := client.Registration.RegisterSubgrove(ctx, subgroveReq)

// The subgrove exists once the registration lands
err = client.WaitUntilLanded(ctx, write.DID, write.Nonce)

// Deregister it (a DeregisterSubgrove transaction; the chain refunds its balance)
_, err = client.Registration.DeleteSubgrove(ctx, "users")
```

The schema is sent in the chain's form (`SchemaDefinition.ChainSchemaJSON`):
a map of field name to type (`string`, `number`, `boolean`, `array`,
`object`, `bytes`) and the required fields; its name and description label
it in the SDK and are not sent. The chain refuses a DataStorage or FileStorage
registration whose subgrove id isn't 1 to 64 ASCII letters, digits, `-`, or
`_` starting with a letter or digit; whose admins, writers, or free readers
aren't DIDs (`did:willow:` then ASCII letters, digits, `-`, or `_`, at most
128 bytes); whose schema doesn't parse as its schema definition (`version` a
u32, `fields` a map of name to one of the six types, `indexes`, and
`required_fields` a list of names; each optional, unknown keys ignored) or
declares indexes; and a private DataStorage registration whose
`InitialOwnerKeyGrant` isn't key epoch 0 to the owner. The SDK refuses each
before signing with a validation error (an index is one added with the schema
builder's index methods, or a field marked indexed). For a
FileStorage or private registration, read pricing, admins, or initial funding,
build a `consensus.RegisterSubgroveTx` and sign it (a nil `Mode` is sent as
the chain's default, an empty DataStorage):

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
    Nonce:       nonce, // from client.NextNonce(ctx, identity.DID())
}
message, err := willow.FormatRegisterSubgroveMessage(tx)
tx.Signature, err = identity.Sign([]byte(message))
result, err := consensusClient.BroadcastTxSync(ctx, map[string]interface{}{"RegisterSubgrove": tx})
```

### GraphQL Queries

```go
// Execute a GraphQL query; the answer is returned unverified
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
query := willow.NewGraphQLQuery(`query Pools($first: Int!) { pools(first: $first) { id } }`).
    Variable("first", 100).
    Build()

response, err = client.Indexing.QueryUnverified(ctx, "uniswap-v3", query)

// Execute and unmarshal the answer's data directly
var result struct {
    Swaps []struct {
        ID        string `json:"id"`
        Timestamp int64  `json:"timestamp"`
    } `json:"swaps"`
}

err = client.Indexing.ExecuteWithResult(ctx, "uniswap-v3",
    `query GetSwaps($first: Int!) { swaps(first: $first) { id timestamp } }`,
    map[string]interface{}{"first": 10},
    &result,
)
```

`Execute`, `ExecuteWithResult`, and `QueryUnverified` ask for no proof and
return the answer as the API (or, with `WithIndexerURL`, the indexer) sends
it. `GraphQLQueryWithSource` asks for a proof only when the request sets
`IncludeProof`, and returns it unverified, as the answer's JSON, in
`GraphQLResponse.Proof`. `Indexing.Query` returns an unsupported error and
sends nothing, because the SDK can't verify a GraphQL answer (see What the
SDK verifies).

### Proofs and the light client

A proof the API returns (from `Data.GetProof`, or with a query) is of the
state after block `Height`, so its root is the `app_hash` of the CometBFT
header at `Height+1`. Checking it takes that header verified against the
validators' commit signatures, a GroveDB verifier that reproduces the chain's
root for the proof, and, for a query, the returned documents matched to the
values the proof proves. The SDK doesn't provide these, so `Data.Query` and
`Data.VerifyProof` return an unsupported error (`willow.IsUnsupported`)
instead of presenting data as verified, and `Data.QueryUnverified` and
`Data.GetProof` return what the API sends, unverified.

The `lightclient` package keeps a trusted CometBFT header. Its
`VerifyHeader` checks a later header's chain id, height and time, the
trusting period, clock drift, an adjacent header's validator-set hash, and
the voting power its commit lists, counted from the validator set the block
itself carries; it does not verify the commit signatures, or tie that
validator set to the header, so a header anyone can build passes. The
result's `ChecksPassed` says only that those checks passed (`Verified`, the
same value, is deprecated).

```go
import "github.com/willow-network/willow-go/lightclient"

lc, err := lightclient.NewLightClient(lightclient.Config{
    ChainID:            "willow-mainnet",
    ValidatorEndpoints: []string{"http://validator1:26657"},
    TrustingPeriod:     24 * time.Hour,
})

// Pin a header you trust, then read it back
err = lc.InitializeWithTrustedHeader(trustedBlock)
header, err := lc.GetLatestTrustedHeader()
fmt.Println(header.Height, header.AppHash)
```

`lc.GetLatestAppHash` returns that header's app hash (`GetVerifiedRootHash`
is a deprecated alias): it is as trustworthy as the header pinned, or the
endpoints the light client took it from, not verified against the validators.

### What the SDK verifies

- Nothing read from the chain's state is verified: the SDK verifies no
  CometBFT header (`VerifyHeader` doesn't check commit signatures) and has no
  GroveDB verifier that binds data to the chain's root. So `Data.Query`,
  `Data.VerifyProof`, `Data.QueryHistoricalVerified` (deprecated), and
  `Indexing.Query` return an unsupported error and send nothing, and every
  other read (`Data.Get`, `Data.QueryUnverified`, `Data.GetProof`,
  `Data.QueryHistorical`, GraphQL and SQL queries, `GetLatestAppHash`)
  returns what it is sent, unverified.
- Block completeness: `VerifyBlockCompleteness` re-hashes an indexer's
  matched logs and compares them with the block's events commitment. It
  doesn't trust the indexer, but it trusts the RPC node it reads the
  commitment from: that ABCI answer carries no proof. That node is the one
  `WithRPCURL` names; without it, it is the API's host (the API URL with
  `:3031` replaced by `:26657`), or the API URL itself when it has no
  `:3031`, so the check trusts the API's operator. An answer for another
  subgrove or block than the one asked for is an error.
- Ethereum state reads (`EthOperations`): the indexer's answer carries the
  block's state root and MPT proofs of the account and slot values under it.
  The SDK requires the proof to be for the address, block, and slots asked
  for (in order), and in `EthWalkProofs` mode (the default) walks it, but it
  has no trusted source of Ethereum block headers, so it can't check that the
  root is Ethereum's: every result is the indexer's claim. A zero slot value
  is proved by the slot's absence from the storage trie, and an account that
  doesn't exist by its absence from the state trie (it reads as empty).
  `Erc20Balance` refuses a token address with no contract (no account, or no
  code), but can't tell a wrong balance slot, which reads as zero. An
  `eth_call`'s result is bound by no proof.
- File downloads: `Files.Download` checks the chunks against the manifest's
  chunk Merkle root and content hash, with the manifest as the API sends it,
  unverified.

### Consensus Client

```go
import "github.com/willow-network/willow-go/consensus"

// Create consensus client: BroadcastTxSync sends to the API's /tx/submit,
// so it needs APIURL; RPCURL is for the CometBFT reads (GetTx, GetBlock, ...)
consensusClient := consensus.NewClient(consensus.ClientConfig{
    RPCURL:  "http://localhost:26657",
    APIURL:  "http://localhost:3031",
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

// Look a transaction up by its hash once it is in a block (the hex hash is
// sent to CometBFT as base64 of its bytes): Status is not_found until then,
// and Code and Log are its block's result.
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
# Basic usage - DID generation, signed requests, storing and reading data
go run ./examples/basic_usage

# Data operations - storing, reading, and querying data, and the writes this
# SDK doesn't build (update, delete), which return an unsupported error
go run ./examples/data_operations

# Light client - a trusted CometBFT header, and what the SDK verifies
go run ./examples/light_client

# Registration - DID generation, listing, reading, and registering subgroves
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
