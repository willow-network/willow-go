// Package httpbody reads HTTP answers under a cap on their size, one per kind
// of answer.
//
// A cap bounds the bytes the SDK reads of one answer, not the memory decoding
// them takes: Go's JSON decoder builds a value for each element it reads, so
// a few bytes of JSON (an empty object or array in a list) can take tens to
// hundreds of bytes once decoded. An answer at a cap can take a multiple of
// the cap in memory: measured, a list of empty objects decoded into maps keeps
// about 19 times its length, and decoding a list of empty arrays into
// interface{} values allocates about 40 times it.
//
// Each cap is the smallest that holds the largest honest answer of its routes
// where the node bounds that answer; where the request sets an answer's size
// (a query's limit, the slots asked for) and the node sets no maximum, the
// cap is Large, and an answer past it is refused: ask for less.
package httpbody

import (
	"errors"
	"fmt"
	"io"
)

const (
	// Small caps an answer of fixed shape, or a list the node keeps short:
	// an account's nonce, a balance, the token's info, the fee schedule,
	// validators, indexers, the health check, a /tx/submit answer, a DID
	// document and its permissions, key grants, subgrove information, state
	// roots, a file manifest or a page of the file list (at most 100
	// files), ERC-8004 answers (at most 100 entries), and CometBFT's status,
	// commit, validators (at most 100 a page), and ABCI queries. These
	// answers are a few KB; 4 MiB is the chain's max_tx_bytes, the most one
	// transaction writes. The subgrove, validator, and indexer lists aren't
	// paged, so they grow with the chain: a subgrove's entry is about 1 KB
	// unless its schema is long, so 4 MiB holds thousands.
	Small = 4 << 20
	// Chunk caps a file chunk: the storage node's upload route takes a body
	// of at most 2 MiB (axum's default body limit), so it stores no longer
	// chunk.
	Chunk = 2 << 20
	// Tx caps an answer that carries what one transaction holds: CometBFT's
	// /tx (a transaction of at most max_tx_bytes, 4 MiB, is 5.4 MiB in
	// base64, with its result beside it), and the API's /data value and
	// /proof of a key. A value is at most what one transaction writes
	// (max_data_payload_bytes, 512 KiB, for StoreData; under 4 MiB for any),
	// and a proof carries it in hex, twice its length, beside the hashes on
	// its path: 8 MiB and some KB for a 4 MiB value.
	Tx = 12 << 20
	// Block caps CometBFT's /block: a block of at most block.max_bytes, 21
	// MiB, carries its transactions in base64, 28 MiB, with its header and
	// last commit.
	Block = 32 << 20
	// Large caps an answer whose size the request sets, with no maximum on
	// the node: a /query page (100 documents unless the query sets a limit,
	// each at most max_data_payload_bytes, 512 KiB: 50 MiB), GraphQL and SQL
	// answers, a historical query, a block's matched logs, and Ethereum state
	// and call answers (proofs of as many slots as asked for, or as the call
	// touched).
	Large = 64 << 20
)

// ErrTooLarge is what reading past an answer's cap returns, as a
// *TooLargeError naming the cap (errors.Is(err, ErrTooLarge)).
var ErrTooLarge = errors.New("the answer is over the SDK's limit")

// TooLargeError is an answer longer than Limit bytes, the cap of its route.
type TooLargeError struct {
	Limit int64
}

func (e *TooLargeError) Error() string {
	return fmt.Sprintf("the answer is over the SDK's %d MiB limit for its route", e.Limit>>20)
}

// Is reports whether target is ErrTooLarge.
func (e *TooLargeError) Is(target error) bool {
	return target == ErrTooLarge
}

// Reader reads r, but returns a *TooLargeError in place of any byte past
// limit.
func Reader(r io.Reader, limit int64) io.Reader {
	return &capped{r: io.LimitReader(r, limit+1), limit: limit}
}

// ReadAll reads r to its end, refusing more than limit bytes with a
// *TooLargeError.
func ReadAll(r io.Reader, limit int64) ([]byte, error) {
	return io.ReadAll(Reader(r, limit))
}

type capped struct {
	r     io.Reader // limited to limit+1 bytes
	limit int64
	read  int64
}

// Read returns the bytes up to the limit, and a *TooLargeError once the
// answer passes it; a read after that returns no bytes and the error again.
func (c *capped) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read += int64(n)
	if over := c.read - c.limit; over > 0 {
		return max(n-int(over), 0), &TooLargeError{Limit: c.limit}
	}
	return n, err
}
