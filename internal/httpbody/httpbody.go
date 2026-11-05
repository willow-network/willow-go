// Package httpbody reads HTTP answers under a cap on their size, one per kind
// of answer, and refuses to decode one that holds more JSON than the SDK
// decodes.
//
// A cap bounds the bytes the SDK reads of one answer, not the memory decoding
// them takes: Go's JSON decoder builds a value for each element it reads, so
// a few bytes of JSON (an empty object or array in a list) can take tens to
// hundreds of bytes once decoded. So before decoding an answer the SDK counts
// what it holds (see CheckJSON): at most MaxValues units, each string, number,
// true, false, or null costing one and each array or object ContainerCost,
// nested at most MaxDepth deep. Measured, JSON decoded into interface{}
// values, maps, or the SDK's types keeps at most about 40 bytes per unit
// besides the bytes of its strings (decoding allocates up to about three
// times that on the way), so an answer under the limit decodes to at most
// about 80 MiB besides them.
//
// A cap holds the largest answer the node serves on a route where the node
// bounds it. Some answers have no bound on the node: the lists that aren't
// paged (subgroves, validators, indexers, a subgrove's key grants, a DID's
// permissions) and DID documents grow with the chain, and a query, a SQL or
// GraphQL answer, an Ethereum call's proofs, or a historical answer is as
// large as the request makes it. An answer past its cap or the value limit is
// refused: ask for less (a lower limit, a narrower query, fewer slots).
package httpbody

import (
	"encoding/json"
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
	// /tx (a transaction of at most max_tx_bytes, 4 MiB, is 5.33 MiB in
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
// *TooLargeError naming the cap, and what decoding an answer that holds more
// JSON than the SDK decodes returns, as a *TooMuchJSONError (errors.Is(err,
// ErrTooLarge)).
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

const (
	// MaxValues is the most JSON the SDK decodes of one answer, in units:
	// each string, number, true, false, or null costs one, and each array or
	// object ContainerCost. An honest answer holds far fewer: a page of 100
	// documents of 10 fields is under 3,000, and a SQL answer of 100,000 rows
	// of 10 columns under 1.9 million.
	MaxValues = 1 << 21
	// ContainerCost is what an array or object costs: decoded, one takes
	// several times what a number or a short string takes (a map, about 340
	// bytes with its first member).
	ContainerCost = 8
	// MaxDepth is the deepest the SDK decodes JSON nested. The node's JSON
	// parser refuses a document nested deeper than 128.
	MaxDepth = 512
)

// TooMuchJSONError is an answer that holds more JSON than the SDK decodes:
// past MaxValues units, or nested deeper than MaxDepth.
type TooMuchJSONError struct {
	// Depth is true when the answer nests too deep, false when it holds
	// too many values.
	Depth bool
}

func (e *TooMuchJSONError) Error() string {
	if e.Depth {
		return fmt.Sprintf("the answer nests JSON deeper than the SDK decodes (%d levels)", MaxDepth)
	}
	return fmt.Sprintf("the answer holds more JSON values than the SDK decodes (%d, an array or object counting %d)",
		MaxValues, ContainerCost)
}

// Is reports whether target is ErrTooLarge.
func (e *TooMuchJSONError) Is(target error) bool {
	return target == ErrTooLarge
}

// CheckJSON returns a *TooMuchJSONError when data, a JSON answer, holds more
// than MaxValues units or nests deeper than MaxDepth, without decoding it. It
// reads data once and allocates nothing. It doesn't validate data: JSON that
// isn't valid passes, and the decoder refuses it.
func CheckJSON(data []byte) error {
	return checkJSON(data, MaxValues, MaxDepth)
}

func checkJSON(data []byte, maxValues, maxDepth int) error {
	units, depth := 0, 0
	for i := 0; i < len(data); i++ {
		switch c := data[i]; {
		case c == '"':
			units++
			for i++; i < len(data) && data[i] != '"'; i++ {
				if data[i] == '\\' {
					i++
				}
			}
		case c == '[' || c == '{':
			units += ContainerCost
			if depth++; depth > maxDepth {
				return &TooMuchJSONError{Depth: true}
			}
		case c == ']' || c == '}':
			depth--
		case c == '-' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z':
			// A number, true, false, or null: skip to its end.
			units++
			for i+1 < len(data) && isScalarByte(data[i+1]) {
				i++
			}
		}
		if units > maxValues {
			return &TooMuchJSONError{}
		}
	}
	return nil
}

func isScalarByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '.' || c == '+' || c == '-'
}

// Unmarshal decodes data, a JSON answer, into v, unless it holds more JSON
// than the SDK decodes (see CheckJSON).
func Unmarshal(data []byte, v any) error {
	if err := CheckJSON(data); err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// Decode reads r under limit (see ReadAll) and decodes it into v (see
// Unmarshal).
func Decode(r io.Reader, limit int64, v any) error {
	data, err := ReadAll(r, limit)
	if err != nil {
		return err
	}
	return Unmarshal(data, v)
}
