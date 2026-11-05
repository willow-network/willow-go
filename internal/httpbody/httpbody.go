// Package httpbody reads HTTP answers under a size cap, so that a server
// can't make the SDK hold an answer of any size in memory.
package httpbody

import (
	"fmt"
	"io"
)

// MaxBytes is the most the SDK reads of one answer: 64 MiB, well above the
// largest answer a node, the API, or an indexer gives (a proof is a few MB).
const MaxBytes = 64 << 20

// ErrTooLarge is the error reading past MaxBytes of an answer returns.
var ErrTooLarge = fmt.Errorf("the answer is over the SDK's %d MiB limit", MaxBytes>>20)

// Reader reads r, but returns ErrTooLarge in place of any byte past MaxBytes.
func Reader(r io.Reader) io.Reader {
	return &capped{r: io.LimitReader(r, MaxBytes+1)}
}

// ReadAll reads r to its end, refusing more than MaxBytes with ErrTooLarge.
func ReadAll(r io.Reader) ([]byte, error) {
	return io.ReadAll(Reader(r))
}

type capped struct {
	r    io.Reader // limited to MaxBytes+1 bytes
	read int64
}

func (c *capped) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read += int64(n)
	if over := c.read - MaxBytes; over > 0 {
		return n - int(over), ErrTooLarge
	}
	return n, err
}
