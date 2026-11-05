package httpbody

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"testing"
)

// An answer of MaxBytes is read whole; one byte more is refused, to a reader
// or a JSON decoder, with ErrTooLarge.
func TestReadAllStopsAtMaxBytes(t *testing.T) {
	got, err := ReadAll(io.LimitReader(zeros{}, MaxBytes))
	if err != nil || len(got) != MaxBytes {
		t.Fatalf("MaxBytes: %d bytes, %v", len(got), err)
	}
	if _, err := ReadAll(io.LimitReader(zeros{}, MaxBytes+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("MaxBytes+1: %v", err)
	}
	if _, err := ReadAll(zeros{}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("an endless answer: %v", err)
	}
	padded := io.MultiReader(bytes.NewReader(bytes.Repeat([]byte{' '}, MaxBytes)), bytes.NewReader([]byte("{}")))
	var v map[string]interface{}
	if err := json.NewDecoder(Reader(padded)).Decode(&v); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("a JSON answer past MaxBytes: %v", err)
	}
}

// A read that passes the cap returns the bytes up to it, and every read after
// returns none (never a negative count) with ErrTooLarge.
func TestReadsPastTheCapReturnNoBytes(t *testing.T) {
	r := Reader(zeros{})
	buf := make([]byte, 3<<20) // MaxBytes isn't a multiple of it
	var total int
	for {
		n, err := r.Read(buf)
		if n < 0 || n > len(buf) {
			t.Fatalf("a read returned %d bytes", n)
		}
		total += n
		if err != nil {
			if !errors.Is(err, ErrTooLarge) || total != MaxBytes {
				t.Fatalf("after %d bytes: %v", total, err)
			}
			break
		}
	}
	for i := 0; i < 2; i++ {
		if n, err := r.Read(buf); n != 0 || !errors.Is(err, ErrTooLarge) {
			t.Fatalf("read %d past the cap: %d bytes, %v; want 0, ErrTooLarge", i+1, n, err)
		}
	}
}

// zeros reads as an endless run of zero bytes.
type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}
