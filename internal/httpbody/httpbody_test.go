package httpbody

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

// An answer of limit bytes is read whole; one byte more is refused, to a
// reader or a JSON decoder, with an error that is ErrTooLarge and names the
// limit.
func TestReadAllStopsAtTheLimit(t *testing.T) {
	for _, limit := range []int64{Small, Large} {
		got, err := ReadAll(io.LimitReader(zeros{}, limit), limit)
		if err != nil || int64(len(got)) != limit {
			t.Fatalf("limit %d: %d bytes, %v", limit, len(got), err)
		}
		if _, err := ReadAll(io.LimitReader(zeros{}, limit+1), limit); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("limit %d + 1: %v", limit, err)
		}
		_, err = ReadAll(zeros{}, limit)
		var tooLarge *TooLargeError
		if !errors.As(err, &tooLarge) || tooLarge.Limit != limit || !strings.Contains(err.Error(), "MiB limit") {
			t.Fatalf("an endless answer under %d: %v", limit, err)
		}
		padded := io.MultiReader(bytes.NewReader(bytes.Repeat([]byte{' '}, int(limit))), bytes.NewReader([]byte("{}")))
		var v map[string]interface{}
		if err := json.NewDecoder(Reader(padded, limit)).Decode(&v); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("a JSON answer past %d: %v", limit, err)
		}
	}
}

// A read that passes the cap returns the bytes up to it, and every read after
// returns none (never a negative count) with ErrTooLarge.
func TestReadsPastTheCapReturnNoBytes(t *testing.T) {
	r := Reader(zeros{}, Small)
	buf := make([]byte, 3<<20) // Small isn't a multiple of it
	var total int
	for {
		n, err := r.Read(buf)
		if n < 0 || n > len(buf) {
			t.Fatalf("a read returned %d bytes", n)
		}
		total += n
		if err != nil {
			if !errors.Is(err, ErrTooLarge) || total != Small {
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

// CheckJSON counts each string, number, true, false, and null as one unit
// and each array or object as ContainerCost, keys included and text inside
// strings not, and refuses past the limit or the depth.
func TestCheckJSONCountsUnitsAndDepth(t *testing.T) {
	for _, c := range []struct {
		json  string
		units int
	}{
		{`0`, 1},
		{`-1.5e+3`, 1},
		{`"a"`, 1},
		{`true`, 1},
		{`null`, 1},
		{`[]`, ContainerCost},
		{`{}`, ContainerCost},
		{`[1,"x",false,null]`, ContainerCost + 4},
		{`{"a":1,"b":[]}`, 2*ContainerCost + 3},
		{`["[{,\"]}", "\\", "\\\"[" ]`, ContainerCost + 3},
		{` [ 12 , 345 ] `, ContainerCost + 2},
	} {
		if err := checkJSON([]byte(c.json), c.units, MaxDepth); err != nil {
			t.Errorf("%s at %d units: %v", c.json, c.units, err)
		}
		var tooMuch *TooMuchJSONError
		if err := checkJSON([]byte(c.json), c.units-1, MaxDepth); !errors.As(err, &tooMuch) || tooMuch.Depth || !errors.Is(err, ErrTooLarge) {
			t.Errorf("%s at %d units: %v; want it refused", c.json, c.units-1, err)
		}
		var v interface{}
		if err := json.Unmarshal([]byte(c.json), &v); err != nil {
			t.Errorf("%s isn't JSON: %v", c.json, err)
		}
	}
	deep := strings.Repeat("[", MaxDepth) + strings.Repeat("]", MaxDepth)
	if err := CheckJSON([]byte(deep)); err != nil {
		t.Errorf("%d deep: %v", MaxDepth, err)
	}
	deeper := "[" + deep + "]"
	var tooMuch *TooMuchJSONError
	if err := CheckJSON([]byte(deeper)); !errors.As(err, &tooMuch) || !tooMuch.Depth || !errors.Is(err, ErrTooLarge) {
		t.Errorf("%d deep: %v; want it refused", MaxDepth+1, err)
	}
	var v interface{}
	if err := Unmarshal([]byte(deeper), &v); !errors.As(err, &tooMuch) || v != nil {
		t.Errorf("Unmarshal of %d deep: %v, %v; want it refused undecoded", MaxDepth+1, err, v)
	}
}
