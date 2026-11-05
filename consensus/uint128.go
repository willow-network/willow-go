package consensus

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"math/bits"
	"strings"
)

// Uint128 is an unsigned 128-bit integer, the chain's u128 (token amounts in
// the smallest unit, 10^-18 WILL). It holds every value exactly: it marshals to
// JSON as a number with all its digits and reads a JSON number or a decimal
// string, never through a float.
type Uint128 struct {
	Hi, Lo uint64
}

// NewUint128 returns v as a Uint128.
func NewUint128(v uint64) Uint128 {
	return Uint128{Lo: v}
}

// Uint128FromBig returns v as a Uint128, refusing a negative value or one of
// more than 128 bits.
func Uint128FromBig(v *big.Int) (Uint128, error) {
	switch {
	case v == nil:
		return Uint128{}, fmt.Errorf("nil is not a u128")
	case v.Sign() < 0:
		return Uint128{}, fmt.Errorf("a negative number is not a u128")
	case v.BitLen() > 128:
		return Uint128{}, fmt.Errorf("a %d-bit number is not a u128", v.BitLen())
	}
	lo := new(big.Int).And(v, new(big.Int).SetUint64(^uint64(0)))
	hi := new(big.Int).Rsh(v, 64)
	return Uint128{Hi: hi.Uint64(), Lo: lo.Uint64()}, nil
}

// maxUint128Digits is how many decimal digits the largest u128,
// 340282366920938463463374607431768211455, has.
const maxUint128Digits = 39

// ParseUint128 reads a u128 written in decimal digits (ASCII 0-9, leading
// zeros allowed). It refuses a number of more than 39 digits after its leading
// zeros before reading any of it, and reads the rest into two 64-bit halves,
// so a long input costs one pass over it. The error doesn't repeat a long
// input.
func ParseUint128(s string) (Uint128, error) {
	digits := strings.TrimLeft(s, "0")
	if s == "" || strings.Trim(digits, "0123456789") != "" {
		if len(s) > 64 {
			return Uint128{}, fmt.Errorf("a %d-byte string is not an unsigned decimal integer", len(s))
		}
		return Uint128{}, fmt.Errorf("%q is not an unsigned decimal integer", s)
	}
	if len(digits) > maxUint128Digits {
		return Uint128{}, fmt.Errorf("a number of %d digits is not a u128 (at most %d)", len(digits), maxUint128Digits)
	}
	var u Uint128
	for i := 0; i < len(digits); i++ {
		// u = u*10 + digit, refusing a carry out of the high half.
		hiCarry, hi := bits.Mul64(u.Hi, 10)
		loCarry, lo := bits.Mul64(u.Lo, 10)
		hi, c1 := bits.Add64(hi, loCarry, 0)
		lo, c2 := bits.Add64(lo, uint64(digits[i]-'0'), 0)
		hi, c3 := bits.Add64(hi, 0, c2)
		if hiCarry != 0 || c1 != 0 || c3 != 0 {
			return Uint128{}, fmt.Errorf("%s is more than a u128 holds", digits)
		}
		u = Uint128{Hi: hi, Lo: lo}
	}
	return u, nil
}

// Big returns the value as a big.Int.
func (u Uint128) Big() *big.Int {
	v := new(big.Int).SetUint64(u.Hi)
	v.Lsh(v, 64)
	return v.Or(v, new(big.Int).SetUint64(u.Lo))
}

// String returns the value in decimal.
func (u Uint128) String() string {
	return u.Big().String()
}

// IsZero reports whether the value is 0.
func (u Uint128) IsZero() bool {
	return u.Hi == 0 && u.Lo == 0
}

// appendLittleEndian appends the value's 16 little-endian bytes, as bincode
// encodes a u128.
func (u Uint128) appendLittleEndian(b []byte) []byte {
	b = binary.LittleEndian.AppendUint64(b, u.Lo)
	return binary.LittleEndian.AppendUint64(b, u.Hi)
}

// MarshalJSON writes the value as a JSON number.
func (u Uint128) MarshalJSON() ([]byte, error) {
	return []byte(u.String()), nil
}

// UnmarshalJSON reads a JSON number or a JSON string of decimal digits (null
// leaves the value as it is).
func (u *Uint128) UnmarshalJSON(data []byte) error {
	text := strings.TrimSpace(string(data))
	if text == "null" {
		return nil
	}
	if strings.HasPrefix(text, `"`) {
		if err := json.Unmarshal(data, &text); err != nil {
			return err
		}
	}
	v, err := ParseUint128(text)
	if err != nil {
		return err
	}
	*u = v
	return nil
}
