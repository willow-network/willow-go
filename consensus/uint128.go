package consensus

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
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
	if v == nil || v.Sign() < 0 || v.BitLen() > 128 {
		return Uint128{}, fmt.Errorf("%v is not a u128", v)
	}
	lo := new(big.Int).And(v, new(big.Int).SetUint64(^uint64(0)))
	hi := new(big.Int).Rsh(v, 64)
	return Uint128{Hi: hi.Uint64(), Lo: lo.Uint64()}, nil
}

// ParseUint128 reads a u128 written in decimal digits.
func ParseUint128(s string) (Uint128, error) {
	if s == "" || strings.Trim(s, "0123456789") != "" {
		return Uint128{}, fmt.Errorf("%q is not an unsigned decimal integer", s)
	}
	v, _ := new(big.Int).SetString(s, 10)
	return Uint128FromBig(v)
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
