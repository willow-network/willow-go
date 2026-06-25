package willow

import (
	"encoding/hex"
	"testing"
)

// hexCommitment decodes a 0x-prefixed 32-byte hex string into a [32]byte.
func hexCommitment(t *testing.T, s string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode commitment: %v", err)
	}
	if len(b) != 32 {
		t.Fatalf("commitment must be 32 bytes, got %d", len(b))
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

func repeatByte(v byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = v
	}
	return out
}

func repeatAddr(v byte) [20]byte {
	var out [20]byte
	for i := range out {
		out[i] = v
	}
	return out
}

// Vector A: the empty set. Authoritative cross-language correctness gate.
func TestCanonicalEventSetHashVectorAEmpty(t *testing.T) {
	want := hexCommitment(t, "52089e4c924fbab0475d310d7f74bf8cae542d006a45d3c5d94adacda6937da5")
	got := CanonicalEventSetHash(0, []Log{})
	if got != want {
		t.Fatalf("vector A mismatch:\n got %x\nwant %x", got, want)
	}
	if !VerifyServedEvents(want, 0, []Log{}) {
		t.Fatal("vector A: VerifyServedEvents should accept the matching set")
	}
}

// vectorBLogs is the matched set for vector B.
func vectorBLogs() []Log {
	return []Log{
		{
			Address: repeatAddr(0x42),
			Topics:  [][32]byte{repeatByte(0xdd), repeatByte(0x11)},
			Data:    []byte{0x01, 0x02, 0x03, 0x04},
		},
		{
			Address: repeatAddr(0x43),
			Topics:  [][32]byte{repeatByte(0xaa)},
			Data:    nil,
		},
	}
}

// Vector B: two logs at block 7. Authoritative cross-language correctness gate.
func TestCanonicalEventSetHashVectorB(t *testing.T) {
	want := hexCommitment(t, "e1544ae919458663e8fce14bdcd06df6a777410c068302c0584dff1587524dfd")
	got := CanonicalEventSetHash(7, vectorBLogs())
	if got != want {
		t.Fatalf("vector B mismatch:\n got %x\nwant %x", got, want)
	}
	if !VerifyServedEvents(want, 7, vectorBLogs()) {
		t.Fatal("vector B: VerifyServedEvents should accept the matching set")
	}
}

// A tampered, incomplete, reordered, or wrong-block set must be rejected.
func TestVerifyServedEventsRejectsTampering(t *testing.T) {
	commitment := hexCommitment(t, "e1544ae919458663e8fce14bdcd06df6a777410c068302c0584dff1587524dfd")

	// Wrong block number.
	if VerifyServedEvents(commitment, 8, vectorBLogs()) {
		t.Fatal("expected rejection for wrong block number")
	}

	// Dropped a log.
	dropped := vectorBLogs()[:1]
	if VerifyServedEvents(commitment, 7, dropped) {
		t.Fatal("expected rejection for a dropped log")
	}

	// Added a log.
	added := append(vectorBLogs(), Log{Address: repeatAddr(0x44)})
	if VerifyServedEvents(commitment, 7, added) {
		t.Fatal("expected rejection for an added log")
	}

	// Flipped a byte in the first log's data.
	flipped := vectorBLogs()
	flipped[0].Data = []byte{0x01, 0x02, 0x03, 0x05}
	if VerifyServedEvents(commitment, 7, flipped) {
		t.Fatal("expected rejection for tampered log data")
	}

	// Reordered the logs.
	reordered := []Log{vectorBLogs()[1], vectorBLogs()[0]}
	if VerifyServedEvents(commitment, 7, reordered) {
		t.Fatal("expected rejection for reordered logs")
	}
}
