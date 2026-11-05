package grovedb

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Large-value merk ops (0x20..0x22, 0x28..0x2a). grovedb 3.1.0 writes a proof
// value's length as a u16, so a value of 64 KiB or more could not be proven;
// the Willow GroveDB fork writes such values with large-value ops (u32
// length). The fixtures are real proofs from the fork's prover: a
// 70,000-byte item (its merk op is 0x20) and a 65,530-byte item whose
// 65,535-byte merk value is the largest a 3.1.0 op (0x03) carries.

type largeValueFixture struct {
	Path       []string `json:"path"`
	Key        string   `json:"key"`
	ValueLen   int      `json:"value_len"`
	ElementLen int      `json:"element_len"`
	ItemOpcode int      `json:"item_opcode"`
	ProofHex   string   `json:"proof_hex"`
}

func loadLargeValueFixture(t *testing.T, name string) largeValueFixture {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var f largeValueFixture
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func katValue(n int) []byte {
	v := make([]byte, n)
	for i := range v {
		v[i] = byte((i*7 + 3) % 256)
	}
	return v
}

func TestRealLargeAndSmallValueProofsDecode(t *testing.T) {
	for _, tc := range []struct {
		name   string
		opcode int
	}{{"large_value_item", 0x20}, {"small_value_item", 0x03}} {
		f := loadLargeValueFixture(t, tc.name)
		if f.ItemOpcode != tc.opcode {
			t.Fatalf("%s: opcode %#x", tc.name, f.ItemOpcode)
		}
		proof, err := DecodeGroveDBProof(mustHex(t, f.ProofHex))
		if err != nil {
			t.Fatalf("%s: decode: %v", tc.name, err)
		}
		path := make([][]byte, len(f.Path))
		for i, s := range f.Path {
			path[i] = []byte(s)
		}
		if err := CheckEnvelope(proof, path); err != nil {
			t.Fatalf("%s: envelope: %v", tc.name, err)
		}
		layer := proof.Proof.RootLayer
		for _, seg := range path {
			layer = layer.LowerLayers[hex.EncodeToString(seg)]
		}
		key := []byte(f.Key)
		if !bytes.Contains(layer.MerkProof, append([]byte{byte(tc.opcode), byte(len(key))}, key...)) {
			t.Fatalf("%s: item op %#x not in the leaf merk proof", tc.name, tc.opcode)
		}
		d := NewMerkDecoder(layer.MerkProof)
		found := false
		for d.HasMore() {
			op, err := d.Next()
			if err != nil {
				t.Fatalf("%s: merk decode: %v", tc.name, err)
			}
			if op.Node != nil && op.Node.Type == NodeKV && bytes.Equal(op.Node.Key, key) {
				found = true
				v := op.Node.Value
				if len(v) != f.ElementLen {
					t.Fatalf("%s: element %d bytes, want %d", tc.name, len(v), f.ElementLen)
				}
				// Item(value, None): [0x00, varint len, value, 0x00]
				if !bytes.Equal(v[len(v)-1-f.ValueLen:len(v)-1], katValue(f.ValueLen)) {
					t.Fatalf("%s: value bytes differ", tc.name)
				}
			}
		}
		if !found {
			t.Fatalf("%s: no KV node for the key", tc.name)
		}
	}
}

func largeKV(op byte, declared uint32, carried int, tail []byte) []byte {
	b := []byte{op, 1, 'k'}
	b = binary.BigEndian.AppendUint32(b, declared)
	b = append(b, bytes.Repeat([]byte{9}, carried)...)
	return append(b, tail...)
}

func decodeOne(b []byte) (*MerkOp, error) {
	d := NewMerkDecoder(b)
	op, err := d.Next()
	if err == nil && d.HasMore() {
		return nil, NewVerificationError("trailing bytes")
	}
	return op, err
}

func TestLargeValueOpsDecodeAsTheOpTheyMirror(t *testing.T) {
	hash := bytes.Repeat([]byte{5}, 32)
	for _, tc := range []struct {
		op   byte
		typ  MerkOpType
		node MerkNodeType
		tail []byte
	}{
		{0x20, OpPush, NodeKV, nil},
		{0x21, OpPush, NodeKVValueHash, hash},
		{0x22, OpPush, NodeKVRefValueHash, hash},
		{0x28, OpPushInverted, NodeKV, nil},
		{0x29, OpPushInverted, NodeKVValueHash, hash},
		{0x2a, OpPushInverted, NodeKVRefValueHash, hash},
	} {
		op, err := decodeOne(largeKV(tc.op, 65536, 65536, tc.tail))
		if err != nil {
			t.Fatalf("%#x: %v", tc.op, err)
		}
		if op.Type != tc.typ || op.Node.Type != tc.node || len(op.Node.Value) != 65536 {
			t.Fatalf("%#x: decoded %+v", tc.op, op.Type)
		}
	}
}

func TestLargeValueOpRefusals(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
		want string
	}{
		{"short value", largeKV(0x20, 100, 100, nil), "at least 65536"},
		{"65535", largeKV(0x20, 65535, 65535, nil), "at least 65536"},
		{"over 64 MiB", largeKV(0x20, MaxValueLen+1, 0, nil), "limit"},
		{"max u32", largeKV(0x20, 0xffffffff, 0, nil), "limit"},
		{"truncated value", largeKV(0x20, 70000, 69999, nil), "unexpected end"},
		{"truncated length", []byte{0x21, 1, 'k', 0, 1}, "u32"},
	}
	for _, c := range cases {
		_, err := decodeOne(c.b)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: got %v, want %q", c.name, err, c.want)
		}
	}
	for _, op := range []byte{0x23, 0x24, 0x25, 0x26, 0x27, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f} {
		if _, err := decodeOne(largeKV(op, 65536, 65536, nil)); err == nil || !strings.Contains(err.Error(), "unknown op code") {
			t.Fatalf("%#x: got %v", op, err)
		}
	}
	if _, err := decodeOne(largeKV(0x20, 65536, 65536, nil)); err != nil {
		t.Fatal(err)
	}
}
