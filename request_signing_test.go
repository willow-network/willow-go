package willow

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// The api-server's test vector (crates/api-server/src/read_auth_tests.rs,
// the_signed_message_is_eight_lines), byte for byte.
const signedMessageVector = "willow-request-v2\ndid:willow:a\ndid:willow:a#key-1\nPOST\n/query/sg?x=1\n1700000000\n" +
	"abcdefghijklmnop\n44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"

// Signatures over signedMessageVector by the key whose seed is 32 bytes of 0x03,
// computed with an independent implementation of the server's verification.
const (
	vectorEd25519Signature = "c117313c0d01641340e398d9a7a9ff024a1c6672bca16bbcb99e6fe2738f82e7" +
		"7870bd2c30dc62d6c50cea32a3b21086730d9c25297831dd83bc797c5b394d0d"
	vectorSecp256k1DER = "3045022100bfbad8ec000c66ed30349070db245db0c45249293c545e35dc997d6427d32238" +
		"022030787244d5b3bb7e8a1b39bdba0c62261e02344a515f5e8e89f678e17d4b976d"
)

func vectorIdentity(t *testing.T, algorithm SignatureAlgorithm) *Identity {
	t.Helper()
	seed := strings.Repeat("03", 32)
	var kp *KeyPair
	var err error
	if algorithm == Ed25519 {
		priv := ed25519.NewKeyFromSeed(mustHex(t, seed))
		kp, err = KeyPairFromPrivateKey(Ed25519, hex.EncodeToString(priv))
	} else {
		kp, err = KeyPairFromPrivateKey(Secp256k1, seed)
	}
	if err != nil {
		t.Fatal(err)
	}
	return &Identity{
		KeyPair: kp,
		DidDocument: &DidDocument{
			ID:         "did:willow:a",
			PublicKeys: []PublicKey{{ID: "did:willow:a#key-1", Type: algorithm.KeyType(), PublicKeyHex: kp.PublicKeyHex()}},
		},
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSignedRequestMessageMatchesServerVector(t *testing.T) {
	got := SignedRequestMessage("did:willow:a", "did:willow:a#key-1", "POST", "/query/sg?x=1",
		"1700000000", "abcdefghijklmnop", []byte("{}"))
	if got != signedMessageVector {
		t.Fatalf("signed message mismatch:\n got %q\nwant %q", got, signedMessageVector)
	}
}

func TestSignRequestWithNonceEd25519KnownAnswer(t *testing.T) {
	id := vectorIdentity(t, Ed25519)
	headers, err := id.signRequestWithNonceAt("POST", "/query/sg?x=1", []byte("{}"), "1700000000", "abcdefghijklmnop")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"X-DID":           "did:willow:a",
		"X-Public-Key-ID": "did:willow:a#key-1",
		"X-Signature":     vectorEd25519Signature,
		"X-Timestamp":     "1700000000",
		"X-Nonce":         "abcdefghijklmnop",
	}
	for k, v := range want {
		if headers[k] != v {
			t.Errorf("%s = %q, want %q", k, headers[k], v)
		}
	}
	if len(headers) != len(want) {
		t.Errorf("unexpected headers: %v", headers)
	}
}

func TestSignRequestWithNonceSecp256k1KnownAnswer(t *testing.T) {
	id := vectorIdentity(t, Secp256k1)
	headers, err := id.signRequestWithNonceAt("POST", "/query/sg?x=1", []byte("{}"), "1700000000", "abcdefghijklmnop")
	if err != nil {
		t.Fatal(err)
	}
	// 0x-prefixed: the server reads an unprefixed secp256k1 signature as base64 first.
	if headers["X-Signature"] != "0x"+vectorSecp256k1DER {
		t.Fatalf("X-Signature = %q, want 0x%s", headers["X-Signature"], vectorSecp256k1DER)
	}
	ok, err := Verify(Secp256k1, id.KeyPair.PublicKey, []byte(signedMessageVector), mustHex(t, vectorSecp256k1DER))
	if err != nil || !ok {
		t.Fatalf("Verify = %v, %v", ok, err)
	}
	// The same signature as 64-byte r||s.
	compact := mustHex(t, "bfbad8ec000c66ed30349070db245db0c45249293c545e35dc997d6427d32238"+
		"30787244d5b3bb7e8a1b39bdba0c62261e02344a515f5e8e89f678e17d4b976d")
	if ok, err := Verify(Secp256k1, id.KeyPair.PublicKey, []byte(signedMessageVector), compact); err != nil || !ok {
		t.Fatalf("Verify(compact) = %v, %v", ok, err)
	}
}

func TestLegacyRequestMessageSignsThePathAlone(t *testing.T) {
	if got := LegacyRequestMessage("GET", "/data/sg/k?include_proof=true", "1700000000"); got != "GET:/data/sg/k:1700000000" {
		t.Fatalf("got %q", got)
	}
	if got := LegacyRequestMessage("GET", "/data/sg/k", "1700000000"); got != "GET:/data/sg/k:1700000000" {
		t.Fatalf("got %q", got)
	}

	id := vectorIdentity(t, Ed25519)
	headers, err := id.SignRequest("GET", "/data/sg/k?include_proof=true")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := headers["X-Nonce"]; ok {
		t.Fatal("the older form carries no nonce")
	}
	msg := "GET:/data/sg/k:" + headers["X-Timestamp"]
	if !ed25519.Verify(id.KeyPair.PublicKey, []byte(msg), mustHex(t, headers["X-Signature"])) {
		t.Fatal("older-form signature does not cover METHOD:PATH:TIMESTAMP")
	}
}

func TestNewRequestNonce(t *testing.T) {
	valid := regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		n, err := NewRequestNonce()
		if err != nil {
			t.Fatal(err)
		}
		if !valid.MatchString(n) {
			t.Fatalf("nonce %q is not 16-128 characters of A-Z a-z 0-9 - _", n)
		}
		if seen[n] {
			t.Fatalf("nonce %q repeated", n)
		}
		seen[n] = true
	}
}

// What a server would verify: the eight lines rebuilt from the request it got.
func verifyNonceSigned(t *testing.T, r *http.Request, body []byte, pub ed25519.PublicKey) {
	t.Helper()
	if r.Header.Get("X-Nonce") == "" {
		t.Fatalf("%s %s: no X-Nonce", r.Method, r.URL.RequestURI())
	}
	msg := SignedRequestMessage(r.Header.Get("X-DID"), r.Header.Get("X-Public-Key-ID"), r.Method,
		r.URL.RequestURI(), r.Header.Get("X-Timestamp"), r.Header.Get("X-Nonce"), body)
	sig, err := hex.DecodeString(r.Header.Get("X-Signature"))
	if err != nil || !ed25519.Verify(pub, []byte(msg), sig) {
		t.Fatalf("%s %s: signature does not cover the request as received", r.Method, r.URL.RequestURI())
	}
}

func TestClientSignsAPIRequestsWithANonce(t *testing.T) {
	id := vectorIdentity(t, Ed25519)
	var mu sync.Mutex
	var nonces []string
	failFirst := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		verifyNonceSigned(t, r, body, id.KeyPair.PublicKey)
		mu.Lock()
		nonces = append(nonces, r.Header.Get("X-Nonce"))
		retry := failFirst && r.URL.Path == "/query/sg"
		if retry {
			failFirst = false
		}
		mu.Unlock()
		if retry {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		if r.URL.Path == "/query/sg" && !strings.Contains(string(body), `"include_proof":false`) {
			t.Errorf("retried body lost: %q", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	client, err := NewClient(srv.URL, WithRetryConfig(RetryConfig{MaxRetries: 2, InitialBackoff: time.Millisecond, MaxBackoff: time.Millisecond, BackoffFactor: 1}))
	if err != nil {
		t.Fatal(err)
	}
	client.SetIdentity(id)
	ctx := context.Background()

	if _, err := client.Data.GetUnverified(ctx, "sg", "k"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Data.QueryUnverified(ctx, "sg", &QueryRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Indexing.SqlQuery(ctx, "sg", "SELECT 1", false); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Indexing.SqlQueryWithSource(ctx, "sg", "SELECT 1", false, QuerySourceValidator); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	// GET, the failed POST, its retry, and the two SQL reads.
	if len(nonces) != 5 {
		t.Fatalf("got %d requests, want 5", len(nonces))
	}
	seen := map[string]bool{}
	for _, n := range nonces {
		if seen[n] {
			t.Fatalf("nonce %q sent twice; a retry must be signed anew", n)
		}
		seen[n] = true
	}
}

func TestAPITargetDropsTheBaseURLPath(t *testing.T) {
	client, err := NewClient("https://proxy.example/willow")
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("GET", client.buildURL("/data/sg/k?include_proof=false"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := client.apiTarget(req.URL); got != "/data/sg/k?include_proof=false" {
		t.Fatalf("apiTarget = %q", got)
	}
}
