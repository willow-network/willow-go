package willow

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// envelopeAPI is a mocked API answering each "METHOD path" with its body, as
// the node's handlers do: most routes wrap their result as
// {"success":true,"data":...,"error":null}.
func envelopeAPI(t *testing.T, routes map[string]string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := routes[r.Method+" "+r.URL.Path]
		if !ok {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	client, err := NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	client.SetIdentity(vectorIdentity(t, Ed25519))
	return client
}

func okEnvelope(data string) string {
	return `{"success":true,"data":` + data + `,"error":null}`
}

// 10^22 and 2^64: amounts the chain sends as u128 numbers beyond uint64.
const (
	stake22 = "10000000000000000000000"
	above64 = "18446744073709551616"
)

func TestEveryEnvelopeRouteYieldsItsData(t *testing.T) {
	client := envelopeAPI(t, map[string]string{
		"GET /did/did:willow:a": okEnvelope(`{"id":"did:willow:a","public_keys":[{"id":"did:willow:a#key-1","type":"Ed25519VerificationKey2018",` +
			`"controller":"did:willow:a","public_key_base58":null,"public_key_hex":"ab"}],"authentication":["did:willow:a#key-1"],` +
			`"service":[],"created":1700000000,"updated":1700000001,"proof":null}`),
		"GET /state/root-hash":          okEnvelope(`{"root_hash":"aa11","note":"n","deprecation_warning":"w"}`),
		"GET /state/root-hash/verified": okEnvelope(`{"root_hash":"BB22","source":"cometbft","verified":true,"note":"n"}`),
		"GET /data/sg/k":                okEnvelope(`{"title":"Hello","value":42}`),
		"POST /query/sg": okEnvelope(`{"total":3,"offset":0,"limit":2,"documents":[{"a":1},{"a":2}],"proof":"0a0b","height":9,` +
			`"verification":{"verified":false}}`),
		"GET /proof/sg/k": okEnvelope(`{"proof":"c0ffee","path":["7375626772"],"key":"6b","height":12}`),
		"GET /checkpoints/sg/" + strings.Repeat("ab", 32) + "/state-root": okEnvelope(`{"checkpoint_id":"` + strings.Repeat("ab", 32) +
			`","subgrove_id":"sg","state_root":"cd","block_range":[1,9],"is_trusted":true}`),
		"GET /subgroves": okEnvelope(`[{"subgrove_id":"notes-1","name":"Notes","description":"d","admins":[],` +
			`"schema":{"version":1,"fields":{"title":"string","rank":"number"},"indexes":[{"name":"by_title","fields":["title"],"unique":true}],"required_fields":["title"]},` +
			`"owner_did":"did:willow:a","writers":["did:willow:a"],"free_readers":["did:willow:c"],"read_pricing":null,` +
			`"mode":"DataStorage","indexer_count":0}]`),
		"GET /subgroves/notes-1": okEnvelope(`{"subgrove_id":"notes-1","name":"Notes","owner_did":"did:willow:a","status":"active",` +
			`"latest_block":0,"deployment_block":0,"indexers":[]}`),
		"GET /did/did:willow:a/permissions": okEnvelope(`[{"did":"did:willow:a","subgrove_id":"sg","role":"reader","granted_by":"did:willow:o","granted_at":5}]`),
		"GET /token/info": okEnvelope(`{"name":"Willow","symbol":"WILL","decimals":18,"genesis_supply":` + stake22 +
			`,"minted_supply":0,"max_supply":` + stake22 + `0,"circulating_supply":` + above64 + `}`),
		"GET /token/balance/did:willow:a": okEnvelope(`{"did":"did:willow:a","available":` + above64 + `,"staked":` + stake22 + `,"locked":1}`),
		"GET /fees/schedule": okEnvelope(`{"did_registration":` + above64 + `,"subgrove_registration":1000000000000000000000,` +
			`"blockchain_indexing_subgrove_registration":1,"indexer_registration":1,"submit_anchor":1,"base_tx_cost":100,` +
			`"cost_per_byte":` + above64 + `,"query_fee":7,"transfer_fee_percentage":1,"max_tx_size_bytes":1048576,"max_data_payload_bytes":65536}`),
		"GET /validators": okEnvelope(`[{"did":"did:willow:v","total_stake":` + stake22 + `,"self_stake":` + above64 +
			`,"active":true,"jailed":false,"jail_end_time":null,"consensus_pubkey":"pk"}]`),
		"GET /validators/did:willow:v": okEnvelope(`{"did":"did:willow:v","total_stake":` + stake22 + `,"self_stake":1,"active":true,"jailed":true,"jail_end_time":9,"consensus_pubkey":null}`),
		"GET /indexers": okEnvelope(`[{"indexer_did":"did:willow:i","subgroves":["sg"],"stake_amount":` + stake22 +
			`,"endpoint":"http://i","status":"active","performance_score":0.9,"last_update":4}]`),
		"GET /indexers/did:willow:i": okEnvelope(`{"indexer_did":"did:willow:i","subgroves":["sg"],"stake_amount":` + stake22 +
			`,"endpoint":"http://i","query_endpoint":"http://q","status":"active","performance_score":0.9,"last_update":4}`),
		"GET /key-grants/sg/did:willow:a": okEnvelope(`{"grantee_did":"did:willow:a","key_epoch":2,"grantee_public_key_id":"did:willow:a#key-1",` +
			`"ephemeral_public_key":[1,2],"encrypted_key":[3],"granted_by":"did:willow:o","granted_at":5}`),
		"GET /key-grants/sg":                   okEnvelope(`["did:willow:a","did:willow:b"]`),
		"GET /proof/key-grant/sg/did:willow:a": okEnvelope(`{"proof":"ab","subgrove_id":"sg","grantee_did":"did:willow:a"}`),
		"GET /account/did:willow:a/nonce":      okEnvelope(`{"did":"did:willow:a","nonce":` + "18446744073709551614" + `}`),
		"GET /health":                          `{"status":"degraded","timestamp":"t","version":"1.2.3","checks":{"storage":{"status":"healthy"}}}`,
	})
	ctx := context.Background()

	did, err := client.GetDID(ctx, "did:willow:a")
	if err != nil || did.Did != "did:willow:a" || did.Document == nil || did.Document.PublicKeys[0].PublicKeyHex != "ab" || did.CreatedAt != 1700000000 {
		t.Errorf("GetDID = %+v, %v", did, err)
	}
	if root, err := client.GetRootHash(ctx); err != nil || root != "aa11" {
		t.Errorf("GetRootHash = %q, %v", root, err)
	}
	if root, err := client.GetLatestAppHash(ctx); err != nil || root != "BB22" {
		t.Errorf("GetLatestAppHash = %q, %v", root, err)
	}
	if root, err := client.GetVerifiedRootHash(ctx); err != nil || root != "BB22" {
		t.Errorf("GetVerifiedRootHash = %q, %v", root, err)
	}
	if state, err := client.GetAccountNonce(ctx, "did:willow:a"); err != nil || state.Base != 18446744073709551614 || state.Used != 0 {
		t.Errorf("GetAccountNonce = %+v, %v", state, err)
	}
	// No nonce above that base is one the chain accepts.
	if _, err := client.NextNonce(ctx, "did:willow:a"); !errors.Is(err, ErrNonceWindowFull) {
		t.Errorf("NextNonce at the top of the range: %v, want ErrNonceWindowFull", err)
	}

	for name, get := range map[string]func(context.Context, string, string) (*DataResponse, error){
		"Get": client.Data.Get, "GetUnverified": client.Data.GetUnverified,
	} {
		value, err := get(ctx, "sg", "k")
		if err != nil || value.Key != "k" || value.Data["title"] != "Hello" || value.Data["value"] != float64(42) {
			t.Errorf("Data.%s = %+v, %v", name, value, err)
		}
	}
	query, err := client.Data.QueryUnverified(ctx, "sg", NewQueryBuilder().Limit(2).Build())
	if err != nil || len(query.Results) != 2 || query.Results[1].Data["a"] != float64(2) || query.TotalCount != 3 ||
		!query.HasMore || string(query.Proof) != "\x0a\x0b" || query.Height != 9 {
		t.Errorf("Data.QueryUnverified = %+v, %v", query, err)
	}
	if proof, err := client.Data.GetProof(ctx, "sg", "k"); err != nil || string(proof.Proof) != "\xc0\xff\xee" || proof.Height != 12 ||
		len(proof.Path) != 1 || string(proof.Path[0]) != "subgr" || string(proof.Key) != "k" {
		t.Errorf("Data.GetProof = %+v, %v", proof, err)
	}
	if cp, err := client.Data.GetCheckpointStateRoot(ctx, "sg", strings.Repeat("ab", 32)); err != nil || cp.StateRoot != "cd" || cp.BlockRange != [2]uint64{1, 9} || !cp.IsTrusted {
		t.Errorf("Data.GetCheckpointStateRoot = %+v, %v", cp, err)
	}

	list, err := client.Registration.ListSubgroves(ctx)
	if err != nil || len(list) != 1 || list[0].SubgroveID != "notes-1" || list[0].Readers[0] != "did:willow:c" ||
		len(list[0].Schema.Fields) != 2 || list[0].Schema.Fields[1] != (SchemaField{Name: "title", Type: "string", Required: true}) ||
		!list[0].Schema.Indexes[0].Unique {
		t.Errorf("Registration.ListSubgroves = %+v, %v", list, err)
	}
	if sg, err := client.Registration.GetSubgrove(ctx, "notes-1"); err != nil || sg.SubgroveID != "notes-1" || sg.OwnerDid != "did:willow:a" {
		t.Errorf("Registration.GetSubgrove = %+v, %v", sg, err)
	}
	if perms, err := client.Registration.GetPermissions(ctx, "did:willow:a"); err != nil || len(perms) != 1 || perms[0].Role != "reader" {
		t.Errorf("Registration.GetPermissions = %+v, %v", perms, err)
	}

	info, err := client.Token.GetInfo(ctx)
	if err != nil || info.Symbol != "WILL" || info.Decimals != 18 || info.GenesisSupply != stake22 ||
		info.MaxSupply != stake22+"0" || info.MintedSupply != "0" || info.CirculatingSupply != above64 {
		t.Errorf("Token.GetInfo = %+v, %v", info, err)
	}
	balance, err := client.Token.GetBalance(ctx, "did:willow:a")
	if err != nil || balance.DID != "did:willow:a" || balance.Available.String() != above64 || balance.Staked.String() != stake22 || balance.Locked.String() != "1" {
		t.Errorf("Token.GetBalance = %+v, %v", balance, err)
	}
	fees, err := client.Token.GetFeeSchedule(ctx)
	if err != nil || fees.DidRegistration != above64 || fees.SubgroveRegistration != "1000000000000000000000" ||
		fees.CostPerByte != above64 || fees.QueryFee != "7" || fees.MaxDataPayloadBytes != 65536 {
		t.Errorf("Token.GetFeeSchedule = %+v, %v", fees, err)
	}
	if fee, err := client.Token.EstimateStorageFee(ctx, 2); err != nil || fee != "36893488147419103232" {
		t.Errorf("Token.EstimateStorageFee = %q, %v", fee, err)
	}

	validators, err := client.Validators.List(ctx)
	if err != nil || len(validators) != 1 || validators[0].DID != "did:willow:v" || validators[0].TotalStake.String() != stake22 ||
		validators[0].Status() != ValidatorStatusActive {
		t.Errorf("Validators.List = %+v, %v", validators, err)
	}
	if total, err := client.Validators.GetTotalStake(ctx); err != nil || total.String() != stake22 {
		t.Errorf("Validators.GetTotalStake = %v, %v", total, err)
	}
	if v, err := client.Validators.Get(ctx, "did:willow:v"); err != nil || v.Status() != ValidatorStatusJailed || *v.JailEndTime != 9 {
		t.Errorf("Validators.Get = %+v, %v", v, err)
	}

	subgroves, err := client.Indexing.ListSubgroves(ctx)
	if err != nil || len(subgroves) != 1 || subgroves[0].SubgroveID != "notes-1" || subgroves[0].Mode != "DataStorage" {
		t.Errorf("Indexing.ListSubgroves = %+v, %v", subgroves, err)
	}
	if sg, err := client.Indexing.GetSubgrove(ctx, "notes-1"); err != nil || sg.Status != "active" || sg.OwnerDid != "did:willow:a" {
		t.Errorf("Indexing.GetSubgrove = %+v, %v", sg, err)
	}
	indexers, err := client.Indexing.ListIndexers(ctx)
	if err != nil || len(indexers) != 1 || indexers[0].StakeAmount.String() != stake22 {
		t.Errorf("Indexing.ListIndexers = %+v, %v", indexers, err)
	}
	if indexer, err := client.Indexing.GetIndexer(ctx, "did:willow:i"); err != nil || indexer.EffectiveQueryEndpoint() != "http://q" {
		t.Errorf("Indexing.GetIndexer = %+v, %v", indexer, err)
	}
	// Source routing reads the same list; a stake above uint64 must not stop it.
	if routed, err := client.Indexers.ForSubgrove(ctx, "sg"); err != nil || len(routed) != 1 {
		t.Errorf("Indexers.ForSubgrove = %+v, %v", routed, err)
	}

	if grant, err := client.Privacy.GetMyKeyGrant(ctx, "sg"); err != nil || grant.KeyEpoch != 2 || len(grant.EphemeralPublicKey) != 2 {
		t.Errorf("Privacy.GetMyKeyGrant = %+v, %v", grant, err)
	}
	if grantees, err := client.Privacy.ListKeyGrantees(ctx, "sg"); err != nil || len(grantees) != 2 {
		t.Errorf("Privacy.ListKeyGrantees = %v, %v", grantees, err)
	}
	proof, err := client.Privacy.GetKeyGrantProof(ctx, "sg", "did:willow:a")
	var proofData struct {
		Proof string `json:"proof"`
	}
	if err != nil || json.Unmarshal(proof, &proofData) != nil || proofData.Proof != "ab" {
		t.Errorf("Privacy.GetKeyGrantProof = %s, %v", proof, err)
	}

	// /health answers with the status itself.
	if health, err := client.Health(ctx); err != nil || health.Status != "degraded" || health.Healthy || health.Version != "1.2.3" {
		t.Errorf("Health = %+v, %v", health, err)
	}
}

// An envelope with success false is an error carrying the API's message, at
// any HTTP status: the data route answers a missing key with 200.
func TestEnvelopeErrorsAreSurfaced(t *testing.T) {
	client := envelopeAPI(t, map[string]string{
		"GET /data/sg/missing":            `{"success":false,"data":null,"error":"Data not found"}`,
		"GET /data/sg/odd":                `{"success":false,"data":null,"error":"Private subgrove data is not available through this endpoint"}`,
		"GET /token/balance/did:bad":      `{"success":false,"data":null,"error":"Invalid DID format"}`,
		"GET /key-grants/sg/did:willow:a": `{"success":false,"data":null,"error":"Authentication required: sign the request with a one-time nonce (X-Nonce)"}`,
	})
	ctx := context.Background()

	_, err := client.Data.Get(ctx, "sg", "missing")
	if !IsNotFound(err) || !strings.Contains(err.Error(), "Data not found") {
		t.Errorf("missing key: %v, want a not-found error", err)
	}
	_, err = client.Data.GetUnverified(ctx, "sg", "odd")
	var werr *WillowError
	if !errors.As(err, &werr) || werr.Type != ErrorTypeAPI || !strings.Contains(err.Error(), "Private subgrove") {
		t.Errorf("refused read: %v, want an API error with its message", err)
	}
	if _, err := client.Token.GetBalance(ctx, "did:bad"); err == nil || !strings.Contains(err.Error(), "Invalid DID format") {
		t.Errorf("refused balance: %v", err)
	}
	if _, err := client.Privacy.GetMyKeyGrant(ctx, "sg"); err == nil || !strings.Contains(err.Error(), "one-time nonce") {
		t.Errorf("refused key grant: %v", err)
	}
}

// An error status carries the envelope's message too.
func TestEnvelopeErrorsWithAStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"success":false,"data":null,"error":"Subgrove not found"}`))
	}))
	defer srv.Close()
	client, err := NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Registration.GetSubgrove(context.Background(), "nope")
	if !IsNotFound(err) || err.Error() != "not_found: Subgrove not found" {
		t.Errorf("got %v, want not_found: Subgrove not found", err)
	}
}

// A query is sent in the form the API's /query reads, and one it wouldn't
// apply is refused before anything is sent.
func TestQueryBodyIsWhatTheAPIApplies(t *testing.T) {
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(body))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(okEnvelope(`{"total":0,"offset":4,"limit":2,"documents":[]}`)))
	}))
	defer srv.Close()
	client, err := NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	client.SetIdentity(vectorIdentity(t, Ed25519))
	ctx := context.Background()

	q := NewQueryBuilder().Equals("category", "toys").SortDesc("price").Limit(2).Offset(4).Build()
	if _, err := client.Data.QueryUnverified(ctx, "sg", q); err != nil {
		t.Fatal(err)
	}
	want := `{"filters":{"category":"toys"},"include_proof":false,"limit":2,"offset":4,"sort":{"field":"price","order":"desc"}}`
	if len(bodies) != 1 || bodies[0] != want {
		t.Fatalf("sent %q, want %s", bodies, want)
	}
	for name, bad := range map[string]*QueryRequest{
		"two filters":  NewQueryBuilder().Equals("a", 1).Equals("b", 2).Build(),
		"operator":     NewQueryBuilder().GreaterThan("a", 1).Build(),
		"search":       NewQueryBuilder().Search([]string{"a"}, "x").Build(),
		"object value": NewQueryBuilder().Equals("a", map[string]interface{}{"b": 1}).Build(),
	} {
		if _, err := client.Data.QueryUnverified(ctx, "sg", bad); !IsValidationError(err) {
			t.Errorf("%s: got %v, want a validation error", name, err)
		}
	}
	if len(bodies) != 1 {
		t.Fatalf("sent %d queries, want 1", len(bodies))
	}
}

// Data.Query and Data.VerifyProof don't present data as verified, since the
// SDK can't verify a proof against the chain: they return an unsupported
// error, and Query sends nothing.
func TestQueryAndVerifyProofAreUnsupported(t *testing.T) {
	client := envelopeAPI(t, map[string]string{}) // any request fails the test
	ctx := context.Background()
	if got, err := client.Data.Query(ctx, "sg", NewQueryBuilder().Equals("a", 1).Build()); !IsUnsupported(err) || got != nil {
		t.Errorf("Data.Query = %+v, %v; want an unsupported error", got, err)
	}
	if err := client.Data.VerifyProof(ctx, &DataProof{Proof: []byte{1}, Height: 9}); !IsUnsupported(err) {
		t.Errorf("Data.VerifyProof = %v; want an unsupported error", err)
	}
}
