package willow

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/willow-network/willow-go/internal/httpbody"
	"github.com/willow-network/willow-go/lightclient"
)

// Client is the main client for interacting with the Willow network.
type Client struct {
	httpClient      *http.Client
	baseURL         *url.URL
	indexerURL      *url.URL // Optional indexer node URL for GraphQL/SQL routing
	rpcURL          *url.URL // Optional CometBFT JSON-RPC endpoint override (for ABCI queries)
	identity        *Identity
	identityMu      sync.RWMutex
	retryConfig     RetryConfig
	lightClient     *lightclient.LightClient
	lightClientMu   sync.Mutex
	lightClientInit bool

	// nonces hands out transaction nonces per signing DID (see NextNonce).
	nonces *nonceAllocator
	// noncePollInterval is how often WaitUntilLanded reads the nonce state.
	noncePollInterval time.Duration

	// Computed fields registry for SDK-side derived field computation
	computedFields *ComputedFieldRegistry

	// Sub-clients for different operations
	Data         *DataOperations
	Registration *RegistrationOperations
	Token        *TokenOperations
	Validators   *ValidatorOperations
	Indexing     *IndexingOperations
	Privacy      *PrivacyOperations
	Files        *FileOperations
	// Indexers is the discovery client used by source-routed queries.
	// When no indexer URL was configured, it queries GET /indexers on the
	// validator (with 30-second cache). When indexerURL is set, it returns
	// a synthetic single-entry list.
	Indexers *Indexers
	// Subscriptions opens graphql-transport-ws WebSocket connections
	// against either the validator's /graphql/ws (default) or an
	// indexer's, based on SubscribeOptions.Source.
	Subscriptions *Subscriptions
}

// ClientOption is a functional option for configuring the Client.
type ClientOption func(*Client) error

// defaultTimeout is the timeout of the HTTP clients the SDK makes when the
// caller gives none.
const defaultTimeout = 30 * time.Second

// NewClient creates a new Willow client with the given API URL and options.
func NewClient(apiURL string, opts ...ClientOption) (*Client, error) {
	parsedURL, err := url.Parse(strings.TrimSuffix(apiURL, "/"))
	if err != nil {
		return nil, NewConfigError(fmt.Sprintf("invalid API URL: %s", err))
	}

	client := &Client{
		httpClient: &http.Client{
			Timeout: defaultTimeout,
		},
		baseURL:           parsedURL,
		retryConfig:       DefaultRetryConfig(),
		computedFields:    NewComputedFieldRegistry(),
		nonces:            newNonceAllocator(time.Now),
		noncePollInterval: time.Second,
	}

	// Apply options
	for _, opt := range opts {
		if err := opt(client); err != nil {
			return nil, err
		}
	}

	// Initialize sub-clients
	client.Data = &DataOperations{client: client}
	client.Registration = &RegistrationOperations{client: client}
	client.Token = &TokenOperations{client: client}
	client.Validators = &ValidatorOperations{client: client}
	client.Indexing = &IndexingOperations{client: client}
	client.Privacy = &PrivacyOperations{client: client}
	client.Files = &FileOperations{client: client}

	indexerURLStr := ""
	if client.indexerURL != nil {
		indexerURLStr = client.indexerURL.String()
	}
	client.Indexers = NewIndexers(client.httpClient, client.baseURL.String(), indexerURLStr)
	client.Subscriptions = NewSubscriptions(client.baseURL.String(), client.Indexers, client.httpClient)

	return client, nil
}

// WithTimeout sets the HTTP client timeout.
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) error {
		c.httpClient.Timeout = timeout
		return nil
	}
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(httpClient *http.Client) ClientOption {
	return func(c *Client) error {
		c.httpClient = httpClient
		return nil
	}
}

// WithRetryConfig sets the retry configuration.
func WithRetryConfig(config RetryConfig) ClientOption {
	return func(c *Client) error {
		c.retryConfig = config
		return nil
	}
}

// WithIndexerURL sets an optional indexer node URL.
// When set, GraphQL and SQL queries are routed to the indexer instead of the validator.
func WithIndexerURL(indexerURL string) ClientOption {
	return func(c *Client) error {
		parsed, err := url.Parse(strings.TrimSuffix(indexerURL, "/"))
		if err != nil {
			return NewConfigError(fmt.Sprintf("invalid indexer URL: %s", err))
		}
		c.indexerURL = parsed
		return nil
	}
}

// WithRPCURL sets an explicit CometBFT JSON-RPC endpoint (e.g.
// http://localhost:26657). Used for ABCI store queries such as the
// completeness anchor and, only when set, the account nonce state (see
// GetAccountNonce), whose bitmap of used nonces lets writes skip them. When
// unset, the endpoint is derived from the API URL by swapping the :3031 REST
// port for :26657, and the nonce state is read from the API (its base alone).
func WithRPCURL(rpcURL string) ClientOption {
	return func(c *Client) error {
		parsed, err := url.Parse(strings.TrimSuffix(rpcURL, "/"))
		if err != nil {
			return NewConfigError(fmt.Sprintf("invalid RPC URL: %s", err))
		}
		c.rpcURL = parsed
		return nil
	}
}

// WithLightClient sets the light client LightClient and GetOrCreateLightClient
// return. It tracks CometBFT headers without verifying their commit
// signatures (see the lightclient package), and no read is verified against
// it.
func WithLightClient(lc *lightclient.LightClient) ClientOption {
	return func(c *Client) error {
		c.lightClient = lc
		return nil
	}
}

// apiKeyTransport wraps a base RoundTripper so every outbound request
// carries the managed-tier `X-API-Key` header. The wrap is non-destructive:
// the original request is cloned before the header is set, so the wrapped
// transport is safe to share across goroutines and reuse with other clients.
type apiKeyTransport struct {
	base http.RoundTripper
	key  string
}

func (t *apiKeyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req2 := req.Clone(req.Context())
	req2.Header.Set("X-API-Key", t.key)
	return t.base.RoundTrip(req2)
}

// WithAPIKey configures the managed-tier API key. When set, the SDK sends
// `X-API-Key: <key>` on every request. Mint a key at
// https://dashboard.willow.tech/account. Required for queries and writes
// against managed api.willow.tech / indexer.willow.tech.
func WithAPIKey(key string) ClientOption {
	return func(c *Client) error {
		if key == "" {
			return nil
		}
		base := c.httpClient.Transport
		if base == nil {
			base = http.DefaultTransport
		}
		c.httpClient.Transport = &apiKeyTransport{base: base, key: key}
		return nil
	}
}

// ClientBuilder provides a fluent interface for building a Client.
type ClientBuilder struct {
	apiURL  string
	options []ClientOption
	err     error
}

// Builder creates a new ClientBuilder.
func Builder(apiURL string) *ClientBuilder {
	return &ClientBuilder{
		apiURL:  apiURL,
		options: make([]ClientOption, 0),
	}
}

// WithTimeout adds a timeout option to the builder.
func (b *ClientBuilder) WithTimeout(timeout time.Duration) *ClientBuilder {
	if b.err != nil {
		return b
	}
	b.options = append(b.options, WithTimeout(timeout))
	return b
}

// WithHTTPClient adds a custom HTTP client option to the builder.
func (b *ClientBuilder) WithHTTPClient(httpClient *http.Client) *ClientBuilder {
	if b.err != nil {
		return b
	}
	b.options = append(b.options, WithHTTPClient(httpClient))
	return b
}

// WithRetryConfig adds a retry configuration option to the builder.
func (b *ClientBuilder) WithRetryConfig(config RetryConfig) *ClientBuilder {
	if b.err != nil {
		return b
	}
	b.options = append(b.options, WithRetryConfig(config))
	return b
}

// WithIndexerURL adds an indexer URL option to the builder.
func (b *ClientBuilder) WithIndexerURL(indexerURL string) *ClientBuilder {
	if b.err != nil {
		return b
	}
	b.options = append(b.options, WithIndexerURL(indexerURL))
	return b
}

// WithRPCURL adds a CometBFT JSON-RPC endpoint option to the builder.
func (b *ClientBuilder) WithRPCURL(rpcURL string) *ClientBuilder {
	if b.err != nil {
		return b
	}
	b.options = append(b.options, WithRPCURL(rpcURL))
	return b
}

// WithLightClient adds a light client option to the builder.
func (b *ClientBuilder) WithLightClient(lc *lightclient.LightClient) *ClientBuilder {
	if b.err != nil {
		return b
	}
	b.options = append(b.options, WithLightClient(lc))
	return b
}

// WithAPIKey adds a managed-tier API key to the builder. See WithAPIKey.
func (b *ClientBuilder) WithAPIKey(key string) *ClientBuilder {
	if b.err != nil {
		return b
	}
	b.options = append(b.options, WithAPIKey(key))
	return b
}

// Build creates the Client with all configured options.
func (b *ClientBuilder) Build() (*Client, error) {
	if b.err != nil {
		return nil, b.err
	}
	return NewClient(b.apiURL, b.options...)
}

// SetIdentity sets the identity used for request signing.
func (c *Client) SetIdentity(identity *Identity) {
	c.identityMu.Lock()
	defer c.identityMu.Unlock()
	c.identity = identity
}

// GetIdentity returns the current identity.
func (c *Client) GetIdentity() *Identity {
	c.identityMu.RLock()
	defer c.identityMu.RUnlock()
	return c.identity
}

// HasIdentity returns true if an identity is set on the client.
func (c *Client) HasIdentity() bool {
	return c.GetIdentity() != nil
}

// RequireAuth returns an error if the client has no identity set.
func (c *Client) RequireAuth() error {
	if !c.HasIdentity() {
		return ErrNotAuthenticated
	}
	return nil
}

// RegisterComputedFields registers computed fields for a dataset.
//
// Computed fields are derived values calculated from the values a query
// returns, which are unverified, enabling drop-in compatibility with The
// Graph's query interfaces.
//
// Example:
//
//	client.RegisterComputedFields("pairs", UniswapV2PairFields)
func (c *Client) RegisterComputedFields(datasetID string, fields ComputedFieldSet) {
	c.computedFields.Register(datasetID, fields)
}

// HasComputedFields checks if computed fields are registered for a dataset.
func (c *Client) HasComputedFields(datasetID string) bool {
	return c.computedFields.Has(datasetID)
}

// GetComputedFields returns the computed fields for a dataset.
func (c *Client) GetComputedFields(datasetID string) (ComputedFieldSet, bool) {
	return c.computedFields.Get(datasetID)
}

// RegisterDID returns an unsupported-operation error and sends nothing.
//
// The API serves no DID registration route: a DID is registered on chain by a
// RegisterDid transaction sent to POST /tx/submit, which this SDK does not
// build.
//
// Willow DIDs are self-certifying: the id is derived from the public key (see
// GenerateDID), not chosen. Because the fee for registration is paid from the
// derived id's own balance, a new DID must be funded (a token transfer of at
// least the registration fee to identity.DID()) before it is registered.
func (c *Client) RegisterDID(ctx context.Context, didDocument *DidDocument) (*DidDocument, error) {
	return nil, NewUnsupportedError("RegisterDID: the API serves no DID registration route; a DID is registered by a RegisterDid transaction sent to POST /tx/submit, which this SDK does not build")
}

// GetDID retrieves a DID's on-chain document. Its balance is read with
// Token.GetBalance.
func (c *Client) GetDID(ctx context.Context, did string) (*DidInfo, error) {
	var document *DidDocument
	if err := c.getData(ctx, fmt.Sprintf("/did/%s", did), &document); err != nil {
		return nil, err
	}
	if document == nil {
		return nil, &WillowError{Type: ErrorTypeNotFound, Message: "DID not found"}
	}
	return &DidInfo{Did: document.ID, Document: document, CreatedAt: document.Created}, nil
}

// Health checks the health of the node. The API answers /health with the
// status itself, not the success/data envelope.
func (c *Client) Health(ctx context.Context) (*HealthStatus, error) {
	var status HealthStatus
	err := c.get(ctx, "/health", &status)
	if err != nil {
		return nil, err
	}
	if status.Status != "" {
		status.Healthy = status.Status == "healthy"
	}
	return &status, nil
}

// GetRootHash returns the current root hash from the local node.
func (c *Client) GetRootHash(ctx context.Context) (string, error) {
	var result struct {
		RootHash string `json:"root_hash"`
	}
	err := c.getData(ctx, "/state/root-hash", &result)
	if err != nil {
		return "", err
	}
	return result.RootHash, nil
}

// GetLatestAppHash returns the app hash of the latest block, as the API reads
// it from its CometBFT node (/state/root-hash/verified). The SDK doesn't
// verify it: it is the API's value, not checked against the validators'
// commit signatures.
func (c *Client) GetLatestAppHash(ctx context.Context) (string, error) {
	var result struct {
		RootHash string `json:"root_hash"`
	}
	err := c.getData(ctx, "/state/root-hash/verified", &result)
	if err != nil {
		return "", err
	}
	return result.RootHash, nil
}

// GetVerifiedRootHash returns GetLatestAppHash: the API's value, which the
// SDK doesn't verify.
//
// Deprecated: the hash isn't verified; use GetLatestAppHash.
func (c *Client) GetVerifiedRootHash(ctx context.Context) (string, error) {
	return c.GetLatestAppHash(ctx)
}

// LightClient returns the light client, if configured.
func (c *Client) LightClient() *lightclient.LightClient {
	return c.lightClient
}

// HasLightClient returns true if a light client is configured.
func (c *Client) HasLightClient() bool {
	return c.lightClient != nil
}

// GetOrCreateLightClient returns the light client, creating one with
// trust-on-first-use if needed: it takes the RPC endpoint's latest header as
// trusted. See the lightclient package for what its VerifyHeader checks; it
// does not verify commit signatures.
func (c *Client) GetOrCreateLightClient(ctx context.Context) (*lightclient.LightClient, error) {
	if c.lightClient != nil {
		return c.lightClient, nil
	}

	c.lightClientMu.Lock()
	defer c.lightClientMu.Unlock()

	// Double-check after acquiring lock
	if c.lightClient != nil {
		return c.lightClient, nil
	}

	// Use the configured/derived CometBFT RPC endpoint (typically :3031 -> :26657)
	rpcEndpoint := c.RPCEndpoint()

	config := lightclient.Config{
		ChainID:            "willow-chain",
		ValidatorEndpoints: []string{rpcEndpoint},
		TrustThreshold:     lightclient.TrustThreshold{Numerator: 2, Denominator: 3},
		TrustingPeriod:     24 * time.Hour,
		MaxClockDrift:      30 * time.Second,
		SyncInterval:       60 * time.Second,
		RPCTimeout:         30 * time.Second,
		MaxRetries:         3,
		AutoSync:           false,
	}

	lc, err := lightclient.NewLightClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create light client: %w", err)
	}

	if err := lc.InitializeWithTrustOnFirstUse(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize light client: %w", err)
	}

	c.lightClient = lc
	c.lightClientInit = true
	return lc, nil
}

// Close closes the client and releases resources.
func (c *Client) Close() error {
	if c.lightClient != nil {
		c.lightClient.Stop()
	}
	return nil
}

// IndexerBaseURL returns the indexer URL if configured, otherwise the base API URL.
// Used to route GraphQL/SQL queries to an indexer node.
func (c *Client) IndexerBaseURL() string {
	if c.indexerURL != nil {
		return c.indexerURL.String()
	}
	return c.baseURL.String()
}

// RPCEndpoint returns the CometBFT JSON-RPC endpoint used for ABCI store
// queries. It returns the explicit override from WithRPCURL when set, otherwise
// derives it from the API URL by swapping the :3031 REST port for :26657.
func (c *Client) RPCEndpoint() string {
	if c.rpcURL != nil {
		return c.rpcURL.String()
	}
	return strings.Replace(c.baseURL.String(), ":3031", ":26657", 1)
}

// HTTP helper methods

func (c *Client) buildURL(path string) string {
	return c.baseURL.String() + path
}

// get GETs an API route whose answer is small (see httpbody.Small).
func (c *Client) get(ctx context.Context, path string, result interface{}) error {
	return c.doRequest(ctx, http.MethodGet, path, nil, httpbody.Small, result)
}

// post POSTs to an API route, reading at most limit bytes of its answer.
func (c *Client) post(ctx context.Context, path string, body interface{}, limit int64, result interface{}) error {
	return c.doRequest(ctx, http.MethodPost, path, body, limit, result)
}

func (c *Client) put(ctx context.Context, path string, body, result interface{}) error {
	return c.doRequest(ctx, http.MethodPut, path, body, httpbody.Small, result)
}

func (c *Client) delete(ctx context.Context, path string, result interface{}) error {
	return c.doRequest(ctx, http.MethodDelete, path, nil, httpbody.Small, result)
}

// doRequest sends a request to the API and decodes its answer, of at most
// limit bytes (see the httpbody caps), into result.
func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}, limit int64, result interface{}) error {
	var payload []byte
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return NewSerializationError("failed to marshal request body", err)
		}
		payload = jsonBody
	}

	resp, err := c.doWithRetry(ctx, func() (*http.Request, error) {
		return c.newAPIRequest(ctx, method, path, payload)
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := httpbody.ReadAll(resp.Body, limit)
	if err != nil {
		return NewNetworkError("failed to read response body", err)
	}

	// Check for errors
	if resp.StatusCode >= 400 {
		return c.handleErrorResponse(resp.StatusCode, respBody)
	}

	// Parse successful response
	if result != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, result); err != nil {
			return NewSerializationError("failed to unmarshal response", err)
		}
	}

	return nil
}

// apiEnvelope is the body most API routes answer with:
// {"success": bool, "data": <the result>, "error": <message or null>}.
type apiEnvelope struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data"`
	Error   *string         `json:"error"`
}

// decode returns the API's error when it reports one, else decodes data into
// result (a null or absent data leaves result as it is).
func (env *apiEnvelope) decode(result interface{}) error {
	if !env.Success || env.Error != nil {
		message := "the API reported a failure without a message"
		if env.Error != nil && *env.Error != "" {
			message = *env.Error
		}
		if strings.Contains(strings.ToLower(message), "not found") {
			return &WillowError{Type: ErrorTypeNotFound, Message: message}
		}
		return NewAPIError(message)
	}
	if result == nil || len(env.Data) == 0 || string(env.Data) == "null" {
		return nil
	}
	if err := json.Unmarshal(env.Data, result); err != nil {
		return NewSerializationError("failed to unmarshal response data", err)
	}
	return nil
}

// getData GETs an API route that answers with the envelope, its answer small
// (see httpbody.Small), and decodes its data into result.
func (c *Client) getData(ctx context.Context, path string, result interface{}) error {
	return c.requestData(ctx, http.MethodGet, path, nil, httpbody.Small, result)
}

// postData POSTs to an API route that answers with the envelope, reading at
// most limit bytes of its answer, and decodes its data into result.
func (c *Client) postData(ctx context.Context, path string, body interface{}, limit int64, result interface{}) error {
	return c.requestData(ctx, http.MethodPost, path, body, limit, result)
}

func (c *Client) requestData(ctx context.Context, method, path string, body interface{}, limit int64, result interface{}) error {
	var env apiEnvelope
	if err := c.doRequest(ctx, method, path, body, limit, &env); err != nil {
		return err
	}
	return env.decode(result)
}

// postTx posts a JSON transaction to the API's /tx/submit, which hands it to
// CheckTx, once: a transaction that reached the mempool before a 5xx would be
// sent twice by a retry. It returns the transaction's hash when CheckTx
// accepted it, an error otherwise, and what the answer leaves did's nonce as:
// accepted; given back after a 4xx (the API refused the body before CheckTx)
// or a refusal that doesn't say the nonce is held or used; or unknown after a
// network error or a 5xx, when the transaction may have reached the node.
func (c *Client) postTx(ctx context.Context, body []byte, did string, nonce uint64) (string, nonceOutcome, error) {
	var envelope struct {
		Success bool `json:"success"`
		Data    *struct {
			TxHash string `json:"tx_hash"`
			Code   int    `json:"code"`
			Log    string `json:"log"`
		} `json:"data"`
		Error *string `json:"error"`
	}
	req, err := c.newAPIRequest(ctx, http.MethodPost, "/tx/submit", body)
	if err != nil {
		return "", nonceFree, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", nonceUnknown, NewNetworkError("transaction submission failed", err)
	}
	defer resp.Body.Close()
	respBody, err := httpbody.ReadAll(resp.Body, httpbody.Small)
	if err != nil {
		return "", nonceUnknown, NewNetworkError("failed to read /tx/submit response", err)
	}
	if resp.StatusCode >= 400 {
		outcome := nonceUnknown
		if resp.StatusCode < 500 && resp.StatusCode != http.StatusRequestTimeout {
			outcome = nonceFree
		}
		return "", outcome, c.handleErrorResponse(resp.StatusCode, respBody)
	}
	if err := json.Unmarshal(respBody, &envelope); err != nil {
		return "", nonceUnknown, NewSerializationError("failed to parse /tx/submit response", err)
	}
	if !envelope.Success || envelope.Data == nil {
		message := "transaction submission failed"
		if envelope.Error != nil {
			message = *envelope.Error
		}
		return "", nonceUnknown, NewTransactionError(message, "", 0)
	}
	if envelope.Data.Code != 0 {
		return envelope.Data.TxHash, refusalOutcome(envelope.Data.Log, did, nonce),
			NewTransactionError(envelope.Data.Log, envelope.Data.TxHash, envelope.Data.Code)
	}
	return envelope.Data.TxHash, nonceAccepted, nil
}

// newAPIRequest builds one attempt of a JSON request to the API, signed by the
// identity when one is set (see signAPIRequest).
func (c *Client) newAPIRequest(ctx context.Context, method, path string, payload []byte) (*http.Request, error) {
	var bodyReader io.Reader
	if payload != nil {
		bodyReader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.buildURL(path), bodyReader)
	if err != nil {
		return nil, NewNetworkError("failed to create request", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if err := c.signAPIRequest(req, payload); err != nil {
		return nil, err
	}
	return req, nil
}

// signAPIRequest signs a request to the API when an identity is set.
//
// A read of subgrove data (see carriesReadRights) is signed with
// a one-time nonce over its method, path and query, and body: only that form
// carries the rights. payload must be the exact bytes the request sends, and
// each call draws a fresh nonce, so each attempt of a retried request is signed
// anew. Any other request is signed in the older {METHOD}:{PATH}:{TIMESTAMP}
// form, which the server also accepts for 30 s after a restart, when it refuses
// nonce-signed requests, and with up to 300 s of clock skew.
func (c *Client) signAPIRequest(req *http.Request, payload []byte) error {
	c.identityMu.RLock()
	identity := c.identity
	c.identityMu.RUnlock()
	if identity == nil {
		return nil
	}
	target := c.apiTarget(req.URL)
	var headers map[string]string
	var err error
	if carriesReadRights(req.Method, target) {
		headers, err = identity.SignRequestWithNonce(req.Method, target, payload)
	} else {
		headers, err = identity.SignRequest(req.Method, target)
	}
	if err != nil {
		return err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return nil
}

// carriesReadRights reports whether a request is a read the API gates by the
// DID a replay-protected signature proves: GET /data/{sg}/{key}, GET
// /proof/{sg}/{key}, the key-grant reads (GET /key-grants/{sg},
// /key-grants/{sg}/{did}, and /proof/key-grant/{sg}/{did}), POST /query/{sg},
// /sql/{sg}, /graphql/{sg}, and POST /a2a.
func carriesReadRights(method, target string) bool {
	path := target
	if q := strings.IndexByte(path, '?'); q >= 0 {
		path = path[:q]
	}
	segments := strings.Split(strings.TrimPrefix(path, "/"), "/")
	switch method {
	case http.MethodGet:
		switch segments[0] {
		case "data":
			return len(segments) == 3
		case "proof":
			return len(segments) == 3 || (len(segments) == 4 && segments[1] == "key-grant")
		case "key-grants":
			return len(segments) == 2 || len(segments) == 3
		}
		return false
	case http.MethodPost:
		switch segments[0] {
		case "query", "sql", "graphql":
			return len(segments) == 2
		case "a2a":
			return len(segments) == 1
		}
	}
	return false
}

// apiTarget is the path and query the API receives for u: the request line's
// target, less any path the API base URL carries (a proxy mounted under a path
// strips it before the API sees the request).
func (c *Client) apiTarget(u *url.URL) string {
	target := u.RequestURI()
	if base := strings.TrimSuffix(c.baseURL.EscapedPath(), "/"); base != "" && strings.HasPrefix(target, base+"/") {
		target = target[len(base):]
	}
	return target
}

// doWithRetry sends the request newReq builds, retrying network errors and 5xx
// answers with backoff. Each attempt is built anew, so its body is whole and a
// signed attempt carries its own nonce.
func (c *Client) doWithRetry(ctx context.Context, newReq func() (*http.Request, error)) (*http.Response, error) {
	var lastErr error
	backoff := c.retryConfig.InitialBackoff

	for attempt := 0; attempt <= c.retryConfig.MaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}

			// Increase backoff
			backoff = time.Duration(float64(backoff) * c.retryConfig.BackoffFactor)
			if backoff > c.retryConfig.MaxBackoff {
				backoff = c.retryConfig.MaxBackoff
			}
		}

		req, err := newReq()
		if err != nil {
			return nil, err
		}
		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = NewNetworkError("request failed", err)
			continue
		}

		// Don't retry on client errors (4xx)
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return resp, nil
		}

		// Retry on server errors (5xx) and network errors
		if resp.StatusCode >= 500 {
			resp.Body.Close()
			lastErr = NewHTTPError(resp.StatusCode, "server error")
			continue
		}

		return resp, nil
	}

	return nil, lastErr
}

func (c *Client) handleErrorResponse(statusCode int, body []byte) error {
	// Try to parse error response
	var errorResp struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &errorResp); err == nil {
		message := errorResp.Error
		if message == "" {
			message = errorResp.Message
		}

		switch statusCode {
		case http.StatusUnauthorized:
			return NewAuthenticationError(message)
		case http.StatusForbidden:
			return NewPermissionDeniedError(message)
		case http.StatusNotFound:
			return &WillowError{Type: ErrorTypeNotFound, Message: message}
		case http.StatusBadRequest:
			return NewValidationError(message)
		default:
			return NewHTTPError(statusCode, message)
		}
	}

	return NewHTTPError(statusCode, string(body))
}
