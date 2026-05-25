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

	"github.com/willow-network/willow-go/lightclient"
)

// Client is the main client for interacting with the Willow network.
type Client struct {
	httpClient      *http.Client
	baseURL         *url.URL
	indexerURL      *url.URL // Optional indexer node URL for GraphQL/SQL routing
	identity        *Identity
	identityMu      sync.RWMutex
	retryConfig     RetryConfig
	lightClient     *lightclient.LightClient
	lightClientMu   sync.Mutex
	lightClientInit bool

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

// NewClient creates a new Willow client with the given API URL and options.
func NewClient(apiURL string, opts ...ClientOption) (*Client, error) {
	parsedURL, err := url.Parse(strings.TrimSuffix(apiURL, "/"))
	if err != nil {
		return nil, NewConfigError(fmt.Sprintf("invalid API URL: %s", err))
	}

	client := &Client{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL:        parsedURL,
		retryConfig:    DefaultRetryConfig(),
		computedFields: NewComputedFieldRegistry(),
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

// WithLightClient enables light client verification.
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
// Computed fields are derived values calculated from proven data,
// enabling drop-in compatibility with The Graph's query interfaces.
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

// RegisterDID registers a new DID document.
func (c *Client) RegisterDID(ctx context.Context, didDocument *DidDocument) (*DidDocument, error) {
	var result DidDocument
	err := c.post(ctx, "/did", didDocument, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// GetDID retrieves information about a DID.
func (c *Client) GetDID(ctx context.Context, did string) (*DidInfo, error) {
	var info DidInfo
	err := c.get(ctx, fmt.Sprintf("/did/%s", did), &info)
	if err != nil {
		return nil, err
	}
	return &info, nil
}

// Health checks the health of the node.
func (c *Client) Health(ctx context.Context) (*HealthStatus, error) {
	var status HealthStatus
	err := c.get(ctx, "/health", &status)
	if err != nil {
		return nil, err
	}
	return &status, nil
}

// GetRootHash returns the current root hash from the local node.
func (c *Client) GetRootHash(ctx context.Context) (string, error) {
	var result struct {
		RootHash string `json:"root_hash"`
	}
	err := c.get(ctx, "/state/root-hash", &result)
	if err != nil {
		return "", err
	}
	return result.RootHash, nil
}

// GetVerifiedRootHash returns the verified root hash from consensus.
func (c *Client) GetVerifiedRootHash(ctx context.Context) (string, error) {
	var result struct {
		RootHash string `json:"root_hash"`
		Height   int64  `json:"height"`
	}
	err := c.get(ctx, "/state/root-hash/verified", &result)
	if err != nil {
		return "", err
	}
	return result.RootHash, nil
}

// LightClient returns the light client, if configured.
func (c *Client) LightClient() *lightclient.LightClient {
	return c.lightClient
}

// HasLightClient returns true if a light client is configured.
func (c *Client) HasLightClient() bool {
	return c.lightClient != nil
}

// GetOrCreateLightClient returns the light client, creating one with trust-on-first-use if needed.
//
// Trust-on-first-use bootstrap: the first verified header is trusted, and
// every subsequent header chains from it cryptographically. Pin a known-good
// checkpoint header in production deployments.
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

	// Derive CometBFT RPC endpoint from API URL (typically :3031 -> :26657)
	rpcEndpoint := strings.Replace(c.baseURL.String(), ":3031", ":26657", 1)

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

// HTTP helper methods

func (c *Client) buildURL(path string) string {
	return c.baseURL.String() + path
}

func (c *Client) get(ctx context.Context, path string, result interface{}) error {
	return c.doRequest(ctx, http.MethodGet, path, nil, result)
}

func (c *Client) post(ctx context.Context, path string, body, result interface{}) error {
	return c.doRequest(ctx, http.MethodPost, path, body, result)
}

func (c *Client) put(ctx context.Context, path string, body, result interface{}) error {
	return c.doRequest(ctx, http.MethodPut, path, body, result)
}

func (c *Client) delete(ctx context.Context, path string, result interface{}) error {
	return c.doRequest(ctx, http.MethodDelete, path, nil, result)
}

func (c *Client) doRequest(ctx context.Context, method, path string, body, result interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return NewSerializationError("failed to marshal request body", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.buildURL(path), bodyReader)
	if err != nil {
		return NewNetworkError("failed to create request", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Add signature headers if identity is set
	c.identityMu.RLock()
	identity := c.identity
	c.identityMu.RUnlock()
	if identity != nil {
		headers, err := identity.SignRequest(method, path)
		if err == nil {
			for k, v := range headers {
				req.Header.Set(k, v)
			}
		}
	}

	resp, err := c.doWithRetry(ctx, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
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

func (c *Client) doWithRetry(ctx context.Context, req *http.Request) (*http.Response, error) {
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

			// Clone request for retry
			req = req.Clone(ctx)
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
			return NewNotFoundError(message)
		case http.StatusBadRequest:
			return NewValidationError(message)
		default:
			return NewHTTPError(statusCode, message)
		}
	}

	return NewHTTPError(statusCode, string(body))
}
