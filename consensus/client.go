package consensus

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/willow-network/willow-go/internal/httpbody"
)

// Client provides methods for interacting with the CometBFT consensus layer.
type Client struct {
	httpClient *http.Client
	rpcURL     string
	apiURL     string
}

// ClientConfig contains configuration for the consensus client.
type ClientConfig struct {
	// RPCURL is CometBFT's JSON-RPC endpoint (used for read-only
	// queries: status, block, validators, etc.).
	RPCURL string
	// APIURL is the Willow REST API endpoint. Transaction submission
	// goes through its /tx/submit endpoint because the validator's
	// on-the-wire format is bincode.
	APIURL string
	// Timeout is the HTTP client's timeout; 0 is DefaultClientConfig's.
	Timeout time.Duration
}

// DefaultClientConfig returns the default configuration.
func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		RPCURL:  "http://localhost:26657",
		APIURL:  "http://localhost:3031",
		Timeout: 30 * time.Second,
	}
}

// NewClient creates a new consensus client.
func NewClient(config ClientConfig) *Client {
	if config.Timeout == 0 {
		config.Timeout = DefaultClientConfig().Timeout
	}
	return &Client{
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
		rpcURL: config.RPCURL,
		apiURL: config.APIURL,
	}
}

// BroadcastTxSync submits a transaction through the Willow API server's
// /tx/submit endpoint. The server bincode-encodes the JSON body and
// forwards to CometBFT's broadcast_tx_sync — the chain's on-the-wire
// format is bincode, so SDKs send JSON and let the server handle the
// bincode conversion.
func (c *Client) BroadcastTxSync(ctx context.Context, tx interface{}) (*BroadcastResult, error) {
	if c.apiURL == "" {
		return nil, fmt.Errorf("APIURL is required for transaction submission; set it in ClientConfig")
	}

	body, err := json.Marshal(tx)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize transaction: %w", err)
	}

	url := strings.TrimRight(c.apiURL, "/") + "/tx/submit"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("tx submit request failed: %w", err)
	}
	defer httpResp.Body.Close()

	respBody, err := httpbody.ReadAll(httpResp.Body, httpbody.Small)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var envelope struct {
		Success bool `json:"success"`
		Data    *struct {
			TxHash string `json:"tx_hash"`
			Code   int    `json:"code"`
			Log    string `json:"log"`
		} `json:"data"`
		Error *string `json:"error"`
	}
	if err := httpbody.Unmarshal(respBody, &envelope); err != nil {
		return nil, fmt.Errorf("failed to parse /tx/submit response: %w", err)
	}

	result := &BroadcastResult{}
	if !envelope.Success || envelope.Data == nil {
		result.Success = false
		if envelope.Error != nil {
			result.ErrorMessage = *envelope.Error
		} else {
			result.ErrorMessage = fmt.Sprintf("HTTP %d", httpResp.StatusCode)
		}
		return result, nil
	}

	result.TxHash = envelope.Data.TxHash
	result.RawLog = envelope.Data.Log
	if envelope.Data.Code == 0 {
		result.Success = true
	} else {
		result.Success = false
		result.ErrorCode = envelope.Data.Code
		result.ErrorMessage = envelope.Data.Log
	}
	return result, nil
}

// BroadcastTxAsync and BroadcastTxCommit were removed after the bincode
// wire migration. The API server only exposes `/tx/submit` (which maps
// to `broadcast_tx_sync` under the hood); callers that need fire-and-
// forget or wait-for-commit semantics should layer that on top of
// BroadcastTxSync + GetTx polling, not speak JSON-RPC directly to
// CometBFT (the validator no longer accepts JSON on the wire).

// GetTx looks a transaction up by its hash: the hex TxHash /tx/submit returns
// (either case, with or without a 0x prefix). CometBFT's JSON-RPC reads the
// tx method's hash as base64 of its 32 bytes, so GetTx sends it that way. A
// transaction the node hasn't indexed (not in a block yet, or never) is a
// TxResult with Status TransactionStatusNotFound; one in a block has its
// Height and its block result's Code and Log (Code 0 is applied; a refusal's
// Log ends "(nonce N spent)" when the refusal used its nonce). An answer whose
// hash isn't the one asked for is an error. The result is the RPC node's
// word: nothing in its answer is verified against the chain.
func (c *Client) GetTx(ctx context.Context, hash string) (*TxResult, error) {
	raw, err := txHashBytes(hash)
	if err != nil {
		return nil, err
	}
	rpcReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tx",
		"params": map[string]interface{}{
			"hash":  base64.StdEncoding.EncodeToString(raw),
			"prove": false,
		},
	}

	resp, err := c.doRPCRequest(ctx, rpcReq, httpbody.Tx)
	if err != nil {
		return nil, err
	}

	if resp.Error != nil {
		// CometBFT answers an unknown hash with an internal error whose data
		// says "tx (<HASH>) not found" or "tx not found: <HASH>".
		if resp.Error.Code == -32603 && strings.Contains(resp.Error.Data, "not found") {
			return &TxResult{
				Hash:   hash,
				Status: TransactionStatusNotFound,
			}, nil
		}
		return nil, fmt.Errorf("RPC error: %s %s", resp.Error.Message, resp.Error.Data)
	}

	var txResp struct {
		Hash     string    `json:"hash"`
		Height   jsonInt64 `json:"height"`
		Index    uint32    `json:"index"`
		TxResult struct {
			Code    uint32          `json:"code"`
			Log     string          `json:"log"`
			GasUsed jsonInt64       `json:"gas_used"`
			GasWant jsonInt64       `json:"gas_wanted"`
			Data    json.RawMessage `json:"data"`
		} `json:"tx_result"`
	}

	if err := json.Unmarshal(resp.Result, &txResp); err != nil {
		return nil, fmt.Errorf("failed to parse transaction: %w", err)
	}
	if answered, err := txHashBytes(txResp.Hash); err != nil || !bytes.Equal(answered, raw) {
		return nil, fmt.Errorf("the RPC answered for transaction %.80q, not %s", txResp.Hash, hash)
	}

	result := &TxResult{
		Hash:    txResp.Hash,
		Height:  int64(txResp.Height),
		Index:   txResp.Index,
		Code:    txResp.TxResult.Code,
		Log:     txResp.TxResult.Log,
		GasUsed: int64(txResp.TxResult.GasUsed),
		GasWant: int64(txResp.TxResult.GasWant),
		Data:    txResp.TxResult.Data,
	}

	if txResp.TxResult.Code == 0 {
		result.Status = TransactionStatusSuccess
	} else {
		result.Status = TransactionStatusFailed
	}

	return result, nil
}

// txHashBytes reads a transaction hash given as hex (either case, with or
// without a 0x prefix): CometBFT's, a SHA-256 of 32 bytes.
func txHashBytes(hash string) ([]byte, error) {
	bare := strings.TrimPrefix(strings.TrimPrefix(hash, "0x"), "0X")
	raw, err := hex.DecodeString(bare)
	if err != nil {
		return nil, fmt.Errorf("transaction hash %q is not hex: %w", hash, err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("transaction hash %q is %d bytes, not 32", hash, len(raw))
	}
	return raw, nil
}

// jsonInt64 reads an int64 CometBFT writes as a decimal string (or a number).
type jsonInt64 int64

// UnmarshalJSON implements json.Unmarshaler.
func (n *jsonInt64) UnmarshalJSON(data []byte) error {
	text := string(data)
	if text == "null" {
		return nil
	}
	if unquoted, err := strconv.Unquote(text); err == nil {
		text = unquoted
	}
	v, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return fmt.Errorf("not an integer: %s", data)
	}
	*n = jsonInt64(v)
	return nil
}

// GetStatus retrieves the node status.
func (c *Client) GetStatus(ctx context.Context) (map[string]interface{}, error) {
	rpcReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "status",
		"params":  map[string]interface{}{},
	}

	resp, err := c.doRPCRequest(ctx, rpcReq, httpbody.Small)
	if err != nil {
		return nil, err
	}

	if resp.Error != nil {
		return nil, fmt.Errorf("RPC error: %s", resp.Error.Message)
	}

	var status map[string]interface{}
	if err := json.Unmarshal(resp.Result, &status); err != nil {
		return nil, fmt.Errorf("failed to parse status: %w", err)
	}

	return status, nil
}

// GetLatestBlock retrieves the latest block.
func (c *Client) GetLatestBlock(ctx context.Context) (map[string]interface{}, error) {
	rpcReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "block",
		"params":  map[string]interface{}{},
	}

	resp, err := c.doRPCRequest(ctx, rpcReq, httpbody.Block)
	if err != nil {
		return nil, err
	}

	if resp.Error != nil {
		return nil, fmt.Errorf("RPC error: %s", resp.Error.Message)
	}

	var block map[string]interface{}
	if err := json.Unmarshal(resp.Result, &block); err != nil {
		return nil, fmt.Errorf("failed to parse block: %w", err)
	}

	return block, nil
}

// GetBlock retrieves a block by height.
func (c *Client) GetBlock(ctx context.Context, height int64) (map[string]interface{}, error) {
	rpcReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "block",
		"params": map[string]interface{}{
			"height": fmt.Sprintf("%d", height),
		},
	}

	resp, err := c.doRPCRequest(ctx, rpcReq, httpbody.Block)
	if err != nil {
		return nil, err
	}

	if resp.Error != nil {
		return nil, fmt.Errorf("RPC error: %s", resp.Error.Message)
	}

	var block map[string]interface{}
	if err := json.Unmarshal(resp.Result, &block); err != nil {
		return nil, fmt.Errorf("failed to parse block: %w", err)
	}

	return block, nil
}

// GetValidators retrieves the validators at a given height.
func (c *Client) GetValidators(ctx context.Context, height int64) (map[string]interface{}, error) {
	params := map[string]interface{}{}
	if height > 0 {
		params["height"] = fmt.Sprintf("%d", height)
	}

	rpcReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "validators",
		"params":  params,
	}

	resp, err := c.doRPCRequest(ctx, rpcReq, httpbody.Small)
	if err != nil {
		return nil, err
	}

	if resp.Error != nil {
		return nil, fmt.Errorf("RPC error: %s", resp.Error.Message)
	}

	var validators map[string]interface{}
	if err := json.Unmarshal(resp.Result, &validators); err != nil {
		return nil, fmt.Errorf("failed to parse validators: %w", err)
	}

	return validators, nil
}

// GetCommit retrieves the commit at a given height.
func (c *Client) GetCommit(ctx context.Context, height int64) (map[string]interface{}, error) {
	params := map[string]interface{}{}
	if height > 0 {
		params["height"] = fmt.Sprintf("%d", height)
	}

	rpcReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "commit",
		"params":  params,
	}

	resp, err := c.doRPCRequest(ctx, rpcReq, httpbody.Small)
	if err != nil {
		return nil, err
	}

	if resp.Error != nil {
		return nil, fmt.Errorf("RPC error: %s", resp.Error.Message)
	}

	var commit map[string]interface{}
	if err := json.Unmarshal(resp.Result, &commit); err != nil {
		return nil, fmt.Errorf("failed to parse commit: %w", err)
	}

	return commit, nil
}

// RPCResponse represents a JSON-RPC response.
type RPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// RPCError represents a JSON-RPC error.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data,omitempty"`
}

// doRPCRequest sends a JSON-RPC request to CometBFT and reads its answer, of
// at most limit bytes (see the httpbody caps).
func (c *Client) doRPCRequest(ctx context.Context, req interface{}, limit int64) (*RPCResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.rpcURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := httpbody.ReadAll(resp.Body, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var rpcResp RPCResponse
	if err := httpbody.Unmarshal(respBody, &rpcResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &rpcResp, nil
}
