package consensus

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
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
	// on-the-wire format is bincode — see
	// docs/todo/proposal-bincode-wire.md.
	APIURL  string
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
// format is bincode (see docs/todo/proposal-bincode-wire.md), so SDKs
// send JSON and let the server handle the bincode conversion.
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

	respBody, err := io.ReadAll(httpResp.Body)
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
	if err := json.Unmarshal(respBody, &envelope); err != nil {
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

// GetTx retrieves a transaction by hash.
func (c *Client) GetTx(ctx context.Context, hash string) (*TxResult, error) {
	rpcReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tx",
		"params": map[string]interface{}{
			"hash": hash,
		},
	}

	resp, err := c.doRPCRequest(ctx, rpcReq)
	if err != nil {
		return nil, err
	}

	if resp.Error != nil {
		if resp.Error.Code == -32603 { // Transaction not found
			return &TxResult{
				Hash:   hash,
				Status: TransactionStatusNotFound,
			}, nil
		}
		return nil, fmt.Errorf("RPC error: %s", resp.Error.Message)
	}

	var txResp struct {
		Hash     string `json:"hash"`
		Height   string `json:"height"`
		Index    uint32 `json:"index"`
		TxResult struct {
			Code    uint32          `json:"code"`
			Log     string          `json:"log"`
			GasUsed string          `json:"gas_used"`
			GasWant string          `json:"gas_wanted"`
			Data    json.RawMessage `json:"data"`
		} `json:"tx_result"`
	}

	if err := json.Unmarshal(resp.Result, &txResp); err != nil {
		return nil, fmt.Errorf("failed to parse transaction: %w", err)
	}

	result := &TxResult{
		Hash:  txResp.Hash,
		Index: txResp.Index,
		Code:  txResp.TxResult.Code,
		Log:   txResp.TxResult.Log,
		Data:  txResp.TxResult.Data,
	}

	if txResp.TxResult.Code == 0 {
		result.Status = TransactionStatusSuccess
	} else {
		result.Status = TransactionStatusFailed
	}

	return result, nil
}

// GetStatus retrieves the node status.
func (c *Client) GetStatus(ctx context.Context) (map[string]interface{}, error) {
	rpcReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "status",
		"params":  map[string]interface{}{},
	}

	resp, err := c.doRPCRequest(ctx, rpcReq)
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

	resp, err := c.doRPCRequest(ctx, rpcReq)
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

	resp, err := c.doRPCRequest(ctx, rpcReq)
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

	resp, err := c.doRPCRequest(ctx, rpcReq)
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

	resp, err := c.doRPCRequest(ctx, rpcReq)
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

func (c *Client) doRPCRequest(ctx context.Context, req interface{}) (*RPCResponse, error) {
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

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var rpcResp RPCResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &rpcResp, nil
}
