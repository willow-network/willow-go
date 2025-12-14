package consensus

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client provides methods for interacting with the CometBFT consensus layer.
type Client struct {
	httpClient *http.Client
	rpcURL     string
}

// ClientConfig contains configuration for the consensus client.
type ClientConfig struct {
	RPCURL  string
	Timeout time.Duration
}

// DefaultClientConfig returns the default configuration.
func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		RPCURL:  "http://localhost:26657",
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
	}
}

// BroadcastTxSync broadcasts a transaction synchronously.
func (c *Client) BroadcastTxSync(ctx context.Context, tx interface{}) (*BroadcastResult, error) {
	// Serialize the transaction
	txBytes, err := json.Marshal(tx)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize transaction: %w", err)
	}

	// Base64 encode
	txB64 := base64.StdEncoding.EncodeToString(txBytes)

	// Make RPC request
	rpcReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "broadcast_tx_sync",
		"params": map[string]interface{}{
			"tx": txB64,
		},
	}

	resp, err := c.doRPCRequest(ctx, rpcReq)
	if err != nil {
		return nil, err
	}

	// Parse response
	result := &BroadcastResult{}
	if resp.Error != nil {
		result.Success = false
		result.ErrorMessage = resp.Error.Message
		result.ErrorCode = resp.Error.Code
		return result, nil
	}

	if resp.Result != nil {
		var txResp struct {
			Code int    `json:"code"`
			Data string `json:"data"`
			Log  string `json:"log"`
			Hash string `json:"hash"`
		}
		if err := json.Unmarshal(resp.Result, &txResp); err == nil {
			result.TxHash = txResp.Hash
			result.RawLog = txResp.Log
			if txResp.Code == 0 {
				result.Success = true
			} else {
				result.Success = false
				result.ErrorCode = txResp.Code
				result.ErrorMessage = txResp.Log
			}
		}
	}

	return result, nil
}

// BroadcastTxAsync broadcasts a transaction asynchronously.
func (c *Client) BroadcastTxAsync(ctx context.Context, tx interface{}) (*BroadcastResult, error) {
	// Serialize the transaction
	txBytes, err := json.Marshal(tx)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize transaction: %w", err)
	}

	// Base64 encode
	txB64 := base64.StdEncoding.EncodeToString(txBytes)

	// Make RPC request
	rpcReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "broadcast_tx_async",
		"params": map[string]interface{}{
			"tx": txB64,
		},
	}

	resp, err := c.doRPCRequest(ctx, rpcReq)
	if err != nil {
		return nil, err
	}

	// Parse response
	result := &BroadcastResult{}
	if resp.Error != nil {
		result.Success = false
		result.ErrorMessage = resp.Error.Message
		result.ErrorCode = resp.Error.Code
		return result, nil
	}

	if resp.Result != nil {
		var txResp struct {
			Hash string `json:"hash"`
		}
		if err := json.Unmarshal(resp.Result, &txResp); err == nil {
			result.TxHash = txResp.Hash
			result.Success = true
		}
	}

	return result, nil
}

// BroadcastTxCommit broadcasts a transaction and waits for it to be committed.
func (c *Client) BroadcastTxCommit(ctx context.Context, tx interface{}) (*BroadcastResult, error) {
	// Serialize the transaction
	txBytes, err := json.Marshal(tx)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize transaction: %w", err)
	}

	// Base64 encode
	txB64 := base64.StdEncoding.EncodeToString(txBytes)

	// Make RPC request
	rpcReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "broadcast_tx_commit",
		"params": map[string]interface{}{
			"tx": txB64,
		},
	}

	resp, err := c.doRPCRequest(ctx, rpcReq)
	if err != nil {
		return nil, err
	}

	// Parse response
	result := &BroadcastResult{}
	if resp.Error != nil {
		result.Success = false
		result.ErrorMessage = resp.Error.Message
		result.ErrorCode = resp.Error.Code
		return result, nil
	}

	if resp.Result != nil {
		var txResp struct {
			CheckTx struct {
				Code int    `json:"code"`
				Log  string `json:"log"`
			} `json:"check_tx"`
			DeliverTx struct {
				Code int    `json:"code"`
				Log  string `json:"log"`
			} `json:"deliver_tx"`
			Hash   string `json:"hash"`
			Height string `json:"height"`
		}
		if err := json.Unmarshal(resp.Result, &txResp); err == nil {
			result.TxHash = txResp.Hash
			result.RawLog = txResp.DeliverTx.Log

			if txResp.CheckTx.Code != 0 {
				result.Success = false
				result.ErrorCode = txResp.CheckTx.Code
				result.ErrorMessage = txResp.CheckTx.Log
			} else if txResp.DeliverTx.Code != 0 {
				result.Success = false
				result.ErrorCode = txResp.DeliverTx.Code
				result.ErrorMessage = txResp.DeliverTx.Log
			} else {
				result.Success = true
			}
		}
	}

	return result, nil
}

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
