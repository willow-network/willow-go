package willow

// End-to-end client-side completeness verification.
//
// VerifyBlockCompleteness fetches the two pieces a client needs to verify an
// indexer's served event set without trusting it, then checks them against the
// pure spec in completeness.go:
//
//  1. the on-chain anchor — the 32-byte events_commitment the chain attests to,
//     read via a CometBFT ABCI store query against the validator RPC; and
//  2. the matched-log preimage — the indexer's canonical filter-matched logs,
//     fetched over HTTP from the indexer's completeness route.
//
// The client rebuilds the Log set from {address, topics, data} and re-hashes it
// with VerifyServedEvents. A true result means the served set is exactly the
// matched events the commitment binds (no drop, add, or reorder), with the
// commitment as the RPC node reports it: the node's ABCI answer for the anchor
// carries no proof, so the SDK trusts that node for the commitment (and
// checks only that its answer is for the subgrove and block asked for). It
// doesn't trust the indexer.

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/willow-network/willow-go/internal/httpbody"
)

// matchedLogJSON mirrors the indexer's served IndexedLog. Only the three
// commitment-bound fields are decoded; the rest (block_number, block_hash,
// transaction_hash, transaction_index, log_index, removed) are intentionally
// ignored because they are not bound by the events_commitment.
type matchedLogJSON struct {
	Address string   `json:"address"`
	Topics  []string `json:"topics"`
	Data    string   `json:"data"`
}

// matchedLogsResponse is the body of GET /completeness/{sg}/{block}/matched-logs.
type matchedLogsResponse struct {
	SubgroveID  string           `json:"subgrove_id"`
	BlockNumber uint64           `json:"block_number"`
	Count       int              `json:"count"`
	MatchedLogs []matchedLogJSON `json:"matched_logs"`
}

// decodeHexBytes parses a 0x-prefixed (or bare) hex string into bytes.
// An empty value ("" or "0x") decodes to a zero-length slice.
func decodeHexBytes(s string) ([]byte, error) {
	return hex.DecodeString(strings.TrimPrefix(s, "0x"))
}

// parseMatchedLog converts one served IndexedLog into a Log, validating that
// the address is 20 bytes and every topic is 32 bytes.
func parseMatchedLog(m matchedLogJSON) (Log, error) {
	var log Log

	addr, err := decodeHexBytes(m.Address)
	if err != nil {
		return log, fmt.Errorf("invalid address hex %q: %w", m.Address, err)
	}
	if len(addr) != 20 {
		return log, fmt.Errorf("address must be 20 bytes, got %d", len(addr))
	}
	copy(log.Address[:], addr)

	log.Topics = make([][32]byte, len(m.Topics))
	for i, t := range m.Topics {
		tb, err := decodeHexBytes(t)
		if err != nil {
			return log, fmt.Errorf("invalid topic hex %q: %w", t, err)
		}
		if len(tb) != 32 {
			return log, fmt.Errorf("topic must be 32 bytes, got %d", len(tb))
		}
		copy(log.Topics[i][:], tb)
	}

	data, err := decodeHexBytes(m.Data)
	if err != nil {
		return log, fmt.Errorf("invalid data hex %q: %w", m.Data, err)
	}
	log.Data = data

	return log, nil
}

// parseMatchedLogs converts the served matched-logs response body into a Log
// slice in the order served — the same order the commitment hashes them.
func parseMatchedLogs(body []byte) ([]Log, error) {
	var resp matchedLogsResponse
	if err := httpbody.Unmarshal(body, &resp); err != nil {
		return nil, NewSerializationError("failed to unmarshal matched-logs response", err)
	}
	logs := make([]Log, len(resp.MatchedLogs))
	for i, m := range resp.MatchedLogs {
		log, err := parseMatchedLog(m)
		if err != nil {
			return nil, NewValidationError(fmt.Sprintf("matched_logs[%d]: %v", i, err))
		}
		logs[i] = log
	}
	return logs, nil
}

// FetchEventsCommitment reads a block's on-chain events_commitment anchor via a
// CometBFT ABCI store query against the validator RPC endpoint. It returns the
// 32-byte commitment on success. A non-zero ABCI response code (e.g. no anchor
// stored for the block) is surfaced as an error: the block is not verifiable.
//
// The commitment is the RPC node's answer, which the SDK trusts: the node
// answers this query with no proof, so nothing binds it to a verified header.
// The RPC node is the one WithRPCURL names; without it, the API URL with its
// :3031 replaced by :26657 (the API's host), or, when the API URL has no
// :3031, the API URL itself (see RPCEndpoint). An answer about another
// subgrove or block than the one asked for is an error.
func (c *Client) FetchEventsCommitment(ctx context.Context, subgroveID string, blockNumber uint64) ([32]byte, error) {
	var out [32]byte

	path := fmt.Sprintf("/store/events_commitment/%s/%d", subgroveID, blockNumber)
	rpcReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "abci_query",
		"params": map[string]interface{}{
			"path":   path,
			"data":   "",
			"height": "0",
			"prove":  false,
		},
	}

	body, err := json.Marshal(rpcReq)
	if err != nil {
		return out, NewSerializationError("failed to marshal abci_query request", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.RPCEndpoint(), bytes.NewReader(body))
	if err != nil {
		return out, NewNetworkError("failed to create abci_query request", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return out, NewNetworkError("abci_query request failed", err)
	}
	defer resp.Body.Close()

	var rpcResp struct {
		Result struct {
			Response struct {
				Code  int    `json:"code"`
				Log   string `json:"log"`
				Value string `json:"value"` // base64 of the JSON anchor body
			} `json:"response"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := httpbody.Decode(resp.Body, httpbody.Small, &rpcResp); err != nil {
		return out, NewSerializationError("failed to decode abci_query response", err)
	}
	if rpcResp.Error != nil {
		return out, NewConsensusError(fmt.Sprintf("abci_query RPC error: %s", rpcResp.Error.Message), nil)
	}
	if rpcResp.Result.Response.Code != 0 {
		return out, NewNotFoundError(fmt.Sprintf("no events commitment for block %d: %s", blockNumber, rpcResp.Result.Response.Log))
	}

	valueBytes, err := decodeBase64(rpcResp.Result.Response.Value)
	if err != nil {
		return out, NewSerializationError("failed to base64-decode abci_query value", err)
	}

	var anchor struct {
		SubgroveID       string `json:"subgrove_id"`
		BlockNumber      uint64 `json:"block_number"`
		EventsCommitment string `json:"events_commitment"`
	}
	if err := json.Unmarshal(valueBytes, &anchor); err != nil {
		return out, NewSerializationError("failed to unmarshal events_commitment anchor", err)
	}
	if anchor.SubgroveID != subgroveID || anchor.BlockNumber != blockNumber {
		return out, NewValidationError(fmt.Sprintf("the events_commitment anchor answered is for subgrove %q block %d, not subgrove %q block %d",
			anchor.SubgroveID, anchor.BlockNumber, subgroveID, blockNumber))
	}

	commitment, err := hex.DecodeString(strings.TrimPrefix(anchor.EventsCommitment, "0x"))
	if err != nil {
		return out, NewSerializationError("failed to decode events_commitment hex", err)
	}
	if len(commitment) != 32 {
		return out, NewValidationError(fmt.Sprintf("events_commitment must be 32 bytes, got %d", len(commitment)))
	}
	copy(out[:], commitment)
	return out, nil
}

// FetchMatchedLogs fetches the indexer's canonical filter-matched log set for a
// block — the events_commitment preimage — and parses it into Log values in the
// order served. A non-200 response (e.g. 404 when the indexer retained no
// matched logs, or the block is not finalized) is surfaced as an error: the
// block is not verifiable from this indexer.
//
// Only indexers serve matched logs, so the client needs an indexer URL
// (WithIndexerURL).
func (c *Client) FetchMatchedLogs(ctx context.Context, subgroveID string, blockNumber uint64) ([]Log, error) {
	if c.indexerURL == nil {
		return nil, NewConfigError("matched logs are served by indexers: configure one with WithIndexerURL")
	}
	url := fmt.Sprintf("%s/completeness/%s/%d/matched-logs", c.IndexerBaseURL(), subgroveID, blockNumber)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, NewNetworkError("failed to create matched-logs request", err)
	}
	httpReq.Header.Set("Accept", "application/json")

	c.identityMu.RLock()
	identity := c.identity
	c.identityMu.RUnlock()
	if identity != nil {
		path := fmt.Sprintf("/completeness/%s/%d/matched-logs", subgroveID, blockNumber)
		if headers, err := identity.SignRequest(http.MethodGet, path); err == nil {
			for k, v := range headers {
				httpReq.Header.Set(k, v)
			}
		}
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, NewNetworkError("matched-logs request failed", err)
	}
	defer resp.Body.Close()

	respBody, err := httpbody.ReadAll(resp.Body, httpbody.Large)
	if err != nil {
		return nil, NewNetworkError("failed to read matched-logs response", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleErrorResponse(resp.StatusCode, respBody)
	}

	return parseMatchedLogs(respBody)
}

// VerifyBlockCompleteness performs the client-side completeness check for a
// (subgrove, block): it fetches the events_commitment anchor and the indexer's
// matched-log preimage, then verifies the latter re-hashes to the former. It
// returns true only when the served event set is exactly the filter-matched
// set the commitment binds. The commitment is the RPC node's answer, which the
// SDK trusts (see FetchEventsCommitment): the check removes trust in the
// indexer, not in that node. Without WithRPCURL that node is the API's host
// (the API URL with :3031 replaced by :26657), or the API itself when its URL
// has no :3031, so the check then trusts the API's operator.
//
// An error is returned when either fetch fails or the block is not verifiable
// (no on-chain anchor, or the indexer retained no matched logs). A non-nil
// error with a false result is the not-verifiable case; a nil error with a
// false result means the served set did not match the anchor (tampered,
// incomplete, reordered, or wrong block).
func (c *Client) VerifyBlockCompleteness(ctx context.Context, subgroveID string, blockNumber uint64) (bool, error) {
	commitment, err := c.FetchEventsCommitment(ctx, subgroveID, blockNumber)
	if err != nil {
		return false, err
	}

	logs, err := c.FetchMatchedLogs(ctx, subgroveID, blockNumber)
	if err != nil {
		return false, err
	}

	return VerifyServedEvents(commitment, blockNumber, logs), nil
}
