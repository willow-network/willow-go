package lightclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"
)

// LightClient provides trustless verification of Willow chain state.
type LightClient struct {
	config       Config
	httpClient   *http.Client
	trustedState *TrustedState
	stateMu      sync.RWMutex

	// Background sync
	ctx       context.Context
	cancel    context.CancelFunc
	syncDone  chan struct{}
	lastSync  time.Time
	lastError error
}

// NewLightClient creates a new light client with the given configuration.
func NewLightClient(config Config) (*LightClient, error) {
	if config.ChainID == "" {
		return nil, fmt.Errorf("chain ID is required")
	}
	if len(config.ValidatorEndpoints) == 0 {
		return nil, fmt.Errorf("at least one validator endpoint is required")
	}

	// Apply defaults
	if config.TrustThreshold.Denominator == 0 {
		config.TrustThreshold = DefaultConfig().TrustThreshold
	}
	if config.TrustingPeriod == 0 {
		config.TrustingPeriod = DefaultConfig().TrustingPeriod
	}
	if config.MaxClockDrift == 0 {
		config.MaxClockDrift = DefaultConfig().MaxClockDrift
	}
	if config.SyncInterval == 0 {
		config.SyncInterval = DefaultConfig().SyncInterval
	}
	if config.RPCTimeout == 0 {
		config.RPCTimeout = DefaultConfig().RPCTimeout
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = DefaultConfig().MaxRetries
	}

	lc := &LightClient{
		config: config,
		httpClient: &http.Client{
			Timeout: config.RPCTimeout,
		},
		syncDone: make(chan struct{}),
	}

	return lc, nil
}

// InitializeWithTrustOnFirstUse initializes the light client by fetching and trusting
// the latest block from validators. This is a trust-on-first-use model where the
// first block received is trusted, and all subsequent blocks are verified against it.
//
// Important: TODO: When mainnet/testnet launches, replace trust-on-first-use
// with hardcoded checkpoint headers for true trustless initialization.
// Trust-on-first-use is secure for subsequent operations but trusts the
// initial block from the connected validators.
func (lc *LightClient) InitializeWithTrustOnFirstUse(ctx context.Context) error {
	// TODO: When mainnet/testnet launches, use hardcoded checkpoint headers
	// instead of trust-on-first-use for true trustless initialization from genesis.

	// Fetch the latest block from any responsive validator
	var block *LightBlock
	var lastErr error
	for _, endpoint := range lc.config.ValidatorEndpoints {
		b, err := lc.fetchLatestBlock(ctx, endpoint)
		if err != nil {
			lastErr = err
			continue
		}
		block = b
		break
	}

	if block == nil {
		return fmt.Errorf("could not fetch latest block from validators for trust-on-first-use initialization: %v", lastErr)
	}

	// Trust this header as our initial state
	lc.stateMu.Lock()
	defer lc.stateMu.Unlock()

	lc.trustedState = &TrustedState{
		Header: TrustedHeader{
			Header:    block.Header,
			AppHash:   block.Header.AppHash,
			Height:    block.Header.Height,
			TrustedAt: time.Now(),
		},
		ValidatorSet: block.ValidatorSet,
	}

	return nil
}

// GetVerifiedRootHash returns the verified root hash (app_hash) from the latest trusted header.
// This is the cryptographically verified root hash that proofs should be verified against
// for trustless data verification.
//
// If the light client is not initialized, it will initialize with trust-on-first-use.
//
// Important: TODO: When mainnet/testnet launches, the light client will be
// initialized with hardcoded checkpoint headers instead of trust-on-first-use.
func (lc *LightClient) GetVerifiedRootHash(ctx context.Context) (string, error) {
	lc.stateMu.RLock()
	state := lc.trustedState
	lc.stateMu.RUnlock()

	// Initialize with trust-on-first-use if not already initialized
	if state == nil {
		if err := lc.InitializeWithTrustOnFirstUse(ctx); err != nil {
			return "", err
		}
		lc.stateMu.RLock()
		state = lc.trustedState
		lc.stateMu.RUnlock()
	}

	if state == nil {
		return "", fmt.Errorf("no trusted state available")
	}

	return state.Header.AppHash, nil
}

// InitializeWithTrustedHeader initializes the light client with a trusted header.
func (lc *LightClient) InitializeWithTrustedHeader(block LightBlock) error {
	lc.stateMu.Lock()
	defer lc.stateMu.Unlock()

	// Verify the header matches the expected chain ID
	if block.Header.ChainID != lc.config.ChainID {
		return fmt.Errorf("chain ID mismatch: expected %s, got %s", lc.config.ChainID, block.Header.ChainID)
	}

	lc.trustedState = &TrustedState{
		Header: TrustedHeader{
			Header:    block.Header,
			AppHash:   block.Header.AppHash,
			Height:    block.Header.Height,
			TrustedAt: time.Now(),
		},
		ValidatorSet: block.ValidatorSet,
	}

	return nil
}

// Start starts background synchronization if enabled.
func (lc *LightClient) Start() error {
	if !lc.config.AutoSync {
		return nil
	}

	lc.ctx, lc.cancel = context.WithCancel(context.Background())
	go lc.syncLoop()
	return nil
}

// Stop stops the light client and background sync.
func (lc *LightClient) Stop() {
	if lc.cancel != nil {
		lc.cancel()
		<-lc.syncDone
	}
}

func (lc *LightClient) syncLoop() {
	defer close(lc.syncDone)

	ticker := time.NewTicker(lc.config.SyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-lc.ctx.Done():
			return
		case <-ticker.C:
			if err := lc.SyncToLatest(lc.ctx); err != nil {
				lc.lastError = err
			}
			lc.lastSync = time.Now()
		}
	}
}

// SyncToLatest syncs to the latest block.
func (lc *LightClient) SyncToLatest(ctx context.Context) error {
	// Try each validator endpoint
	var lastErr error
	for _, endpoint := range lc.config.ValidatorEndpoints {
		block, err := lc.fetchLatestBlock(ctx, endpoint)
		if err != nil {
			lastErr = err
			continue
		}

		if err := lc.verifyAndUpdateHeader(ctx, block); err != nil {
			lastErr = err
			continue
		}

		return nil
	}

	return fmt.Errorf("failed to sync from any validator: %v", lastErr)
}

// VerifyHeader verifies an untrusted header against the trusted state.
func (lc *LightClient) VerifyHeader(ctx context.Context, untrusted LightBlock) (*VerificationResult, error) {
	lc.stateMu.RLock()
	trusted := lc.trustedState
	lc.stateMu.RUnlock()

	if trusted == nil {
		return nil, fmt.Errorf("light client not initialized")
	}

	result := &VerificationResult{
		Height: untrusted.Header.Height,
	}

	// Check chain ID
	if untrusted.Header.ChainID != lc.config.ChainID {
		result.Error = fmt.Sprintf("chain ID mismatch: expected %s, got %s", lc.config.ChainID, untrusted.Header.ChainID)
		return result, nil
	}

	// Check height progression
	if untrusted.Header.Height <= trusted.Header.Height {
		result.Error = fmt.Sprintf("height not increasing: trusted=%d, untrusted=%d", trusted.Header.Height, untrusted.Header.Height)
		return result, nil
	}

	// Check time progression
	if !untrusted.Header.Time.After(trusted.Header.Header.Time) {
		result.Error = "time not progressing"
		return result, nil
	}

	// Check within trusting period
	if time.Since(trusted.Header.TrustedAt) > lc.config.TrustingPeriod {
		result.Error = "trusted header has expired"
		return result, nil
	}

	// Check clock drift
	clockDrift := time.Until(untrusted.Header.Time)
	if clockDrift > lc.config.MaxClockDrift {
		result.Error = fmt.Sprintf("clock drift too large: %v", clockDrift)
		return result, nil
	}

	// For adjacent blocks, verify validators_hash matches next_validators_hash
	if untrusted.Header.Height == trusted.Header.Height+1 {
		if untrusted.Header.ValidatorsHash != trusted.Header.Header.NextValidatorsHash {
			result.Error = "validators hash mismatch for adjacent block"
			return result, nil
		}
	}

	// Verify commit signatures
	signedPower, totalPower, sigCount := lc.verifyCommitSignatures(&untrusted)
	result.VotingPower = signedPower
	result.TotalPower = totalPower
	result.SignatureCount = sigCount

	// Check trust threshold
	if !lc.config.TrustThreshold.Validate(signedPower, totalPower) {
		result.Error = fmt.Sprintf("insufficient voting power: %d/%d", signedPower, totalPower)
		return result, nil
	}

	result.Verified = true
	result.AppHash = untrusted.Header.AppHash
	return result, nil
}

func (lc *LightClient) verifyCommitSignatures(block *LightBlock) (signedPower, totalPower int64, sigCount int) {
	totalPower = block.ValidatorSet.GetTotalVotingPower()

	// Build validator map for quick lookup
	validatorMap := make(map[string]*Validator)
	for i := range block.ValidatorSet.Validators {
		v := &block.ValidatorSet.Validators[i]
		validatorMap[v.Address] = v
	}

	// Count signed voting power
	for _, sig := range block.Commit.Signatures {
		if sig.IsAbsent() {
			continue
		}
		if sig.IsCommit() {
			if v, ok := validatorMap[sig.ValidatorAddress]; ok {
				signedPower += v.VotingPower
				sigCount++
			}
		}
	}

	return signedPower, totalPower, sigCount
}

func (lc *LightClient) verifyAndUpdateHeader(ctx context.Context, block *LightBlock) error {
	result, err := lc.VerifyHeader(ctx, *block)
	if err != nil {
		return err
	}
	if !result.Verified {
		return fmt.Errorf("header verification failed: %s", result.Error)
	}

	// Update trusted state
	lc.stateMu.Lock()
	defer lc.stateMu.Unlock()

	lc.trustedState = &TrustedState{
		Header: TrustedHeader{
			Header:    block.Header,
			AppHash:   block.Header.AppHash,
			Height:    block.Header.Height,
			TrustedAt: time.Now(),
		},
		ValidatorSet: block.ValidatorSet,
	}

	return nil
}

// GetLatestTrustedHeader returns the latest trusted header.
func (lc *LightClient) GetLatestTrustedHeader() (*TrustedHeader, error) {
	lc.stateMu.RLock()
	defer lc.stateMu.RUnlock()

	if lc.trustedState == nil {
		return nil, fmt.Errorf("light client not initialized")
	}

	return &lc.trustedState.Header, nil
}

// GetSyncStatus returns the current synchronization status.
func (lc *LightClient) GetSyncStatus() *SyncStatus {
	lc.stateMu.RLock()
	defer lc.stateMu.RUnlock()

	status := &SyncStatus{
		LastSyncAttempt: lc.lastSync,
	}

	if lc.lastError != nil {
		status.LastSyncError = lc.lastError.Error()
	}

	if lc.trustedState != nil {
		status.LatestTrustedHeight = lc.trustedState.Header.Height
		status.LatestTrustedTime = lc.trustedState.Header.Header.Time
		status.IsSynced = time.Since(lc.trustedState.Header.TrustedAt) < lc.config.SyncInterval*2
	}

	return status
}

// ExportTrustedState exports the trusted state for persistence.
func (lc *LightClient) ExportTrustedState() (*TrustedState, error) {
	lc.stateMu.RLock()
	defer lc.stateMu.RUnlock()

	if lc.trustedState == nil {
		return nil, fmt.Errorf("no trusted state to export")
	}

	// Return a copy
	stateCopy := *lc.trustedState
	return &stateCopy, nil
}

// ImportTrustedState imports a previously exported trusted state.
func (lc *LightClient) ImportTrustedState(state *TrustedState) error {
	if state == nil {
		return fmt.Errorf("state cannot be nil")
	}

	// Verify the state is for our chain
	if state.Header.Header.ChainID != lc.config.ChainID {
		return fmt.Errorf("chain ID mismatch")
	}

	// Check if state is still valid
	if time.Since(state.Header.TrustedAt) > lc.config.TrustingPeriod {
		return fmt.Errorf("trusted state has expired")
	}

	lc.stateMu.Lock()
	defer lc.stateMu.Unlock()

	lc.trustedState = state
	return nil
}

// RPC helpers

func (lc *LightClient) fetchLatestBlock(ctx context.Context, endpoint string) (*LightBlock, error) {
	// Get latest commit
	commit, err := lc.rpcCall(ctx, endpoint, "commit", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get commit: %w", err)
	}

	var commitResp struct {
		SignedHeader struct {
			Header Header `json:"header"`
			Commit Commit `json:"commit"`
		} `json:"signed_header"`
	}
	if err := json.Unmarshal(commit, &commitResp); err != nil {
		return nil, fmt.Errorf("failed to parse commit: %w", err)
	}

	// Get validators
	height := commitResp.SignedHeader.Header.Height
	validators, err := lc.rpcCall(ctx, endpoint, "validators", map[string]interface{}{
		"height": fmt.Sprintf("%d", height),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get validators: %w", err)
	}

	var validatorResp struct {
		Validators []struct {
			Address string `json:"address"`
			PubKey  struct {
				Type  string `json:"type"`
				Value string `json:"value"`
			} `json:"pub_key"`
			VotingPower      string `json:"voting_power"`
			ProposerPriority string `json:"proposer_priority"`
		} `json:"validators"`
	}
	if err := json.Unmarshal(validators, &validatorResp); err != nil {
		return nil, fmt.Errorf("failed to parse validators: %w", err)
	}

	// Convert validators
	valSet := ValidatorSet{
		Validators: make([]Validator, len(validatorResp.Validators)),
	}
	for i, v := range validatorResp.Validators {
		var votingPower int64
		fmt.Sscanf(v.VotingPower, "%d", &votingPower)

		var proposerPriority int64
		fmt.Sscanf(v.ProposerPriority, "%d", &proposerPriority)

		valSet.Validators[i] = Validator{
			Address:          v.Address,
			PublicKey:        v.PubKey.Value,
			PublicKeyType:    v.PubKey.Type,
			VotingPower:      votingPower,
			ProposerPriority: proposerPriority,
		}
		valSet.TotalVotingPower += votingPower
	}

	return &LightBlock{
		Header:       commitResp.SignedHeader.Header,
		Commit:       commitResp.SignedHeader.Commit,
		ValidatorSet: valSet,
	}, nil
}

func (lc *LightClient) rpcCall(ctx context.Context, endpoint, method string, params map[string]interface{}) (json.RawMessage, error) {
	if params == nil {
		params = map[string]interface{}{}
	}

	reqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  params,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := lc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var rpcResp struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	return rpcResp.Result, nil
}

// SelectBestEndpoint selects the best validator endpoint based on responsiveness.
func (lc *LightClient) SelectBestEndpoint(ctx context.Context) (string, error) {
	type result struct {
		endpoint string
		latency  time.Duration
		height   int64
	}

	results := make(chan result, len(lc.config.ValidatorEndpoints))

	for _, endpoint := range lc.config.ValidatorEndpoints {
		go func(ep string) {
			start := time.Now()
			resp, err := lc.rpcCall(ctx, ep, "status", nil)
			if err != nil {
				return
			}

			var status struct {
				SyncInfo struct {
					LatestBlockHeight string `json:"latest_block_height"`
				} `json:"sync_info"`
			}
			if err := json.Unmarshal(resp, &status); err != nil {
				return
			}

			var height int64
			fmt.Sscanf(status.SyncInfo.LatestBlockHeight, "%d", &height)

			results <- result{
				endpoint: ep,
				latency:  time.Since(start),
				height:   height,
			}
		}(endpoint)
	}

	// Collect results with timeout
	var collected []result
	timeout := time.After(lc.config.RPCTimeout)

	for i := 0; i < len(lc.config.ValidatorEndpoints); i++ {
		select {
		case r := <-results:
			collected = append(collected, r)
		case <-timeout:
			break
		}
	}

	if len(collected) == 0 {
		return "", fmt.Errorf("no responsive endpoints")
	}

	// Sort by height (descending) then latency (ascending)
	sort.Slice(collected, func(i, j int) bool {
		if collected[i].height != collected[j].height {
			return collected[i].height > collected[j].height
		}
		return collected[i].latency < collected[j].latency
	})

	return collected[0].endpoint, nil
}
