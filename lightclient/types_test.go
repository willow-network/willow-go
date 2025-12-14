package lightclient

import (
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.TrustThreshold.Numerator != 2 {
		t.Errorf("Expected TrustThreshold.Numerator 2, got %d", config.TrustThreshold.Numerator)
	}
	if config.TrustThreshold.Denominator != 3 {
		t.Errorf("Expected TrustThreshold.Denominator 3, got %d", config.TrustThreshold.Denominator)
	}
	if config.TrustingPeriod != 24*time.Hour {
		t.Errorf("Expected TrustingPeriod 24h, got %v", config.TrustingPeriod)
	}
	if config.MaxClockDrift != 10*time.Second {
		t.Errorf("Expected MaxClockDrift 10s, got %v", config.MaxClockDrift)
	}
	if config.MinValidatorsForConsensus != 1 {
		t.Errorf("Expected MinValidatorsForConsensus 1, got %d", config.MinValidatorsForConsensus)
	}
	if !config.AutoSync {
		t.Error("Expected AutoSync true")
	}
	if config.SyncInterval != 5*time.Minute {
		t.Errorf("Expected SyncInterval 5m, got %v", config.SyncInterval)
	}
	if config.RPCTimeout != 10*time.Second {
		t.Errorf("Expected RPCTimeout 10s, got %v", config.RPCTimeout)
	}
	if config.MaxRetries != 3 {
		t.Errorf("Expected MaxRetries 3, got %d", config.MaxRetries)
	}
}

func TestTrustThresholdValidate(t *testing.T) {
	threshold := TrustThreshold{Numerator: 2, Denominator: 3}

	tests := []struct {
		votingPower int64
		totalPower  int64
		expected    bool
	}{
		{100, 100, true},  // 100% >= 66.7%
		{67, 100, true},   // 67% >= 66.7%
		{66, 100, false},  // 66% < 66.7%
		{50, 100, false},  // 50% < 66.7%
		{0, 100, false},   // 0% < 66.7%
		{200, 300, true},  // 66.7% = 66.7%
		{201, 300, true},  // 67% >= 66.7%
		{199, 300, false}, // 66.3% < 66.7%
	}

	for _, tt := range tests {
		result := threshold.Validate(tt.votingPower, tt.totalPower)
		if result != tt.expected {
			t.Errorf("Validate(%d, %d) = %v, expected %v",
				tt.votingPower, tt.totalPower, result, tt.expected)
		}
	}
}

func TestTrustThresholdEdgeCases(t *testing.T) {
	// 1/2 threshold (simple majority)
	halfThreshold := TrustThreshold{Numerator: 1, Denominator: 2}

	if !halfThreshold.Validate(51, 100) {
		t.Error("51% should pass 1/2 threshold")
	}
	if halfThreshold.Validate(49, 100) {
		t.Error("49% should not pass 1/2 threshold")
	}

	// 1/3 threshold
	thirdThreshold := TrustThreshold{Numerator: 1, Denominator: 3}

	if !thirdThreshold.Validate(34, 100) {
		t.Error("34% should pass 1/3 threshold")
	}
	if thirdThreshold.Validate(32, 100) {
		t.Error("32% should not pass 1/3 threshold")
	}
}

func TestValidatorSetGetTotalVotingPower(t *testing.T) {
	// Pre-calculated total
	vs := ValidatorSet{
		Validators: []Validator{
			{Address: "addr1", VotingPower: 100},
			{Address: "addr2", VotingPower: 200},
		},
		TotalVotingPower: 300,
	}

	total := vs.GetTotalVotingPower()
	if total != 300 {
		t.Errorf("Expected 300, got %d", total)
	}

	// Calculate from validators
	vs2 := ValidatorSet{
		Validators: []Validator{
			{Address: "addr1", VotingPower: 100},
			{Address: "addr2", VotingPower: 200},
			{Address: "addr3", VotingPower: 150},
		},
	}

	total = vs2.GetTotalVotingPower()
	if total != 450 {
		t.Errorf("Expected 450, got %d", total)
	}
}

func TestCommitSigIsAbsent(t *testing.T) {
	absentSig := CommitSig{BlockIDFlag: 1}
	if !absentSig.IsAbsent() {
		t.Error("BlockIDFlag 1 should be absent")
	}

	commitSig := CommitSig{BlockIDFlag: 2}
	if commitSig.IsAbsent() {
		t.Error("BlockIDFlag 2 should not be absent")
	}
}

func TestCommitSigIsCommit(t *testing.T) {
	commitSig := CommitSig{BlockIDFlag: 2}
	if !commitSig.IsCommit() {
		t.Error("BlockIDFlag 2 should be commit")
	}

	absentSig := CommitSig{BlockIDFlag: 1}
	if absentSig.IsCommit() {
		t.Error("BlockIDFlag 1 should not be commit")
	}

	nilSig := CommitSig{BlockIDFlag: 3}
	if nilSig.IsCommit() {
		t.Error("BlockIDFlag 3 should not be commit")
	}
}

func TestHeaderStructure(t *testing.T) {
	header := Header{
		ChainID: "willow-testnet",
		Height:  12345,
		Time:    time.Now(),
		AppHash: "abcd1234",
	}

	if header.ChainID != "willow-testnet" {
		t.Error("ChainID mismatch")
	}
	if header.Height != 12345 {
		t.Error("Height mismatch")
	}
	if header.AppHash != "abcd1234" {
		t.Error("AppHash mismatch")
	}
}

func TestLightBlock(t *testing.T) {
	block := LightBlock{
		Header: Header{
			ChainID: "test",
			Height:  100,
		},
		ValidatorSet: ValidatorSet{
			Validators: []Validator{
				{Address: "addr1", VotingPower: 100},
			},
		},
		Commit: Commit{
			Height: 100,
			Round:  0,
		},
	}

	if block.Header.ChainID != "test" {
		t.Error("Header ChainID mismatch")
	}
	if len(block.ValidatorSet.Validators) != 1 {
		t.Error("ValidatorSet should have 1 validator")
	}
	if block.Commit.Height != 100 {
		t.Error("Commit height mismatch")
	}
}

func TestTrustedState(t *testing.T) {
	state := TrustedState{
		Header: TrustedHeader{
			Height:    100,
			AppHash:   "roothash",
			TrustedAt: time.Now(),
		},
		ValidatorSet: ValidatorSet{
			TotalVotingPower: 1000,
		},
	}

	if state.Header.Height != 100 {
		t.Error("Height mismatch")
	}
	if state.Header.AppHash != "roothash" {
		t.Error("AppHash mismatch")
	}
	if state.ValidatorSet.TotalVotingPower != 1000 {
		t.Error("TotalVotingPower mismatch")
	}
}

func TestVerificationResult(t *testing.T) {
	result := VerificationResult{
		Verified:       true,
		Height:         100,
		AppHash:        "hash",
		VotingPower:    700,
		TotalPower:     1000,
		SignatureCount: 7,
	}

	if !result.Verified {
		t.Error("Should be verified")
	}
	if result.Error != "" {
		t.Error("Should have no error")
	}

	// With error
	errorResult := VerificationResult{
		Verified: false,
		Height:   100,
		Error:    "verification failed",
	}

	if errorResult.Verified {
		t.Error("Should not be verified")
	}
	if errorResult.Error != "verification failed" {
		t.Error("Error message mismatch")
	}
}

func TestSyncStatus(t *testing.T) {
	status := SyncStatus{
		LatestTrustedHeight: 100,
		LatestTrustedTime:   time.Now(),
		LatestKnownHeight:   105,
		IsSynced:            true,
		LastSyncAttempt:     time.Now(),
	}

	if status.LatestTrustedHeight != 100 {
		t.Error("LatestTrustedHeight mismatch")
	}
	if status.LatestKnownHeight != 105 {
		t.Error("LatestKnownHeight mismatch")
	}
	if !status.IsSynced {
		t.Error("Should be synced")
	}

	// With error
	errorStatus := SyncStatus{
		IsSynced:      false,
		LastSyncError: "connection refused",
	}

	if errorStatus.IsSynced {
		t.Error("Should not be synced")
	}
	if errorStatus.LastSyncError != "connection refused" {
		t.Error("LastSyncError mismatch")
	}
}

func TestProofVerificationResult(t *testing.T) {
	result := ProofVerificationResult{
		Verified:     true,
		RootHash:     "abc123",
		ExpectedHash: "abc123",
		Height:       100,
	}

	if !result.Verified {
		t.Error("Should be verified")
	}
	if result.RootHash != result.ExpectedHash {
		t.Error("Hashes should match")
	}

	// Mismatch case
	mismatchResult := ProofVerificationResult{
		Verified:     false,
		RootHash:     "abc123",
		ExpectedHash: "def456",
		Error:        "hash mismatch",
	}

	if mismatchResult.Verified {
		t.Error("Should not be verified")
	}
	if mismatchResult.Error != "hash mismatch" {
		t.Error("Error message mismatch")
	}
}
