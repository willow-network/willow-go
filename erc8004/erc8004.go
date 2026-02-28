// Package erc8004 provides ERC-8004 (Trustless Agents) integration for Willow.
//
// It includes helpers for linking Ethereum addresses to Willow DIDs and
// interacting with on-chain ERC-8004 agent registrations.
package erc8004

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// LinkEthAddressTx links an Ethereum address to a Willow DID.
type LinkEthAddressTx struct {
	DID         string `json:"did"`
	EthAddress  string `json:"eth_address"`
	PublicKeyID string `json:"public_key_id"`
	Signature   []byte `json:"signature,omitempty"`
	Nonce       uint64 `json:"nonce,omitempty"`
}

// RegisterErc8004AgentTx records an ERC-8004 agent registration.
type RegisterErc8004AgentTx struct {
	DID             string `json:"did"`
	ChainID         uint64 `json:"chain_id"`
	RegistryAddress string `json:"registry_address"`
	AgentID         uint64 `json:"agent_id"`
	AgentURI        string `json:"agent_uri"`
	Signature       []byte `json:"signature,omitempty"`
	PublicKeyID     string `json:"public_key_id,omitempty"`
	Nonce           uint64 `json:"nonce,omitempty"`
}

// AgentReputationSummary is a summary of an agent's reputation.
type AgentReputationSummary struct {
	Score                 uint32  `json:"score"`
	Tier                  string  `json:"tier"`
	CheckpointSuccessRate float64 `json:"checkpoint_success_rate"`
	VerificationAccuracy  float64 `json:"verification_accuracy"`
	ActiveDays            uint32  `json:"active_days"`
	LastUpdated           uint64  `json:"last_updated"`
}

// AgentRegistrationJson is the ERC-8004 compliant registration JSON.
type AgentRegistrationJson struct {
	Type           string                   `json:"type"`
	Name           string                   `json:"name"`
	Description    string                   `json:"description"`
	Services       []AgentService           `json:"services"`
	X402Support    bool                     `json:"x402_support"`
	Active         bool                     `json:"active"`
	Registrations  []AgentChainRegistration `json:"registrations"`
	SupportedTrust []string                 `json:"supported_trust"`
	Reputation     *AgentReputationSummary  `json:"reputation,omitempty"`
}

// ReputationAttestation contains reputation data with a GroveDB Merkle proof.
type ReputationAttestation struct {
	DID         string                 `json:"did"`
	Score       uint32                 `json:"score"`
	Tier        string                 `json:"tier"`
	Metrics     map[string]interface{} `json:"metrics"`
	Proof       string                 `json:"proof"`
	BlockHeight uint64                 `json:"block_height"`
	LastUpdated uint64                 `json:"last_updated"`
}

// ReputationHistoryEvent is a single reputation history event.
type ReputationHistoryEvent struct {
	EventType   string  `json:"event_type"`
	ScoreDelta  int32   `json:"score_delta"`
	NewScore    uint32  `json:"new_score"`
	BlockHeight uint64  `json:"block_height"`
	Timestamp   uint64  `json:"timestamp"`
	Reference   *string `json:"reference"`
}

// ReputationHistoryResponse is the ERC-8004 formatted reputation history.
type ReputationHistoryResponse struct {
	DID         string                   `json:"did"`
	Events      []ReputationHistoryEvent `json:"events"`
	TotalEvents int                      `json:"total_events"`
}

// AgentService is a service advertised by the agent.
type AgentService struct {
	Name     string `json:"name"`
	Endpoint string `json:"endpoint"`
}

// AgentChainRegistration contains on-chain registration details.
type AgentChainRegistration struct {
	ChainID  uint64 `json:"chain_id"`
	Registry string `json:"registry"`
	AgentID  uint64 `json:"agent_id"`
}

// Erc8004Registration contains stored registration details.
type Erc8004Registration struct {
	ChainID         uint64 `json:"chain_id"`
	RegistryAddress []byte `json:"registry_address"`
	AgentID         uint64 `json:"agent_id"`
	AgentURI        string `json:"agent_uri"`
	RegisteredAt    uint64 `json:"registered_at"`
}

// Erc8004ValidationRecord is a single ERC-8004 validation record.
type Erc8004ValidationRecord struct {
	RequestHash       string   `json:"request_hash"`
	SubgroveID        string   `json:"subgrove_id"`
	BlockRange        [2]int64 `json:"block_range"`
	StateRoot         string   `json:"state_root"`
	Response          uint32   `json:"response"`
	Status            string   `json:"status"`
	TeeVerified       bool     `json:"tee_verified"`
	TeeType           *string  `json:"tee_type"`
	SubmittedAtBlock  uint64   `json:"submitted_at_block"`
	ChallengeDeadline *uint64  `json:"challenge_deadline"`
	Tag               string   `json:"tag"`
}

// Erc8004ValidationStatusResponse is the response for the validation-status endpoint.
type Erc8004ValidationStatusResponse struct {
	DID         string                     `json:"did"`
	Validations []Erc8004ValidationRecord `json:"validations"`
	Total       int                        `json:"total"`
}

// ValidationStatusBreakdown breaks down validation statuses.
type ValidationStatusBreakdown struct {
	Trusted          uint64 `json:"trusted"`
	PendingChallenge uint64 `json:"pending_challenge"`
	TeeAttested      uint64 `json:"tee_attested"`
	Disputed         uint64 `json:"disputed"`
	Invalidated      uint64 `json:"invalidated"`
}

// DisputeStats contains dispute participation statistics.
type DisputeStats struct {
	DisputesWonAsDefendant  uint64 `json:"disputes_won_as_defendant"`
	DisputesLostAsDefendant uint64 `json:"disputes_lost_as_defendant"`
	DisputesWonAsChallenger uint64 `json:"disputes_won_as_challenger"`
	DisputesLostAsChallenger uint64 `json:"disputes_lost_as_challenger"`
}

// Erc8004ValidationSummary is the aggregated validation summary.
type Erc8004ValidationSummary struct {
	DID             string                    `json:"did"`
	Count           int                       `json:"count"`
	AverageResponse float64                   `json:"average_response"`
	StatusBreakdown ValidationStatusBreakdown `json:"status_breakdown"`
	DisputeStats    DisputeStats              `json:"dispute_stats"`
}

// AgentReputationBrief is a brief reputation summary in agent listings.
type AgentReputationBrief struct {
	Score int64  `json:"score"`
	Tier  string `json:"tier"`
}

// Erc8004AgentListItem is a single agent in the discovery listing.
type Erc8004AgentListItem struct {
	DID                    string               `json:"did"`
	EthAddress             *string              `json:"eth_address"`
	AgentURI               string               `json:"agent_uri"`
	ChainID                uint64               `json:"chain_id"`
	AgentID                uint64               `json:"agent_id"`
	Reputation             AgentReputationBrief `json:"reputation"`
	ValidationCount        int                  `json:"validation_count"`
	AverageValidationScore float64              `json:"average_validation_score"`
	RegisteredAt           uint64               `json:"registered_at"`
}

// Erc8004AgentListResponse is the paginated response from the agent discovery endpoint.
type Erc8004AgentListResponse struct {
	Agents []Erc8004AgentListItem `json:"agents"`
	Total  int                    `json:"total"`
	Offset int                    `json:"offset"`
	Limit  int                    `json:"limit"`
}

// Client provides ERC-8004 agent identity operations.
type Client struct {
	apiURL string
	http   *http.Client
}

// NewClient creates a new ERC-8004 client.
func NewClient(apiURL string) *Client {
	return &Client{
		apiURL: apiURL,
		http:   http.DefaultClient,
	}
}

type apiResponse struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data,omitempty"`
	Error   string          `json:"error,omitempty"`
}

func (c *Client) get(path string) (*apiResponse, error) {
	resp, err := c.http.Get(c.apiURL + path)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var result apiResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &result, nil
}

// ListAgents lists/searches ERC-8004 registered agents with optional filters.
func (c *Client) ListAgents(limit, offset int, minScore int64, tier string) (*Erc8004AgentListResponse, error) {
	var params []string
	if limit > 0 {
		params = append(params, fmt.Sprintf("limit=%d", limit))
	}
	if offset > 0 {
		params = append(params, fmt.Sprintf("offset=%d", offset))
	}
	if minScore > 0 {
		params = append(params, fmt.Sprintf("min_score=%d", minScore))
	}
	if tier != "" {
		params = append(params, "tier="+url.QueryEscape(tier))
	}
	path := "/agents"
	if len(params) > 0 {
		path += "?"
		for i, p := range params {
			if i > 0 {
				path += "&"
			}
			path += p
		}
	}
	result, err := c.get(path)
	if err != nil {
		return nil, err
	}
	if !result.Success {
		return nil, fmt.Errorf("%s", result.Error)
	}
	var resp Erc8004AgentListResponse
	if err := json.Unmarshal(result.Data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse agent list: %w", err)
	}
	return &resp, nil
}

// GetAgentRegistration fetches the ERC-8004 registration JSON for an agent DID.
func (c *Client) GetAgentRegistration(did string) (*AgentRegistrationJson, error) {
	result, err := c.get("/agent/" + url.PathEscape(did) + "/registration.json")
	if err != nil {
		return nil, err
	}
	if !result.Success {
		return nil, fmt.Errorf("%s", result.Error)
	}
	var reg AgentRegistrationJson
	if err := json.Unmarshal(result.Data, &reg); err != nil {
		return nil, fmt.Errorf("failed to parse registration: %w", err)
	}
	return &reg, nil
}

// GetEthAddress gets the ETH address linked to a DID.
func (c *Client) GetEthAddress(did string) (string, error) {
	result, err := c.get("/did/" + url.PathEscape(did) + "/eth-address")
	if err != nil {
		return "", err
	}
	if !result.Success {
		return "", fmt.Errorf("%s", result.Error)
	}
	var data struct {
		EthAddress string `json:"eth_address"`
	}
	if err := json.Unmarshal(result.Data, &data); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}
	return data.EthAddress, nil
}

// GetDidForEth gets the DID linked to an ETH address.
func (c *Client) GetDidForEth(ethAddress string) (string, error) {
	result, err := c.get("/eth-address/" + url.PathEscape(ethAddress) + "/did")
	if err != nil {
		return "", err
	}
	if !result.Success {
		return "", fmt.Errorf("%s", result.Error)
	}
	var data struct {
		DID string `json:"did"`
	}
	if err := json.Unmarshal(result.Data, &data); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}
	return data.DID, nil
}

// GetErc8004Details gets stored ERC-8004 registration details for a DID.
func (c *Client) GetErc8004Details(did string) (*Erc8004Registration, error) {
	result, err := c.get("/did/" + url.PathEscape(did) + "/erc8004")
	if err != nil {
		return nil, err
	}
	if !result.Success {
		return nil, fmt.Errorf("%s", result.Error)
	}
	var reg Erc8004Registration
	if err := json.Unmarshal(result.Data, &reg); err != nil {
		return nil, fmt.Errorf("failed to parse registration: %w", err)
	}
	return &reg, nil
}

// GetReputationAttestation fetches reputation attestation with GroveDB Merkle proof for a DID.
func (c *Client) GetReputationAttestation(did string) (*ReputationAttestation, error) {
	result, err := c.get("/agent/" + url.PathEscape(did) + "/reputation-attestation")
	if err != nil {
		return nil, err
	}
	if !result.Success {
		return nil, fmt.Errorf("%s", result.Error)
	}
	var att ReputationAttestation
	if err := json.Unmarshal(result.Data, &att); err != nil {
		return nil, fmt.Errorf("failed to parse attestation: %w", err)
	}
	return &att, nil
}

// GetReputationHistory fetches ERC-8004 formatted reputation history for a DID.
func (c *Client) GetReputationHistory(did string, limit int) (*ReputationHistoryResponse, error) {
	path := "/agent/" + url.PathEscape(did) + "/reputation-history"
	if limit > 0 {
		path = fmt.Sprintf("%s?limit=%d", path, limit)
	}
	result, err := c.get(path)
	if err != nil {
		return nil, err
	}
	if !result.Success {
		return nil, fmt.Errorf("%s", result.Error)
	}
	var hist ReputationHistoryResponse
	if err := json.Unmarshal(result.Data, &hist); err != nil {
		return nil, fmt.Errorf("failed to parse history: %w", err)
	}
	return &hist, nil
}

// GetValidationStatus fetches ERC-8004 validation status for a DID.
func (c *Client) GetValidationStatus(did string, limit int, subgroveID string) (*Erc8004ValidationStatusResponse, error) {
	path := "/agent/" + url.PathEscape(did) + "/validation-status"
	var params []string
	if limit > 0 {
		params = append(params, fmt.Sprintf("limit=%d", limit))
	}
	if subgroveID != "" {
		params = append(params, "subgrove_id="+url.QueryEscape(subgroveID))
	}
	if len(params) > 0 {
		path += "?"
		for i, p := range params {
			if i > 0 {
				path += "&"
			}
			path += p
		}
	}
	result, err := c.get(path)
	if err != nil {
		return nil, err
	}
	if !result.Success {
		return nil, fmt.Errorf("%s", result.Error)
	}
	var resp Erc8004ValidationStatusResponse
	if err := json.Unmarshal(result.Data, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse validation status: %w", err)
	}
	return &resp, nil
}

// GetValidationSummary fetches aggregated ERC-8004 validation summary for a DID.
func (c *Client) GetValidationSummary(did string, subgroveID string) (*Erc8004ValidationSummary, error) {
	path := "/agent/" + url.PathEscape(did) + "/validation-summary"
	if subgroveID != "" {
		path += "?subgrove_id=" + url.QueryEscape(subgroveID)
	}
	result, err := c.get(path)
	if err != nil {
		return nil, err
	}
	if !result.Success {
		return nil, fmt.Errorf("%s", result.Error)
	}
	var summary Erc8004ValidationSummary
	if err := json.Unmarshal(result.Data, &summary); err != nil {
		return nil, fmt.Errorf("failed to parse validation summary: %w", err)
	}
	return &summary, nil
}
