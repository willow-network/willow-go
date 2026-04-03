// Package willow provides a Go SDK for interacting with the Willow network.
//
// Computed Fields Module
//
// This module provides SDK-layer computation of derived fields from proven data.
// It enables drop-in compatibility with The Graph's query interfaces by computing
// derived values (like price ratios) from cryptographically proven base data.
//
// Design Philosophy:
//   - GKR circuits prove the underlying data (reserves, volumes, balances)
//   - Division and other derived calculations are done client-side
//   - Same trust model: proven inputs + deterministic computation = trustworthy outputs
//   - Same API: queries return the same fields The Graph would return
package willow

import (
	"math"
	"strconv"
	"strings"
	"sync"
)

// ComputeFunction is a function that computes a derived value from a record's proven fields.
// Returns nil if the computation cannot be performed (e.g., division by zero).
type ComputeFunction func(record map[string]interface{}) interface{}

// ComputedFieldDefinition defines a single computed field.
type ComputedFieldDefinition struct {
	// Name is the field name in the output record.
	Name string
	// Description is a human-readable description of what this field represents.
	Description string
	// Dependencies are the proven fields this computation depends on.
	Dependencies []string
	// Compute is the computation function.
	Compute ComputeFunction
}

// ComputedFieldSet is a set of computed field definitions for a dataset.
type ComputedFieldSet []ComputedFieldDefinition

// ComputedFieldRegistry is a registry of computed fields by dataset.
type ComputedFieldRegistry struct {
	mu       sync.RWMutex
	registry map[string]ComputedFieldSet
}

// NewComputedFieldRegistry creates a new ComputedFieldRegistry.
func NewComputedFieldRegistry() *ComputedFieldRegistry {
	return &ComputedFieldRegistry{
		registry: make(map[string]ComputedFieldSet),
	}
}

// Register registers computed fields for a specific dataset.
func (r *ComputedFieldRegistry) Register(datasetID string, fields ComputedFieldSet) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.registry[datasetID] = fields
}

// Get returns computed fields for a specific dataset.
func (r *ComputedFieldRegistry) Get(datasetID string) (ComputedFieldSet, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	fields, ok := r.registry[datasetID]
	return fields, ok
}

// Has checks if computed fields are registered for a dataset.
func (r *ComputedFieldRegistry) Has(datasetID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.registry[datasetID]
	return ok
}

// Unregister removes computed fields for a dataset.
func (r *ComputedFieldRegistry) Unregister(datasetID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, existed := r.registry[datasetID]
	delete(r.registry, datasetID)
	return existed
}

// Clear removes all registered computed fields.
func (r *ComputedFieldRegistry) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.registry = make(map[string]ComputedFieldSet)
}

// ApplyComputedFields applies computed fields to a single record.
// Returns a new map with computed fields added.
func ApplyComputedFields(record map[string]interface{}, fields ComputedFieldSet) map[string]interface{} {
	// Create a copy of the record
	result := make(map[string]interface{}, len(record)+len(fields))
	for k, v := range record {
		result[k] = v
	}

	for _, field := range fields {
		// Check if all dependencies are present
		hasDependencies := true
		for _, dep := range field.Dependencies {
			if record[dep] == nil {
				hasDependencies = false
				break
			}
		}

		if hasDependencies {
			computed := field.Compute(record)
			if computed != nil {
				result[field.Name] = computed
			}
		}
	}

	return result
}

// ApplyComputedFieldsToResponse applies computed fields to a query response.
// Returns a new response with computed fields added to all results.
func ApplyComputedFieldsToResponse(response *QueryResponse, fields ComputedFieldSet) *QueryResponse {
	newResults := make([]QueryResult, len(response.Results))
	for i, result := range response.Results {
		newResults[i] = QueryResult{
			Key:  result.Key,
			Data: ApplyComputedFields(result.Data, fields),
		}
	}

	return &QueryResponse{
		Results:    newResults,
		TotalCount: response.TotalCount,
		HasMore:    response.HasMore,
		Proof:      response.Proof,
	}
}

// ============================================================================
// Helper Functions
// ============================================================================

// parseNumeric safely parses a numeric value from various formats.
// Handles strings (including BigInt-like strings), numbers, and int64/uint64.
func parseNumeric(value interface{}) (float64, bool) {
	if value == nil {
		return 0, false
	}

	switch v := value.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case int32:
		return float64(v), true
	case uint:
		return float64(v), true
	case uint64:
		return float64(v), true
	case uint32:
		return float64(v), true
	case string:
		// Handle hex strings
		if strings.HasPrefix(v, "0x") || strings.HasPrefix(v, "0X") {
			parsed, err := strconv.ParseUint(v[2:], 16, 64)
			if err != nil {
				return 0, false
			}
			return float64(parsed), true
		}
		// Handle decimal strings
		parsed, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return 0, false
		}
		return parsed, true
	}

	return 0, false
}

// ============================================================================
// Pre-built Field Sets for Common Protocols
// ============================================================================

// UniswapV2PairFields provides computed fields for Uniswap V2 pairs.
//
// These fields are computed from proven reserve data to match
// The Graph's Uniswap V2 subgraph schema.
//
// Proven fields required:
//   - reserve0: Token 0 reserve amount
//   - reserve1: Token 1 reserve amount
//   - token0.decimals: Token 0 decimals (optional, defaults to 18)
//   - token1.decimals: Token 1 decimals (optional, defaults to 18)
var UniswapV2PairFields = ComputedFieldSet{
	{
		Name:         "token0Price",
		Description:  "Price of token0 in terms of token1 (reserve1 / reserve0)",
		Dependencies: []string{"reserve0", "reserve1"},
		Compute: func(record map[string]interface{}) interface{} {
			reserve0, ok0 := parseNumeric(record["reserve0"])
			reserve1, ok1 := parseNumeric(record["reserve1"])

			if !ok0 || !ok1 {
				return nil
			}

			// Avoid division by zero
			if reserve0 == 0 {
				return nil
			}

			// Apply decimal adjustment if available
			decimals0 := 18.0
			decimals1 := 18.0

			if token0, ok := record["token0"].(map[string]interface{}); ok {
				if d, ok := parseNumeric(token0["decimals"]); ok {
					decimals0 = d
				}
			}
			if token1, ok := record["token1"].(map[string]interface{}); ok {
				if d, ok := parseNumeric(token1["decimals"]); ok {
					decimals1 = d
				}
			}

			decimalAdjustment := math.Pow(10, decimals0-decimals1)
			return (reserve1 / reserve0) * decimalAdjustment
		},
	},
	{
		Name:         "token1Price",
		Description:  "Price of token1 in terms of token0 (reserve0 / reserve1)",
		Dependencies: []string{"reserve0", "reserve1"},
		Compute: func(record map[string]interface{}) interface{} {
			reserve0, ok0 := parseNumeric(record["reserve0"])
			reserve1, ok1 := parseNumeric(record["reserve1"])

			if !ok0 || !ok1 {
				return nil
			}

			// Avoid division by zero
			if reserve1 == 0 {
				return nil
			}

			// Apply decimal adjustment if available
			decimals0 := 18.0
			decimals1 := 18.0

			if token0, ok := record["token0"].(map[string]interface{}); ok {
				if d, ok := parseNumeric(token0["decimals"]); ok {
					decimals0 = d
				}
			}
			if token1, ok := record["token1"].(map[string]interface{}); ok {
				if d, ok := parseNumeric(token1["decimals"]); ok {
					decimals1 = d
				}
			}

			decimalAdjustment := math.Pow(10, decimals1-decimals0)
			return (reserve0 / reserve1) * decimalAdjustment
		},
	},
}

// UniswapV2TokenFields provides computed fields for Uniswap V2 tokens.
//
// These fields compute derived ETH prices from proven stablecoin pool reserves.
var UniswapV2TokenFields = ComputedFieldSet{
	{
		Name:         "derivedETH",
		Description:  "Price of token in ETH (derived from WETH pair reserves)",
		Dependencies: []string{}, // Empty - we handle the logic internally since WETH is a special case
		Compute: func(record map[string]interface{}) interface{} {
			// If this is WETH itself, return 1
			if isWeth, ok := record["isWeth"].(bool); ok && isWeth {
				return 1.0
			}
			if symbol, ok := record["symbol"].(string); ok && symbol == "WETH" {
				return 1.0
			}

			// For other tokens, we need the WETH pair reserves
			reserve0, ok0 := parseNumeric(record["ethPairReserve0"])
			reserve1, ok1 := parseNumeric(record["ethPairReserve1"])

			// If we don't have pair reserves, we can't compute derivedETH
			if !ok0 || !ok1 {
				return nil
			}

			// Determine which reserve is WETH
			token0IsWeth, _ := record["ethPairToken0IsWeth"].(bool)

			if token0IsWeth {
				// WETH is token0, so price = reserve0 / reserve1
				if reserve1 == 0 {
					return nil
				}
				return reserve0 / reserve1
			}
			// WETH is token1, so price = reserve1 / reserve0
			if reserve0 == 0 {
				return nil
			}
			return reserve1 / reserve0
		},
	},
}

// UniswapV2AggregationFields provides computed fields for Uniswap V2 daily/hourly data.
var UniswapV2AggregationFields = ComputedFieldSet{
	{
		Name:         "dailyVolumeUSD",
		Description:  "Daily volume in USD (dailyVolumeETH * ethPriceUSD)",
		Dependencies: []string{"dailyVolumeETH", "ethPriceUSD"},
		Compute: func(record map[string]interface{}) interface{} {
			volumeETH, ok0 := parseNumeric(record["dailyVolumeETH"])
			ethPrice, ok1 := parseNumeric(record["ethPriceUSD"])

			if !ok0 || !ok1 {
				return nil
			}

			return volumeETH * ethPrice
		},
	},
	{
		Name:         "totalLiquidityUSD",
		Description:  "Total liquidity in USD (totalLiquidityETH * ethPriceUSD)",
		Dependencies: []string{"totalLiquidityETH", "ethPriceUSD"},
		Compute: func(record map[string]interface{}) interface{} {
			liquidityETH, ok0 := parseNumeric(record["totalLiquidityETH"])
			ethPrice, ok1 := parseNumeric(record["ethPriceUSD"])

			if !ok0 || !ok1 {
				return nil
			}

			return liquidityETH * ethPrice
		},
	},
}

// GenericAMMPairFields provides generic AMM pair fields (works for Uniswap V2, Sushiswap, etc.).
var GenericAMMPairFields = ComputedFieldSet{
	{
		Name:         "token0Price",
		Description:  "Price of token0 in terms of token1",
		Dependencies: []string{"reserve0", "reserve1"},
		Compute: func(record map[string]interface{}) interface{} {
			reserve0, ok0 := parseNumeric(record["reserve0"])
			reserve1, ok1 := parseNumeric(record["reserve1"])

			if !ok0 || !ok1 || reserve0 == 0 {
				return nil
			}

			return reserve1 / reserve0
		},
	},
	{
		Name:         "token1Price",
		Description:  "Price of token1 in terms of token0",
		Dependencies: []string{"reserve0", "reserve1"},
		Compute: func(record map[string]interface{}) interface{} {
			reserve0, ok0 := parseNumeric(record["reserve0"])
			reserve1, ok1 := parseNumeric(record["reserve1"])

			if !ok0 || !ok1 || reserve1 == 0 {
				return nil
			}

			return reserve0 / reserve1
		},
	},
}

// LendingProtocolFields provides computed fields for lending protocols (Aave, Compound, etc.).
var LendingProtocolFields = ComputedFieldSet{
	{
		Name:         "utilizationRate",
		Description:  "Utilization rate (totalBorrows / totalSupply)",
		Dependencies: []string{"totalBorrows", "totalSupply"},
		Compute: func(record map[string]interface{}) interface{} {
			borrows, ok0 := parseNumeric(record["totalBorrows"])
			supply, ok1 := parseNumeric(record["totalSupply"])

			if !ok0 || !ok1 || supply == 0 {
				return nil
			}

			return borrows / supply
		},
	},
	{
		Name:         "availableLiquidity",
		Description:  "Available liquidity (totalSupply - totalBorrows)",
		Dependencies: []string{"totalBorrows", "totalSupply"},
		Compute: func(record map[string]interface{}) interface{} {
			borrows, ok0 := parseNumeric(record["totalBorrows"])
			supply, ok1 := parseNumeric(record["totalSupply"])

			if !ok0 || !ok1 {
				return nil
			}

			return supply - borrows
		},
	},
}

// LPShareFields provides LP share computation fields.
var LPShareFields = ComputedFieldSet{
	{
		Name:         "shareOfPool",
		Description:  "User share of pool (userLPBalance / totalLPSupply)",
		Dependencies: []string{"userLPBalance", "totalLPSupply"},
		Compute: func(record map[string]interface{}) interface{} {
			userBalance, ok0 := parseNumeric(record["userLPBalance"])
			totalSupply, ok1 := parseNumeric(record["totalLPSupply"])

			if !ok0 || !ok1 || totalSupply == 0 {
				return nil
			}

			return userBalance / totalSupply
		},
	},
	{
		Name:         "userToken0Amount",
		Description:  "User share of token0 (shareOfPool * reserve0)",
		Dependencies: []string{"userLPBalance", "totalLPSupply", "reserve0"},
		Compute: func(record map[string]interface{}) interface{} {
			userBalance, ok0 := parseNumeric(record["userLPBalance"])
			totalSupply, ok1 := parseNumeric(record["totalLPSupply"])
			reserve0, ok2 := parseNumeric(record["reserve0"])

			if !ok0 || !ok1 || !ok2 || totalSupply == 0 {
				return nil
			}

			return (userBalance / totalSupply) * reserve0
		},
	},
	{
		Name:         "userToken1Amount",
		Description:  "User share of token1 (shareOfPool * reserve1)",
		Dependencies: []string{"userLPBalance", "totalLPSupply", "reserve1"},
		Compute: func(record map[string]interface{}) interface{} {
			userBalance, ok0 := parseNumeric(record["userLPBalance"])
			totalSupply, ok1 := parseNumeric(record["totalLPSupply"])
			reserve1, ok2 := parseNumeric(record["reserve1"])

			if !ok0 || !ok1 || !ok2 || totalSupply == 0 {
				return nil
			}

			return (userBalance / totalSupply) * reserve1
		},
	},
}

// GlobalComputedFieldRegistry is a global registry instance for convenience.
var GlobalComputedFieldRegistry = NewComputedFieldRegistry()
