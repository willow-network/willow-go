package willow

import (
	"context"
	"fmt"
	"math/big"
)

// TokenOperations provides methods for token-related queries.
type TokenOperations struct {
	client *Client
}

// GetInfo retrieves information about the WILL token.
func (t *TokenOperations) GetInfo(ctx context.Context) (*TokenInfo, error) {
	var info TokenInfo
	err := t.client.get(ctx, "/token/info", &info)
	if err != nil {
		return nil, err
	}
	return &info, nil
}

// GetBalance retrieves the balance for a DID.
func (t *TokenOperations) GetBalance(ctx context.Context, did string) (*BalanceInfo, error) {
	var info BalanceInfo
	err := t.client.get(ctx, fmt.Sprintf("/token/balance/%s", did), &info)
	if err != nil {
		return nil, err
	}
	return &info, nil
}

// GetMyBalance retrieves the balance for the authenticated user.
func (t *TokenOperations) GetMyBalance(ctx context.Context) (*BalanceInfo, error) {
	if err := t.client.RequireAuth(); err != nil {
		return nil, err
	}

	identity := t.client.GetIdentity()
	return t.GetBalance(ctx, identity.DID())
}

// GetFeeSchedule retrieves the current fee schedule.
func (t *TokenOperations) GetFeeSchedule(ctx context.Context) (*FeeSchedule, error) {
	var schedule FeeSchedule
	err := t.client.get(ctx, "/token/fees", &schedule)
	if err != nil {
		// Try alternate endpoint
		err = t.client.get(ctx, "/fees/schedule", &schedule)
		if err != nil {
			return nil, err
		}
	}
	return &schedule, nil
}

// EstimateStorageFee estimates the storage fee (in WILL base units) for the
// given data size: cost_per_byte * dataSizeBytes. cost_per_byte is returned
// by the API as a decimal string because the value can exceed uint64, so
// the multiplication runs through math/big and the result is returned as
// a decimal string in the same convention.
func (t *TokenOperations) EstimateStorageFee(ctx context.Context, dataSizeBytes uint64) (string, error) {
	schedule, err := t.GetFeeSchedule(ctx)
	if err != nil {
		return "0", err
	}
	costPerByte, ok := new(big.Int).SetString(schedule.CostPerByte, 10)
	if !ok {
		return "0", fmt.Errorf("invalid cost_per_byte from server: %q", schedule.CostPerByte)
	}
	total := new(big.Int).Mul(costPerByte, new(big.Int).SetUint64(dataSizeBytes))
	return total.String(), nil
}

// EstimateQueryFee estimates the query fee.
func (t *TokenOperations) EstimateQueryFee(ctx context.Context) (string, error) {
	schedule, err := t.GetFeeSchedule(ctx)
	if err != nil {
		return "0", err
	}
	return schedule.QueryFee, nil
}
