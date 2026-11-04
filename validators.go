package willow

import (
	"context"
	"fmt"
	"math/big"

	"github.com/willow-network/willow-go/consensus"
)

// ValidatorOperations provides methods for validator-related queries.
type ValidatorOperations struct {
	client *Client
}

// List retrieves the active validators (the API's /validators lists only
// active, unjailed validators with at least the minimum stake).
func (v *ValidatorOperations) List(ctx context.Context) ([]ValidatorInfo, error) {
	var validators []ValidatorInfo
	err := v.client.getData(ctx, "/validators", &validators)
	if err != nil {
		return nil, err
	}
	return validators, nil
}

// Get retrieves a validator by its DID.
func (v *ValidatorOperations) Get(ctx context.Context, did string) (*ValidatorInfo, error) {
	var validator ValidatorInfo
	err := v.client.getData(ctx, fmt.Sprintf("/validators/%s", did), &validator)
	if err != nil {
		return nil, err
	}
	return &validator, nil
}

// GetActive retrieves the validators that are active and not jailed.
func (v *ValidatorOperations) GetActive(ctx context.Context) ([]ValidatorInfo, error) {
	validators, err := v.List(ctx)
	if err != nil {
		return nil, err
	}

	active := make([]ValidatorInfo, 0)
	for _, val := range validators {
		if val.Status() == ValidatorStatusActive {
			active = append(active, val)
		}
	}
	return active, nil
}

// GetTotalStake returns the total stake of the active validators, in the
// smallest token unit.
func (v *ValidatorOperations) GetTotalStake(ctx context.Context) (consensus.Uint128, error) {
	validators, err := v.GetActive(ctx)
	if err != nil {
		return consensus.Uint128{}, err
	}

	total := new(big.Int)
	for _, val := range validators {
		total.Add(total, val.TotalStake.Big())
	}
	return consensus.Uint128FromBig(total)
}
