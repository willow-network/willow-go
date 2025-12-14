package willow

import (
	"context"
	"fmt"
)

// ValidatorOperations provides methods for validator-related queries.
type ValidatorOperations struct {
	client *Client
}

// List retrieves all validators.
func (v *ValidatorOperations) List(ctx context.Context) ([]ValidatorInfo, error) {
	var validators []ValidatorInfo
	err := v.client.get(ctx, "/validators", &validators)
	if err != nil {
		return nil, err
	}
	return validators, nil
}

// Get retrieves information about a specific validator.
func (v *ValidatorOperations) Get(ctx context.Context, address string) (*ValidatorInfo, error) {
	var validator ValidatorInfo
	err := v.client.get(ctx, fmt.Sprintf("/validators/%s", address), &validator)
	if err != nil {
		return nil, err
	}
	return &validator, nil
}

// GetActive retrieves all active validators.
func (v *ValidatorOperations) GetActive(ctx context.Context) ([]ValidatorInfo, error) {
	validators, err := v.List(ctx)
	if err != nil {
		return nil, err
	}

	active := make([]ValidatorInfo, 0)
	for _, val := range validators {
		if val.Status == ValidatorStatusActive {
			active = append(active, val)
		}
	}
	return active, nil
}

// GetTotalVotingPower returns the total voting power of all validators.
func (v *ValidatorOperations) GetTotalVotingPower(ctx context.Context) (int64, error) {
	validators, err := v.List(ctx)
	if err != nil {
		return 0, err
	}

	var total int64
	for _, val := range validators {
		if val.Status == ValidatorStatusActive {
			total += val.VotingPower
		}
	}
	return total, nil
}
