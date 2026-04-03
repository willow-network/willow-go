package willow

import (
	"context"
	"fmt"
)

// RegistrationOperations provides methods for subgrove registration.
type RegistrationOperations struct {
	client *Client
}

// RegisterSubgrove registers a new subgrove.
func (r *RegistrationOperations) RegisterSubgrove(ctx context.Context, req *RegisterSubgroveRequest) (*SubgroveRegistration, error) {
	if err := r.client.RequireAuth(); err != nil {
		return nil, err
	}

	var result SubgroveRegistration
	err := r.client.post(ctx, "/subgroves", req, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// GetSubgrove retrieves information about a subgrove.
func (r *RegistrationOperations) GetSubgrove(ctx context.Context, subgroveID string) (*SubgroveRegistration, error) {
	var result SubgroveRegistration
	path := fmt.Sprintf("/subgroves/%s", subgroveID)
	err := r.client.get(ctx, path, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// ListSubgroves lists all subgroves.
func (r *RegistrationOperations) ListSubgroves(ctx context.Context) ([]SubgroveRegistration, error) {
	var results []SubgroveRegistration
	err := r.client.get(ctx, "/subgroves", &results)
	if err != nil {
		return nil, err
	}
	return results, nil
}

// UpdateSubgrove updates an existing subgrove.
func (r *RegistrationOperations) UpdateSubgrove(ctx context.Context, subgroveID string, updates map[string]interface{}) (*SubgroveRegistration, error) {
	if err := r.client.RequireAuth(); err != nil {
		return nil, err
	}

	var result SubgroveRegistration
	path := fmt.Sprintf("/subgroves/%s", subgroveID)
	err := r.client.put(ctx, path, updates, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// DeleteSubgrove deletes a subgrove.
func (r *RegistrationOperations) DeleteSubgrove(ctx context.Context, subgroveID string) error {
	if err := r.client.RequireAuth(); err != nil {
		return err
	}

	path := fmt.Sprintf("/subgroves/%s", subgroveID)
	return r.client.delete(ctx, path, nil)
}

// GetPermissions retrieves permissions for a DID.
func (r *RegistrationOperations) GetPermissions(ctx context.Context, did string) ([]Permission, error) {
	var results []Permission
	path := fmt.Sprintf("/permissions/%s", did)
	err := r.client.get(ctx, path, &results)
	if err != nil {
		return nil, err
	}
	return results, nil
}

// GrantPermission grants a permission to a DID.
func (r *RegistrationOperations) GrantPermission(ctx context.Context, permission *Permission) error {
	if err := r.client.RequireAuth(); err != nil {
		return err
	}

	return r.client.post(ctx, "/permissions", permission, nil)
}

// RevokePermission revokes a permission from a DID.
func (r *RegistrationOperations) RevokePermission(ctx context.Context, did, subgroveID string) error {
	if err := r.client.RequireAuth(); err != nil {
		return err
	}

	path := fmt.Sprintf("/permissions/%s/%s", did, subgroveID)
	return r.client.delete(ctx, path, nil)
}

// SubgroveBuilder provides a fluent interface for building subgrove registrations.
type SubgroveBuilder struct {
	req *RegisterSubgroveRequest
}

// NewSubgroveBuilder creates a new SubgroveBuilder.
func NewSubgroveBuilder(subgroveID, name string) *SubgroveBuilder {
	return &SubgroveBuilder{
		req: &RegisterSubgroveRequest{
			SubgroveID: subgroveID,
			Name:       name,
		},
	}
}

// Description sets the subgrove description.
func (b *SubgroveBuilder) Description(desc string) *SubgroveBuilder {
	b.req.Description = desc
	return b
}

// Schema sets the schema definition.
func (b *SubgroveBuilder) Schema(schema SchemaDefinition) *SubgroveBuilder {
	b.req.Schema = schema
	return b
}

// Owner sets the owner DID.
func (b *SubgroveBuilder) Owner(did string) *SubgroveBuilder {
	b.req.OwnerDid = did
	return b
}

// Writers sets the writer DIDs.
func (b *SubgroveBuilder) Writers(dids []string) *SubgroveBuilder {
	b.req.Writers = dids
	return b
}

// AddWriter adds a writer DID.
func (b *SubgroveBuilder) AddWriter(did string) *SubgroveBuilder {
	b.req.Writers = append(b.req.Writers, did)
	return b
}

// Readers sets the reader DIDs.
func (b *SubgroveBuilder) Readers(dids []string) *SubgroveBuilder {
	b.req.Readers = dids
	return b
}

// AddReader adds a reader DID.
func (b *SubgroveBuilder) AddReader(did string) *SubgroveBuilder {
	b.req.Readers = append(b.req.Readers, did)
	return b
}

// RewardRate sets the reward rate for indexers.
func (b *SubgroveBuilder) RewardRate(rate uint64) *SubgroveBuilder {
	b.req.RewardRate = rate
	return b
}

// Build returns the constructed RegisterSubgroveRequest.
func (b *SubgroveBuilder) Build() *RegisterSubgroveRequest {
	return b.req
}

// SchemaBuilder provides a fluent interface for building schema definitions.
type SchemaBuilder struct {
	schema *SchemaDefinition
}

// NewSchemaBuilder creates a new SchemaBuilder.
func NewSchemaBuilder(name string) *SchemaBuilder {
	return &SchemaBuilder{
		schema: &SchemaDefinition{
			Name:    name,
			Fields:  make([]SchemaField, 0),
			Indexes: make([]IndexDefinition, 0),
		},
	}
}

// Description sets the schema description.
func (b *SchemaBuilder) Description(desc string) *SchemaBuilder {
	b.schema.Description = desc
	return b
}

// Field adds a field to the schema.
func (b *SchemaBuilder) Field(name, fieldType string, required, indexed bool) *SchemaBuilder {
	b.schema.Fields = append(b.schema.Fields, SchemaField{
		Name:     name,
		Type:     fieldType,
		Required: required,
		Indexed:  indexed,
	})
	return b
}

// StringField adds a string field.
func (b *SchemaBuilder) StringField(name string, required bool) *SchemaBuilder {
	return b.Field(name, "string", required, false)
}

// IntField adds an integer field.
func (b *SchemaBuilder) IntField(name string, required bool) *SchemaBuilder {
	return b.Field(name, "int", required, false)
}

// FloatField adds a float field.
func (b *SchemaBuilder) FloatField(name string, required bool) *SchemaBuilder {
	return b.Field(name, "float", required, false)
}

// BoolField adds a boolean field.
func (b *SchemaBuilder) BoolField(name string, required bool) *SchemaBuilder {
	return b.Field(name, "bool", required, false)
}

// ArrayField adds an array field with item type.
func (b *SchemaBuilder) ArrayField(name string, itemType string, required bool) *SchemaBuilder {
	return b.Field(name, "array:"+itemType, required, false)
}

// ObjectField adds an object field.
func (b *SchemaBuilder) ObjectField(name string, required bool) *SchemaBuilder {
	return b.Field(name, "object", required, false)
}

// Index adds an index to the schema.
func (b *SchemaBuilder) Index(name string, fields []string, indexType IndexType, unique bool) *SchemaBuilder {
	b.schema.Indexes = append(b.schema.Indexes, IndexDefinition{
		Name:   name,
		Fields: fields,
		Type:   indexType,
		Unique: unique,
	})
	return b
}

// HashIndex adds a hash index.
func (b *SchemaBuilder) HashIndex(name string, fields []string) *SchemaBuilder {
	return b.Index(name, fields, IndexTypeHash, false)
}

// RangeIndex adds a range index.
func (b *SchemaBuilder) RangeIndex(name string, fields []string) *SchemaBuilder {
	return b.Index(name, fields, IndexTypeRange, false)
}

// FullTextIndex adds a full-text index.
func (b *SchemaBuilder) FullTextIndex(name string, fields []string) *SchemaBuilder {
	return b.Index(name, fields, IndexTypeFullText, false)
}

// UniqueIndex adds a unique index.
func (b *SchemaBuilder) UniqueIndex(name string, fields []string) *SchemaBuilder {
	return b.Index(name, fields, IndexTypeHash, true)
}

// Build returns the constructed SchemaDefinition.
func (b *SchemaBuilder) Build() *SchemaDefinition {
	return b.schema
}
