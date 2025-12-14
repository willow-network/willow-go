package willow

import (
	"context"
	"fmt"
)

// RegistrationOperations provides methods for app and subgrove registration.
type RegistrationOperations struct {
	client *Client
}

// RegisterApp registers a new application.
func (r *RegistrationOperations) RegisterApp(ctx context.Context, req *RegisterAppRequest) (*AppRegistration, error) {
	if err := r.client.RequireAuth(); err != nil {
		return nil, err
	}

	var result AppRegistration
	err := r.client.post(ctx, "/apps", req, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// GetApp retrieves information about an app.
func (r *RegistrationOperations) GetApp(ctx context.Context, appID string) (*AppRegistration, error) {
	var result AppRegistration
	err := r.client.get(ctx, fmt.Sprintf("/apps/%s", appID), &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// ListApps lists all registered applications.
func (r *RegistrationOperations) ListApps(ctx context.Context) ([]AppRegistration, error) {
	var results []AppRegistration
	err := r.client.get(ctx, "/apps", &results)
	if err != nil {
		return nil, err
	}
	return results, nil
}

// ListMyApps lists apps owned by the authenticated user.
func (r *RegistrationOperations) ListMyApps(ctx context.Context) ([]AppRegistration, error) {
	if err := r.client.RequireAuth(); err != nil {
		return nil, err
	}

	var results []AppRegistration
	err := r.client.get(ctx, "/apps?owned=true", &results)
	if err != nil {
		return nil, err
	}
	return results, nil
}

// UpdateApp updates an existing application.
func (r *RegistrationOperations) UpdateApp(ctx context.Context, appID string, updates map[string]interface{}) (*AppRegistration, error) {
	if err := r.client.RequireAuth(); err != nil {
		return nil, err
	}

	var result AppRegistration
	err := r.client.put(ctx, fmt.Sprintf("/apps/%s", appID), updates, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// DeleteApp deletes an application.
func (r *RegistrationOperations) DeleteApp(ctx context.Context, appID string) error {
	if err := r.client.RequireAuth(); err != nil {
		return err
	}

	return r.client.delete(ctx, fmt.Sprintf("/apps/%s", appID), nil)
}

// RegisterSubgrove registers a new subgrove within an app.
func (r *RegistrationOperations) RegisterSubgrove(ctx context.Context, req *RegisterSubgroveRequest) (*SubgroveRegistration, error) {
	if err := r.client.RequireAuth(); err != nil {
		return nil, err
	}

	var result SubgroveRegistration
	path := fmt.Sprintf("/apps/%s/subgroves", req.AppID)
	err := r.client.post(ctx, path, req, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// GetSubgrove retrieves information about a subgrove.
func (r *RegistrationOperations) GetSubgrove(ctx context.Context, appID, subgroveID string) (*SubgroveRegistration, error) {
	var result SubgroveRegistration
	path := fmt.Sprintf("/apps/%s/subgroves/%s", appID, subgroveID)
	err := r.client.get(ctx, path, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// ListSubgroves lists all subgroves for an app.
func (r *RegistrationOperations) ListSubgroves(ctx context.Context, appID string) ([]SubgroveRegistration, error) {
	var results []SubgroveRegistration
	path := fmt.Sprintf("/apps/%s/subgroves", appID)
	err := r.client.get(ctx, path, &results)
	if err != nil {
		return nil, err
	}
	return results, nil
}

// UpdateSubgrove updates an existing subgrove.
func (r *RegistrationOperations) UpdateSubgrove(ctx context.Context, appID, subgroveID string, updates map[string]interface{}) (*SubgroveRegistration, error) {
	if err := r.client.RequireAuth(); err != nil {
		return nil, err
	}

	var result SubgroveRegistration
	path := fmt.Sprintf("/apps/%s/subgroves/%s", appID, subgroveID)
	err := r.client.put(ctx, path, updates, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// DeleteSubgrove deletes a subgrove.
func (r *RegistrationOperations) DeleteSubgrove(ctx context.Context, appID, subgroveID string) error {
	if err := r.client.RequireAuth(); err != nil {
		return err
	}

	path := fmt.Sprintf("/apps/%s/subgroves/%s", appID, subgroveID)
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
func (r *RegistrationOperations) RevokePermission(ctx context.Context, did, appID, subgroveID string) error {
	if err := r.client.RequireAuth(); err != nil {
		return err
	}

	path := fmt.Sprintf("/permissions/%s/%s", did, appID)
	if subgroveID != "" {
		path = fmt.Sprintf("%s/%s", path, subgroveID)
	}
	return r.client.delete(ctx, path, nil)
}

// AppBuilder provides a fluent interface for building app registrations.
type AppBuilder struct {
	req *RegisterAppRequest
}

// NewAppBuilder creates a new AppBuilder.
func NewAppBuilder(appID, name string) *AppBuilder {
	return &AppBuilder{
		req: &RegisterAppRequest{
			AppID:   appID,
			Name:    name,
			AppType: AppTypeStandard,
		},
	}
}

// Description sets the app description.
func (b *AppBuilder) Description(desc string) *AppBuilder {
	b.req.Description = desc
	return b
}

// Type sets the app type.
func (b *AppBuilder) Type(appType AppType) *AppBuilder {
	b.req.AppType = appType
	return b
}

// Owner sets the owner DID.
func (b *AppBuilder) Owner(did string) *AppBuilder {
	b.req.OwnerDid = did
	return b
}

// Admins sets the admin DIDs.
func (b *AppBuilder) Admins(dids []string) *AppBuilder {
	b.req.Admins = dids
	return b
}

// AddAdmin adds an admin DID.
func (b *AppBuilder) AddAdmin(did string) *AppBuilder {
	b.req.Admins = append(b.req.Admins, did)
	return b
}

// Build returns the constructed RegisterAppRequest.
func (b *AppBuilder) Build() *RegisterAppRequest {
	return b.req
}

// SubgroveBuilder provides a fluent interface for building subgrove registrations.
type SubgroveBuilder struct {
	req *RegisterSubgroveRequest
}

// NewSubgroveBuilder creates a new SubgroveBuilder.
func NewSubgroveBuilder(subgroveID, appID, name string) *SubgroveBuilder {
	return &SubgroveBuilder{
		req: &RegisterSubgroveRequest{
			SubgroveID: subgroveID,
			AppID:      appID,
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
