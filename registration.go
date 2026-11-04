package willow

import (
	"context"
	"fmt"

	"github.com/willow-network/willow-go/consensus"
)

// RegistrationOperations provides methods for subgrove registration.
type RegistrationOperations struct {
	client *Client
}

// RegisterSubgrove registers a DataStorage subgrove owned by the client's
// identity, by sending a signed RegisterSubgrove transaction to POST
// /tx/submit.
//
// The transaction carries req's SubgroveID, Name, and Description, its Schema
// in the chain's form (SchemaDefinition.ChainSchemaJSON), and a DataStorage
// mode named Name whose writers are Writers and whose free readers are
// Readers. Every other field is sent with its default: no admins, funding,
// TEE requirement, read pricing, privacy, or template. It is signed over
// FormatRegisterSubgroveMessage, which binds all of them and the nonce, one
// past the identity's account nonce. For another mode or those fields, build a
// consensus.RegisterSubgroveTx, sign FormatRegisterSubgroveMessage, and send it
// with consensus.Client.BroadcastTxSync.
//
// OwnerDid, when set, must be the identity's DID, and RewardRate must be 0: a
// DataStorage registration has no reward rate. SubgroveID must be 1 to 64
// ASCII letters, digits, '-', or '_', starting with a letter or digit, and the
// schema must declare no indexes, as the chain requires. The registration
// returned is req as sent; the subgrove exists once the transaction's block
// commits.
func (r *RegistrationOperations) RegisterSubgrove(ctx context.Context, req *RegisterSubgroveRequest) (*SubgroveRegistration, error) {
	if err := r.client.RequireAuth(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, NewValidationError("RegisterSubgrove: no request")
	}
	identity := r.client.GetIdentity()
	if req.OwnerDid != "" && req.OwnerDid != identity.DID() {
		return nil, NewValidationError("RegisterSubgrove: the owner signs the registration, so OwnerDid must be the identity's DID")
	}
	if req.RewardRate != 0 {
		return nil, NewValidationError("RegisterSubgrove: a DataStorage registration has no reward rate")
	}
	if err := validateStorageSubgroveID(req.SubgroveID); err != nil {
		return nil, err
	}
	schema, err := req.Schema.ChainSchemaJSON()
	if err != nil {
		return nil, err
	}

	nonce, err := r.client.nextTxNonce(ctx, identity.DID())
	if err != nil {
		return nil, fmt.Errorf("failed to get nonce: %w", err)
	}
	tx := &consensus.RegisterSubgroveTx{
		SubgroveID:  req.SubgroveID,
		Name:        req.Name,
		Description: req.Description,
		Schema:      schema,
		OwnerDid:    identity.DID(),
		Mode: &consensus.SubgroveMode{DataStorage: &consensus.SubgroveDataStorage{
			Name:        req.Name,
			Writers:     req.Writers,
			FreeReaders: req.Readers,
		}},
		PublicKeyID: identity.PublicKeyID(),
		Nonce:       nonce,
	}
	message, err := FormatRegisterSubgroveMessage(tx)
	if err != nil {
		return nil, err
	}
	if tx.Signature, err = identity.Sign([]byte(message)); err != nil {
		return nil, err
	}
	if err := r.client.submitTx(ctx, map[string]interface{}{"RegisterSubgrove": tx}); err != nil {
		return nil, err
	}

	return &SubgroveRegistration{
		SubgroveID:  req.SubgroveID,
		Name:        req.Name,
		Description: req.Description,
		Schema:      req.Schema,
		OwnerDid:    identity.DID(),
		Writers:     req.Writers,
		Readers:     req.Readers,
	}, nil
}

// GetSubgrove retrieves information about a subgrove. The API's
// /subgroves/{id} answers with the subgrove's id, name, and owner (and its
// status), so only those fields are set; ListSubgroves carries whole
// registrations, with the schema, writers, and free readers.
func (r *RegistrationOperations) GetSubgrove(ctx context.Context, subgroveID string) (*SubgroveRegistration, error) {
	var result SubgroveRegistration
	path := fmt.Sprintf("/subgroves/%s", subgroveID)
	err := r.client.getData(ctx, path, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// ListSubgroves lists all subgroves.
func (r *RegistrationOperations) ListSubgroves(ctx context.Context) ([]SubgroveRegistration, error) {
	var results []SubgroveRegistration
	err := r.client.getData(ctx, "/subgroves", &results)
	if err != nil {
		return nil, err
	}
	return results, nil
}

// UpdateSubgrove returns an unsupported-operation error and sends nothing: the
// API serves no subgrove update route. A subgrove is changed by
// UpdateSubgroveReadPricing, UpdateSubgroveFreeReaders, or ReplaceSubgrove
// transactions sent to POST /tx/submit, which this SDK does not build.
func (r *RegistrationOperations) UpdateSubgrove(ctx context.Context, subgroveID string, updates map[string]interface{}) (*SubgroveRegistration, error) {
	return nil, NewUnsupportedError("UpdateSubgrove: the API serves no subgrove update route; a subgrove is changed by UpdateSubgroveReadPricing, UpdateSubgroveFreeReaders, or ReplaceSubgrove transactions sent to POST /tx/submit, which this SDK does not build")
}

// DeleteSubgrove deregisters a subgrove owned by the client's identity by
// sending a signed DeregisterSubgrove transaction to POST /tx/submit (see
// consensus.DeregisterSubgroveSignMessage); the chain refunds its remaining
// balance to the owner.
func (r *RegistrationOperations) DeleteSubgrove(ctx context.Context, subgroveID string) error {
	if err := r.client.RequireAuth(); err != nil {
		return err
	}
	identity := r.client.GetIdentity()
	nonce, err := r.client.nextTxNonce(ctx, identity.DID())
	if err != nil {
		return fmt.Errorf("failed to get nonce: %w", err)
	}
	signature, err := identity.Sign([]byte(consensus.DeregisterSubgroveSignMessage(subgroveID, identity.DID(), nonce)))
	if err != nil {
		return err
	}
	return r.client.submitTx(ctx, map[string]interface{}{
		"DeregisterSubgrove": consensus.DeregisterSubgroveTx{
			SubgroveID:  subgroveID,
			OwnerDid:    identity.DID(),
			Signature:   signature,
			PublicKeyID: identity.PublicKeyID(),
			Nonce:       nonce,
		},
	})
}

// GetPermissions retrieves permissions for a DID.
func (r *RegistrationOperations) GetPermissions(ctx context.Context, did string) ([]Permission, error) {
	var permissions []Permission
	if err := r.client.getData(ctx, fmt.Sprintf("/did/%s/permissions", did), &permissions); err != nil {
		return nil, err
	}
	return permissions, nil
}

// GrantPermission returns an unsupported-operation error and sends nothing:
// the API serves no permission write route. A subgrove's permissions (its
// owner, admins, writers, and readers) are written by its RegisterSubgrove
// transaction (see RegisterSubgrove).
func (r *RegistrationOperations) GrantPermission(ctx context.Context, permission *Permission) error {
	return NewUnsupportedError("GrantPermission: the API serves no permission write route; a subgrove's permissions (owner, admins, writers, readers) are written by its RegisterSubgrove transaction")
}

// RevokePermission returns an unsupported-operation error and sends nothing:
// the API serves no permission write route. A subgrove's permissions are
// written by its RegisterSubgrove transaction (see RegisterSubgrove).
func (r *RegistrationOperations) RevokePermission(ctx context.Context, did, subgroveID string) error {
	return NewUnsupportedError("RevokePermission: the API serves no permission write route; a subgrove's permissions (owner, admins, writers, readers) are written by its RegisterSubgrove transaction")
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

// Field adds a field to the schema. The chain doesn't support schema
// indexes, so ChainSchemaJSON (and RegisterSubgrove) refuse a field added
// with indexed true.
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

// Index adds an index to the schema. The chain doesn't support schema
// indexes, so ChainSchemaJSON (and RegisterSubgrove) refuse a schema with one;
// this and the other index methods describe a schema this SDK can't register.
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
