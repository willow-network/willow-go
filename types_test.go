package willow

import (
	"testing"
	"time"
)

func TestSessionIsExpired(t *testing.T) {
	// Not expired
	session := &Session{
		Did:       "did:willow:Ed25519:test",
		Token:     "token",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
	}
	if session.IsExpired() {
		t.Error("Session should not be expired")
	}

	// Expired
	session.ExpiresAt = time.Now().Add(-1 * time.Hour).Unix()
	if !session.IsExpired() {
		t.Error("Session should be expired")
	}
}

func TestRetryConfigDefaults(t *testing.T) {
	config := DefaultRetryConfig()

	if config.MaxRetries != 3 {
		t.Errorf("Expected MaxRetries 3, got %d", config.MaxRetries)
	}
	if config.InitialBackoff != 100*time.Millisecond {
		t.Errorf("Expected InitialBackoff 100ms, got %v", config.InitialBackoff)
	}
	if config.MaxBackoff != 5*time.Second {
		t.Errorf("Expected MaxBackoff 5s, got %v", config.MaxBackoff)
	}
	if config.BackoffFactor != 2.0 {
		t.Errorf("Expected BackoffFactor 2.0, got %f", config.BackoffFactor)
	}
}

func TestIndexTypes(t *testing.T) {
	// Just verify the constants are defined correctly
	if IndexTypeHash != "hash" {
		t.Errorf("Expected IndexTypeHash 'hash', got '%s'", IndexTypeHash)
	}
	if IndexTypeRange != "range" {
		t.Errorf("Expected IndexTypeRange 'range', got '%s'", IndexTypeRange)
	}
	if IndexTypeFullText != "fulltext" {
		t.Errorf("Expected IndexTypeFullText 'fulltext', got '%s'", IndexTypeFullText)
	}
	if IndexTypeInverted != "inverted" {
		t.Errorf("Expected IndexTypeInverted 'inverted', got '%s'", IndexTypeInverted)
	}
}

func TestAppTypes(t *testing.T) {
	if AppTypeStandard != "standard" {
		t.Errorf("Expected AppTypeStandard 'standard', got '%s'", AppTypeStandard)
	}
	if AppTypeIndexer != "indexer" {
		t.Errorf("Expected AppTypeIndexer 'indexer', got '%s'", AppTypeIndexer)
	}
}

func TestValidatorStatus(t *testing.T) {
	if ValidatorStatusActive != "active" {
		t.Errorf("Expected ValidatorStatusActive 'active', got '%s'", ValidatorStatusActive)
	}
	if ValidatorStatusInactive != "inactive" {
		t.Errorf("Expected ValidatorStatusInactive 'inactive', got '%s'", ValidatorStatusInactive)
	}
	if ValidatorStatusJailed != "jailed" {
		t.Errorf("Expected ValidatorStatusJailed 'jailed', got '%s'", ValidatorStatusJailed)
	}
}

func TestQueryBuilderBasic(t *testing.T) {
	query := NewQueryBuilder().
		Equals("status", "active").
		Limit(10).
		Build()

	if len(query.Filters) != 1 {
		t.Errorf("Expected 1 filter, got %d", len(query.Filters))
	}
	if query.Filters[0].Field != "status" {
		t.Errorf("Expected field 'status', got '%s'", query.Filters[0].Field)
	}
	if query.Filters[0].Operator != "eq" {
		t.Errorf("Expected operator 'eq', got '%s'", query.Filters[0].Operator)
	}
	if query.Filters[0].Value != "active" {
		t.Errorf("Expected value 'active', got '%v'", query.Filters[0].Value)
	}
	if query.Limit != 10 {
		t.Errorf("Expected limit 10, got %d", query.Limit)
	}
}

func TestQueryBuilderAllOperators(t *testing.T) {
	query := NewQueryBuilder().
		Equals("a", 1).
		NotEquals("b", 2).
		GreaterThan("c", 3).
		GreaterThanOrEqual("d", 4).
		LessThan("e", 5).
		LessThanOrEqual("f", 6).
		Contains("g", "test").
		Build()

	expectedOps := []string{"eq", "ne", "gt", "gte", "lt", "lte", "contains"}
	if len(query.Filters) != 7 {
		t.Errorf("Expected 7 filters, got %d", len(query.Filters))
	}

	for i, op := range expectedOps {
		if query.Filters[i].Operator != op {
			t.Errorf("Filter %d: expected operator '%s', got '%s'", i, op, query.Filters[i].Operator)
		}
	}
}

func TestQueryBuilderSort(t *testing.T) {
	// Ascending
	query := NewQueryBuilder().SortAsc("created_at").Build()
	if query.Sort == nil {
		t.Fatal("Sort should not be nil")
	}
	if query.Sort.Field != "created_at" {
		t.Errorf("Expected sort field 'created_at', got '%s'", query.Sort.Field)
	}
	if !query.Sort.Ascending {
		t.Error("Expected ascending to be true")
	}

	// Descending
	query = NewQueryBuilder().SortDesc("updated_at").Build()
	if query.Sort.Field != "updated_at" {
		t.Errorf("Expected sort field 'updated_at', got '%s'", query.Sort.Field)
	}
	if query.Sort.Ascending {
		t.Error("Expected ascending to be false")
	}
}

func TestQueryBuilderSearch(t *testing.T) {
	query := NewQueryBuilder().
		Search([]string{"name", "bio"}, "developer").
		Build()

	if query.Search == nil {
		t.Fatal("Search should not be nil")
	}
	if len(query.Search.Fields) != 2 {
		t.Errorf("Expected 2 search fields, got %d", len(query.Search.Fields))
	}
	if query.Search.Query != "developer" {
		t.Errorf("Expected search query 'developer', got '%s'", query.Search.Query)
	}
}

func TestQueryBuilderPagination(t *testing.T) {
	query := NewQueryBuilder().
		Limit(20).
		Offset(40).
		Build()

	if query.Limit != 20 {
		t.Errorf("Expected limit 20, got %d", query.Limit)
	}
	if query.Offset != 40 {
		t.Errorf("Expected offset 40, got %d", query.Offset)
	}
}

func TestAppBuilder(t *testing.T) {
	req := NewAppBuilder("my-app", "My Application").
		Description("A test app").
		Type(AppTypeIndexer).
		Owner("did:willow:Ed25519:owner").
		AddAdmin("did:willow:Ed25519:admin1").
		AddAdmin("did:willow:Ed25519:admin2").
		Build()

	if req.AppID != "my-app" {
		t.Errorf("Expected AppID 'my-app', got '%s'", req.AppID)
	}
	if req.Name != "My Application" {
		t.Errorf("Expected Name 'My Application', got '%s'", req.Name)
	}
	if req.Description != "A test app" {
		t.Errorf("Expected Description 'A test app', got '%s'", req.Description)
	}
	if req.AppType != AppTypeIndexer {
		t.Errorf("Expected AppType 'indexer', got '%s'", req.AppType)
	}
	if req.OwnerDid != "did:willow:Ed25519:owner" {
		t.Errorf("Expected OwnerDid 'did:willow:Ed25519:owner', got '%s'", req.OwnerDid)
	}
	if len(req.Admins) != 2 {
		t.Errorf("Expected 2 admins, got %d", len(req.Admins))
	}
}

func TestSchemaBuilder(t *testing.T) {
	schema := NewSchemaBuilder("User").
		Description("User profile").
		StringField("name", true).
		StringField("email", true).
		IntField("age", false).
		BoolField("active", false).
		FloatField("score", false).
		ArrayField("tags", "string", false).
		ObjectField("metadata", false).
		HashIndex("email_idx", []string{"email"}).
		RangeIndex("age_idx", []string{"age"}).
		FullTextIndex("name_search", []string{"name"}).
		Build()

	if schema.Name != "User" {
		t.Errorf("Expected schema name 'User', got '%s'", schema.Name)
	}
	if schema.Description != "User profile" {
		t.Errorf("Expected description 'User profile', got '%s'", schema.Description)
	}
	if len(schema.Fields) != 7 {
		t.Errorf("Expected 7 fields, got %d", len(schema.Fields))
	}
	if len(schema.Indexes) != 3 {
		t.Errorf("Expected 3 indexes, got %d", len(schema.Indexes))
	}

	// Check field types
	expectedTypes := map[string]string{
		"name":     "string",
		"email":    "string",
		"age":      "int",
		"active":   "bool",
		"score":    "float",
		"tags":     "array:string",
		"metadata": "object",
	}

	for _, field := range schema.Fields {
		expected, ok := expectedTypes[field.Name]
		if !ok {
			t.Errorf("Unexpected field: %s", field.Name)
			continue
		}
		if field.Type != expected {
			t.Errorf("Field %s: expected type '%s', got '%s'", field.Name, expected, field.Type)
		}
	}

	// Check indexes
	if schema.Indexes[0].Type != IndexTypeHash {
		t.Errorf("Expected first index type 'hash', got '%s'", schema.Indexes[0].Type)
	}
	if schema.Indexes[1].Type != IndexTypeRange {
		t.Errorf("Expected second index type 'range', got '%s'", schema.Indexes[1].Type)
	}
	if schema.Indexes[2].Type != IndexTypeFullText {
		t.Errorf("Expected third index type 'fulltext', got '%s'", schema.Indexes[2].Type)
	}
}

func TestSubgroveBuilder(t *testing.T) {
	schema := NewSchemaBuilder("User").
		StringField("name", true).
		Build()

	req := NewSubgroveBuilder("users", "my-app", "Users").
		Description("User profiles").
		Schema(*schema).
		Owner("did:willow:Ed25519:owner").
		AddWriter("did:willow:Ed25519:writer1").
		AddReader("did:willow:Ed25519:reader1").
		RewardRate(1000).
		Build()

	if req.SubgroveID != "users" {
		t.Errorf("Expected SubgroveID 'users', got '%s'", req.SubgroveID)
	}
	if req.AppID != "my-app" {
		t.Errorf("Expected AppID 'my-app', got '%s'", req.AppID)
	}
	if req.Name != "Users" {
		t.Errorf("Expected Name 'Users', got '%s'", req.Name)
	}
	if req.Schema.Name != "User" {
		t.Errorf("Expected Schema.Name 'User', got '%s'", req.Schema.Name)
	}
	if len(req.Writers) != 1 {
		t.Errorf("Expected 1 writer, got %d", len(req.Writers))
	}
	if len(req.Readers) != 1 {
		t.Errorf("Expected 1 reader, got %d", len(req.Readers))
	}
	if req.RewardRate != 1000 {
		t.Errorf("Expected RewardRate 1000, got %d", req.RewardRate)
	}
}
