package willow

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// chainSchema is a subgrove schema in the chain's form, the JSON text a
// RegisterSubgrove transaction carries in its schema field.
type chainSchema struct {
	Version        uint32            `json:"version"`
	Fields         map[string]string `json:"fields"`
	Indexes        []chainIndex      `json:"indexes"`
	RequiredFields []string          `json:"required_fields"`
}

type chainIndex struct {
	Name   string   `json:"name"`
	Fields []string `json:"fields"`
	Unique bool     `json:"unique"`
}

// ChainSchemaJSON returns the schema as the JSON text a RegisterSubgrove
// transaction carries:
//
//	{"version":1,"fields":{"<name>":"<type>",...},"indexes":[{"name":...,"fields":[...],"unique":...}],"required_fields":[...]}
//
// Field types map to the chain's: string; int, integer, float, and number to
// number; bool and boolean to boolean; array and array:<item> to array;
// object; bytes. Another type is refused. Required fields go in
// required_fields. The chain's schema has no name, description, per-field
// indexed flag, or index type, so those are not sent.
func (s SchemaDefinition) ChainSchemaJSON() (string, error) {
	out := chainSchema{
		Version:        1,
		Fields:         map[string]string{},
		Indexes:        []chainIndex{},
		RequiredFields: []string{},
	}
	for _, f := range s.Fields {
		if f.Name == "" {
			return "", NewValidationError("schema field with no name")
		}
		if _, dup := out.Fields[f.Name]; dup {
			return "", NewValidationError(fmt.Sprintf("schema field %q appears twice", f.Name))
		}
		t, err := chainFieldType(f.Type)
		if err != nil {
			return "", err
		}
		out.Fields[f.Name] = t
		if f.Required {
			out.RequiredFields = append(out.RequiredFields, f.Name)
		}
	}
	for _, idx := range s.Indexes {
		fields := idx.Fields
		if fields == nil {
			fields = []string{}
		}
		out.Indexes = append(out.Indexes, chainIndex{Name: idx.Name, Fields: fields, Unique: idx.Unique})
	}
	body, err := json.Marshal(out)
	if err != nil {
		return "", NewSerializationError("failed to encode the schema", err)
	}
	return string(body), nil
}

func chainFieldType(t string) (string, error) {
	switch lower := strings.ToLower(t); {
	case lower == "string", lower == "object", lower == "bytes":
		return lower, nil
	case lower == "int", lower == "integer", lower == "float", lower == "number":
		return "number", nil
	case lower == "bool", lower == "boolean":
		return "boolean", nil
	case lower == "array", strings.HasPrefix(lower, "array:"):
		return "array", nil
	}
	return "", NewValidationError(fmt.Sprintf("schema field type %q has no chain equivalent (string, number, boolean, array, object, bytes)", t))
}

// UnmarshalJSON reads a schema in this SDK's form (fields as a list) or in the
// chain's (fields as a map of name to type, with required_fields), which is
// how the API lists registered subgroves. Read from the chain's form, fields
// are sorted by name.
func (s *SchemaDefinition) UnmarshalJSON(data []byte) error {
	var probe struct {
		Fields json.RawMessage `json:"fields"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return err
	}
	if !bytes.HasPrefix(bytes.TrimSpace(probe.Fields), []byte("{")) {
		type plain SchemaDefinition
		var p plain
		if err := json.Unmarshal(data, &p); err != nil {
			return err
		}
		*s = SchemaDefinition(p)
		return nil
	}
	var c chainSchema
	if err := json.Unmarshal(data, &c); err != nil {
		return err
	}
	required := map[string]bool{}
	for _, name := range c.RequiredFields {
		required[name] = true
	}
	names := make([]string, 0, len(c.Fields))
	for name := range c.Fields {
		names = append(names, name)
	}
	sort.Strings(names)
	out := SchemaDefinition{Fields: make([]SchemaField, 0, len(names))}
	for _, name := range names {
		out.Fields = append(out.Fields, SchemaField{Name: name, Type: c.Fields[name], Required: required[name]})
	}
	for _, idx := range c.Indexes {
		out.Indexes = append(out.Indexes, IndexDefinition{Name: idx.Name, Fields: idx.Fields, Unique: idx.Unique})
	}
	*s = out
	return nil
}
