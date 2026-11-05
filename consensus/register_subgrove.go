package consensus

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
)

// RegisterSubgroveUnsignedBincode returns the bytes a RegisterSubgrove
// transaction's Config hashes: the bincode (1.x default) of the chain's
// RegisterSubgroveTx struct, decoded from txJSON (the JSON object inside
// {"RegisterSubgrove": ...}, exactly as sent to /tx/submit), with its
// signature replaced by an empty one.
//
// The encoding: integers fixed-width little-endian (u8, u32, u64, u128); bool
// one byte; String and Vec<T> a u64 length, then the UTF-8 bytes or the
// elements; [u8; 32] and [u32; 4] the elements alone; Option<T> a byte 0 for
// None or 1 then T; enums a u32 variant index, then the variant's fields.
//
// A field the JSON leaves out takes the value the chain fills in for it
// (description "", admins [], confirmation_depth 0, mode DataStorage with an
// empty name and lists, and so on), so the bytes are those of the transaction
// the chain decodes. A field the chain requires that is missing, null, or of
// the wrong type is refused.
func RegisterSubgroveUnsignedBincode(txJSON []byte) ([]byte, error) {
	v, err := decodeExact(txJSON)
	if err != nil {
		return nil, fmt.Errorf("RegisterSubgrove: %w", err)
	}
	e := &bincodeEncoder{}
	if err := e.registerSubgrove(v); err != nil {
		return nil, fmt.Errorf("RegisterSubgrove: %w", err)
	}
	return e.out, nil
}

// decodeExact parses JSON keeping every number's digits (json.Number).
func decodeExact(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("trailing data after the JSON value")
	}
	return v, nil
}

var (
	teeTypes              = []string{"AwsNitro", "IntelSgx", "AmdSev"}
	subgroveModes         = []string{"DataStorage", "FileStorage", "BlockchainIndexing"}
	commitmentFrequencies = []string{"EveryUpdate", "EveryNBlocks", "EveryNSeconds", "Never"}
	executionModes        = []string{"ConsensusExecution", "IndexerExecution", "TeeExecution"}
	retentionWindows      = []string{"Blocks", "Seconds", "Indefinite", "VerifyOnly"}
	historicalAuthModes   = []string{"BftEquivalent", "CanonizedAccumulator"}
)

// defaultEpochLength is the chain's IndexerConfig.epoch_length default.
const defaultEpochLength = 100

type bincodeEncoder struct {
	out []byte
}

func (e *bincodeEncoder) u8(v uint8)   { e.out = append(e.out, v) }
func (e *bincodeEncoder) u32(v uint32) { e.out = binary.LittleEndian.AppendUint32(e.out, v) }
func (e *bincodeEncoder) u64(v uint64) { e.out = binary.LittleEndian.AppendUint64(e.out, v) }
func (e *bincodeEncoder) u128(v Uint128) {
	e.out = v.appendLittleEndian(e.out)
}
func (e *bincodeEncoder) boolean(v bool) {
	if v {
		e.u8(1)
	} else {
		e.u8(0)
	}
}
func (e *bincodeEncoder) bytesVec(b []byte) {
	e.u64(uint64(len(b)))
	e.out = append(e.out, b...)
}
func (e *bincodeEncoder) str(s string) { e.bytesVec([]byte(s)) }
func (e *bincodeEncoder) strs(xs []string) {
	e.u64(uint64(len(xs)))
	for _, x := range xs {
		e.str(x)
	}
}

// object is a decoded JSON object with the path it was read at, for errors.
type object struct {
	path   string
	fields map[string]any
}

func asObject(v any, path string) (object, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return object{}, fmt.Errorf("%s: want an object, got %s", path, describe(v))
	}
	return object{path: path, fields: m}, nil
}

func describe(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case string:
		return "a string"
	case json.Number:
		return "a number"
	case bool:
		return "a boolean"
	case []any:
		return "an array"
	case map[string]any:
		return "an object"
	}
	return fmt.Sprintf("%T", v)
}

func (o object) at(name string) string { return o.path + "." + name }

// get returns a field the chain requires.
func (o object) get(name string) (any, error) {
	v, ok := o.fields[name]
	if !ok {
		return nil, fmt.Errorf("%s: missing", o.at(name))
	}
	return v, nil
}

// lookup returns a field and whether the JSON has it.
func (o object) lookup(name string) (any, bool) {
	v, ok := o.fields[name]
	return v, ok
}

func (o object) str(name string) (string, error) {
	v, err := o.get(name)
	if err != nil {
		return "", err
	}
	return asString(v, o.at(name))
}

func (o object) strOr(name, def string) (string, error) {
	v, ok := o.lookup(name)
	if !ok {
		return def, nil
	}
	return asString(v, o.at(name))
}

func asString(v any, path string) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%s: want a string, got %s", path, describe(v))
	}
	return s, nil
}

func asStrings(v any, path string) ([]string, error) {
	a, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%s: want an array of strings, got %s", path, describe(v))
	}
	out := make([]string, len(a))
	for i, x := range a {
		s, err := asString(x, fmt.Sprintf("%s[%d]", path, i))
		if err != nil {
			return nil, err
		}
		out[i] = s
	}
	return out, nil
}

func (o object) strs(name string) ([]string, error) {
	v, err := o.get(name)
	if err != nil {
		return nil, err
	}
	return asStrings(v, o.at(name))
}

func (o object) strsOrEmpty(name string) ([]string, error) {
	v, ok := o.lookup(name)
	if !ok {
		return nil, nil
	}
	return asStrings(v, o.at(name))
}

// asUint reads a JSON number that fits in bits bits.
func asUint(v any, bits int, path string) (uint64, error) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, fmt.Errorf("%s: want a number, got %s", path, describe(v))
	}
	x, err := strconv.ParseUint(n.String(), 10, bits)
	if err != nil {
		return 0, fmt.Errorf("%s: %s is not a u%d", path, n, bits)
	}
	return x, nil
}

func (o object) uint(name string, bits int) (uint64, error) {
	v, err := o.get(name)
	if err != nil {
		return 0, err
	}
	return asUint(v, bits, o.at(name))
}

func (o object) uintOr(name string, bits int, def uint64) (uint64, error) {
	v, ok := o.lookup(name)
	if !ok {
		return def, nil
	}
	return asUint(v, bits, o.at(name))
}

// asU128 reads a u128 from a JSON number, or also from a decimal string where
// the chain accepts one (its u128_flexible fields).
func asU128(v any, path string, stringToo bool) (Uint128, error) {
	var text string
	switch x := v.(type) {
	case json.Number:
		text = x.String()
	case string:
		if !stringToo {
			return Uint128{}, fmt.Errorf("%s: want a number, got a string", path)
		}
		text = x
	default:
		return Uint128{}, fmt.Errorf("%s: want a number, got %s", path, describe(v))
	}
	u, err := ParseUint128(text)
	if err != nil {
		return Uint128{}, fmt.Errorf("%s: %w", path, err)
	}
	return u, nil
}

func (o object) boolOr(name string, def bool) (bool, error) {
	v, ok := o.lookup(name)
	if !ok {
		return def, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("%s: want a boolean, got %s", o.at(name), describe(v))
	}
	return b, nil
}

func (o object) boolean(name string) (bool, error) {
	if _, err := o.get(name); err != nil {
		return false, err
	}
	return o.boolOr(name, false)
}

// asBytes reads a JSON array of byte values.
func asBytes(v any, path string) ([]byte, error) {
	a, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%s: want an array of byte values, got %s", path, describe(v))
	}
	out := make([]byte, len(a))
	for i, x := range a {
		b, err := asUint(x, 8, fmt.Sprintf("%s[%d]", path, i))
		if err != nil {
			return nil, err
		}
		out[i] = byte(b)
	}
	return out, nil
}

func (o object) bytes(name string) ([]byte, error) {
	v, err := o.get(name)
	if err != nil {
		return nil, err
	}
	return asBytes(v, o.at(name))
}

// option writes an Option field: absent or null is None.
func (e *bincodeEncoder) option(o object, name string, write func(v any, path string) error) error {
	v, ok := o.lookup(name)
	if !ok || v == nil {
		e.u8(0)
		return nil
	}
	e.u8(1)
	return write(v, o.at(name))
}

// enumParts splits an externally tagged enum value: "Variant", or
// {"Variant": payload}.
func enumParts(v any, path string) (string, any, error) {
	switch x := v.(type) {
	case string:
		return x, nil, nil
	case map[string]any:
		if len(x) == 1 {
			for name, payload := range x {
				return name, payload, nil
			}
		}
	}
	return "", nil, fmt.Errorf("%s: want an enum variant, got %s", path, describe(v))
}

// variant writes the u32 index of the enum variant name.
func (e *bincodeEncoder) variant(name string, variants []string, path string) error {
	for i, v := range variants {
		if v == name {
			e.u32(uint32(i))
			return nil
		}
	}
	return fmt.Errorf("%s: unknown variant %q", path, name)
}

// unitVariant writes a fieldless enum given as a string.
func (e *bincodeEncoder) unitVariant(v any, variants []string, path string) error {
	name, ok := v.(string)
	if !ok {
		return fmt.Errorf("%s: want one of %v, got %s", path, variants, describe(v))
	}
	return e.variant(name, variants, path)
}

func (e *bincodeEncoder) registerSubgrove(v any) error {
	t, err := asObject(v, "RegisterSubgrove")
	if err != nil {
		return err
	}
	for _, name := range []string{"subgrove_id", "name"} {
		s, err := t.str(name)
		if err != nil {
			return err
		}
		e.str(s)
	}
	description, err := t.strOr("description", "")
	if err != nil {
		return err
	}
	e.str(description)
	for _, name := range []string{"schema", "owner_did"} {
		s, err := t.str(name)
		if err != nil {
			return err
		}
		e.str(s)
	}
	admins, err := t.strsOrEmpty("admins")
	if err != nil {
		return err
	}
	e.strs(admins)
	if err := e.option(t, "initial_funding", func(v any, path string) error {
		u, err := asU128(v, path, true)
		if err != nil {
			return err
		}
		e.u128(u)
		return nil
	}); err != nil {
		return err
	}
	if cv, ok := t.lookup("checkpoint_verification"); ok {
		c, err := asObject(cv, t.at("checkpoint_verification"))
		if err != nil {
			return err
		}
		if err := e.option(c, "required_tee", func(v any, path string) error {
			return e.unitVariant(v, teeTypes, path)
		}); err != nil {
			return err
		}
	} else {
		e.u8(0) // required_tee: None
	}
	if mode, ok := t.lookup("mode"); ok {
		if err := e.subgroveMode(mode, t.at("mode")); err != nil {
			return err
		}
	} else {
		// DataStorage with an empty name, writers, and free readers, no pricing.
		e.u32(0)
		e.str("")
		e.strs(nil)
		e.strs(nil)
		e.u8(0)
	}
	if err := e.option(t, "privacy", e.privacy); err != nil {
		return err
	}
	if err := e.option(t, "initial_owner_key_grant", e.keyGrant); err != nil {
		return err
	}
	if err := e.option(t, "template_config", e.templateConfig); err != nil {
		return err
	}
	depth, err := t.uintOr("confirmation_depth", 32, 0)
	if err != nil {
		return err
	}
	e.u32(uint32(depth))
	// The chain requires a signature field; the hashed transaction carries an
	// empty one.
	if _, err := t.bytes("signature"); err != nil {
		return err
	}
	e.bytesVec(nil)
	publicKeyID, err := t.str("public_key_id")
	if err != nil {
		return err
	}
	e.str(publicKeyID)
	nonce, err := t.uint("nonce", 64)
	if err != nil {
		return err
	}
	e.u64(nonce)
	completeness, err := t.boolOr("cryptographic_completeness", false)
	if err != nil {
		return err
	}
	e.boolean(completeness)
	return nil
}

func (e *bincodeEncoder) readPricing(v any, path string) error {
	p, err := asObject(v, path)
	if err != nil {
		return err
	}
	enabled, err := p.boolean("enabled")
	if err != nil {
		return err
	}
	price, err := p.get("price_per_query")
	if err != nil {
		return err
	}
	u, err := asU128(price, p.at("price_per_query"), false)
	if err != nil {
		return err
	}
	share, err := p.uint("owner_revenue_share_bps", 32)
	if err != nil {
		return err
	}
	e.boolean(enabled)
	e.u128(u)
	e.u32(uint32(share))
	return nil
}

func (e *bincodeEncoder) subgroveMode(v any, path string) error {
	name, payload, err := enumParts(v, path)
	if err != nil {
		return err
	}
	if err := e.variant(name, subgroveModes, path); err != nil {
		return err
	}
	m, err := asObject(payload, path+"."+name)
	if err != nil {
		return err
	}
	switch name {
	case "DataStorage":
		modeName, err := m.str("name")
		if err != nil {
			return err
		}
		writers, err := m.strs("writers")
		if err != nil {
			return err
		}
		// The chain also reads free_readers from "readers".
		freeReaders, hasFree := m.lookup("free_readers")
		readers, hasReaders := m.lookup("readers")
		if hasFree && hasReaders {
			return fmt.Errorf("%s: both free_readers and readers", m.path)
		}
		field := "free_readers"
		if hasReaders {
			freeReaders, field = readers, "readers"
		} else if !hasFree {
			return fmt.Errorf("%s: missing", m.at("free_readers"))
		}
		free, err := asStrings(freeReaders, m.at(field))
		if err != nil {
			return err
		}
		e.str(modeName)
		e.strs(writers)
		e.strs(free)
		return e.option(m, "read_pricing", e.readPricing)
	case "FileStorage":
		modeName, err := m.str("name")
		if err != nil {
			return err
		}
		maxFileSize, err := m.uint("max_file_size", 64)
		if err != nil {
			return err
		}
		replication, err := m.uint("replication_factor", 8)
		if err != nil {
			return err
		}
		writers, err := m.strs("writers")
		if err != nil {
			return err
		}
		free, err := m.strs("free_readers")
		if err != nil {
			return err
		}
		e.str(modeName)
		e.u64(maxFileSize)
		e.u8(uint8(replication))
		e.strs(writers)
		e.strs(free)
		if err := e.option(m, "read_pricing", e.readPricing); err != nil {
			return err
		}
		retention, err := m.uintOr("retention_period", 64, 0)
		if err != nil {
			return err
		}
		e.u64(retention)
		return nil
	default:
		return e.blockchainIndexing(m)
	}
}

func (e *bincodeEncoder) blockchainIndexing(m object) error {
	manifest, err := m.bytes("manifest_content")
	if err != nil {
		return err
	}
	e.bytesVec(manifest)
	var modules []any
	if v, ok := m.lookup("wasm_modules"); ok {
		a, ok := v.([]any)
		if !ok {
			return fmt.Errorf("%s: want an array, got %s", m.at("wasm_modules"), describe(v))
		}
		modules = a
	}
	e.u64(uint64(len(modules)))
	for i, mv := range modules {
		module, err := asObject(mv, fmt.Sprintf("%s[%d]", m.at("wasm_modules"), i))
		if err != nil {
			return err
		}
		name, err := module.str("name")
		if err != nil {
			return err
		}
		hash, err := module.bytes("hash")
		if err != nil {
			return err
		}
		if len(hash) != 32 {
			return fmt.Errorf("%s: want 32 bytes, got %d", module.at("hash"), len(hash))
		}
		content, err := module.bytes("content")
		if err != nil {
			return err
		}
		e.str(name)
		e.out = append(e.out, hash...)
		e.bytesVec(content)
	}

	ev, err := m.get("execution_mode")
	if err != nil {
		return err
	}
	exName, exPayload, err := enumParts(ev, m.at("execution_mode"))
	if err != nil {
		return err
	}
	if err := e.variant(exName, executionModes, m.at("execution_mode")); err != nil {
		return err
	}
	switch exName {
	case "IndexerExecution":
		ex, err := asObject(exPayload, m.at("execution_mode")+"."+exName)
		if err != nil {
			return err
		}
		rate, err := ex.uint("sampling_rate_percent", 8)
		if err != nil {
			return err
		}
		e.u8(uint8(rate))
	case "TeeExecution":
		ex, err := asObject(exPayload, m.at("execution_mode")+"."+exName)
		if err != nil {
			return err
		}
		tee, err := ex.get("tee_type")
		if err != nil {
			return err
		}
		if err := e.unitVariant(tee, teeTypes, ex.at("tee_type")); err != nil {
			return err
		}
	}

	icv, err := m.get("indexer_config")
	if err != nil {
		return err
	}
	ic, err := asObject(icv, m.at("indexer_config"))
	if err != nil {
		return err
	}
	minIndexers, err := ic.uint("min_indexers", 8)
	if err != nil {
		return err
	}
	maxIndexers, err := ic.uint("max_indexers", 8)
	if err != nil {
		return err
	}
	rewardV, err := ic.get("reward_per_epoch")
	if err != nil {
		return err
	}
	reward, err := asU128(rewardV, ic.at("reward_per_epoch"), true)
	if err != nil {
		return err
	}
	epochLength, err := ic.uintOr("epoch_length", 64, defaultEpochLength)
	if err != nil {
		return err
	}
	stakeV, err := ic.get("min_indexer_stake")
	if err != nil {
		return err
	}
	stake, err := asU128(stakeV, ic.at("min_indexer_stake"), true)
	if err != nil {
		return err
	}
	e.u8(uint8(minIndexers))
	e.u8(uint8(maxIndexers))
	e.u128(reward)
	e.u64(epochLength)
	e.u128(stake)

	if rv, ok := m.lookup("retention_window"); ok {
		rwName, rwValue, err := enumParts(rv, m.at("retention_window"))
		if err != nil {
			return err
		}
		if err := e.variant(rwName, retentionWindows, m.at("retention_window")); err != nil {
			return err
		}
		if rwName == "Blocks" || rwName == "Seconds" {
			n, err := asUint(rwValue, 64, m.at("retention_window")+"."+rwName)
			if err != nil {
				return err
			}
			e.u64(n)
		}
	} else {
		e.u32(2) // Indefinite
	}

	if err := e.option(m, "completeness", func(v any, path string) error {
		c, err := asObject(v, path)
		if err != nil {
			return err
		}
		for _, name := range []string{"log_config_hash", "tx_config_hash"} {
			hv, err := c.get(name)
			if err != nil {
				return err
			}
			a, ok := hv.([]any)
			if !ok || len(a) != 4 {
				return fmt.Errorf("%s: want 4 u32 values", c.at(name))
			}
			for i, x := range a {
				n, err := asUint(x, 32, fmt.Sprintf("%s[%d]", c.at(name), i))
				if err != nil {
					return err
				}
				e.u32(uint32(n))
			}
		}
		deferred, err := c.boolOr("deferred", false)
		if err != nil {
			return err
		}
		bond := Uint128{}
		if bv, ok := c.lookup("bond_amount"); ok {
			if bond, err = asU128(bv, c.at("bond_amount"), false); err != nil {
				return err
			}
		}
		e.boolean(deferred)
		e.u128(bond)
		return nil
	}); err != nil {
		return err
	}

	if hv, ok := m.lookup("historical_auth_mode"); ok {
		return e.unitVariant(hv, historicalAuthModes, m.at("historical_auth_mode"))
	}
	e.u32(0) // BftEquivalent
	return nil
}

func (e *bincodeEncoder) privacy(v any, path string) error {
	p, err := asObject(v, path)
	if err != nil {
		return err
	}
	if err := e.option(p, "allowed_indexers", func(v any, path string) error {
		xs, err := asStrings(v, path)
		e.strs(xs)
		return err
	}); err != nil {
		return err
	}
	cv, err := p.get("commitment_frequency")
	if err != nil {
		return err
	}
	name, n, err := enumParts(cv, p.at("commitment_frequency"))
	if err != nil {
		return err
	}
	if err := e.variant(name, commitmentFrequencies, p.at("commitment_frequency")); err != nil {
		return err
	}
	if name == "EveryNBlocks" || name == "EveryNSeconds" {
		x, err := asUint(n, 64, p.at("commitment_frequency")+"."+name)
		if err != nil {
			return err
		}
		e.u64(x)
	}
	return nil
}

func (e *bincodeEncoder) keyGrant(v any, path string) error {
	g, err := asObject(v, path)
	if err != nil {
		return err
	}
	grantee, err := g.str("grantee_did")
	if err != nil {
		return err
	}
	epoch, err := g.uint("key_epoch", 32)
	if err != nil {
		return err
	}
	keyID, err := g.str("grantee_public_key_id")
	if err != nil {
		return err
	}
	ephemeral, err := g.bytes("ephemeral_public_key")
	if err != nil {
		return err
	}
	encrypted, err := g.bytes("encrypted_key")
	if err != nil {
		return err
	}
	grantedBy, err := g.str("granted_by")
	if err != nil {
		return err
	}
	grantedAt, err := g.uint("granted_at", 64)
	if err != nil {
		return err
	}
	e.str(grantee)
	e.u32(uint32(epoch))
	e.str(keyID)
	e.bytesVec(ephemeral)
	e.bytesVec(encrypted)
	e.str(grantedBy)
	e.u64(grantedAt)
	return nil
}

func (e *bincodeEncoder) templateConfig(v any, path string) error {
	c, err := asObject(v, path)
	if err != nil {
		return err
	}
	templateID, err := c.str("template_id")
	if err != nil {
		return err
	}
	version, err := c.uint("template_version", 32)
	if err != nil {
		return err
	}
	variantID, err := c.str("variant_id")
	if err != nil {
		return err
	}
	parameters, err := c.bytes("parameters")
	if err != nil {
		return err
	}
	contracts, err := c.strs("contracts")
	if err != nil {
		return err
	}
	events, err := c.strs("event_signatures")
	if err != nil {
		return err
	}
	e.str(templateID)
	e.u32(uint32(version))
	e.str(variantID)
	e.bytesVec(parameters)
	e.strs(contracts)
	e.strs(events)
	return e.option(c, "chain", func(v any, path string) error {
		s, err := asString(v, path)
		e.str(s)
		return err
	})
}
