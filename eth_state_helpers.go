package willow

import "encoding/base64"

// Indirection so the stdlib encoding/base64 import lives in a single
// helper file — keeps the main eth_state.go file deps narrow.
func base64Std() *base64.Encoding    { return base64.StdEncoding }
func base64RawStd() *base64.Encoding { return base64.RawStdEncoding }
