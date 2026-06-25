// Package willow — client-side completeness verification.
//
// Mirrors Willow's on-chain completeness anchor so a client can verify that an
// indexer's served event set for a (subgrove, block) is the complete,
// untampered filter-matched set the chain attests to — without trusting the
// indexer. The on-chain events_commitment (a 32-byte keccak hash) is the
// trusted anchor; the indexer serves the matched-log preimage; the client
// re-hashes it via CanonicalEventSetHash and compares.
//
// Canonical Rust source: willow-network consensus
// indexed_data_handler::full_block_auth::canonical_event_set_hash.
//
// This file holds the pure, network-free hashing spec (CanonicalEventSetHash /
// VerifyServedEvents). The end-to-end fetch-and-verify convenience wrapper —
// VerifyBlockCompleteness, which pulls the on-chain anchor and the indexer's
// matched-log preimage and calls VerifyServedEvents — lives in
// completeness_fetch.go so this file stays dependency-free for cross-language
// vector comparison.
package willow

import (
	"encoding/binary"
	"hash"

	"golang.org/x/crypto/sha3"
)

// newKeccak256 returns a streaming Ethereum keccak-256 hasher (the legacy
// Keccak padding, NOT NIST SHA3-256) — the same primitive as the package's
// one-shot keccak256 helper.
func newKeccak256() hash.Hash {
	return sha3.NewLegacyKeccak256()
}

// completenessDomainTag is the domain separator hashed before the event set.
// Must stay byte-identical to the on-chain Rust constant.
const completenessDomainTag = "WILLOW_CRYPTO_EVENTS_V1"

// Log is a filter-matched event log as served by the indexer. Only the
// consensus-derivable, root-bound fields are bound by the commitment.
type Log struct {
	Address [20]byte // contract address
	Topics  [][32]byte
	Data    []byte
}

// CanonicalEventSetHash computes the domain-separated keccak-256 commitment
// over the filter-matched event set in canonical order. All integers are
// big-endian and the layout is length-prefixed, so no boundary is ambiguous:
//
//	"WILLOW_CRYPTO_EVENTS_V1"        (23 ASCII bytes, no terminator)
//	blockNumber                      (u64 big-endian, 8 bytes)
//	len(matchedLogs)                 (u64 big-endian, 8 bytes)
//	for each log, in order:
//	  address                        (20 bytes)
//	  len(topics)                    (u32 big-endian, 4 bytes)
//	  each topic                     (32 bytes each)
//	  len(data)                      (u32 big-endian, 4 bytes)
//	  data                           (raw bytes)
func CanonicalEventSetHash(blockNumber uint64, matchedLogs []Log) [32]byte {
	var u64 [8]byte
	var u32 [4]byte

	h := newKeccak256()
	h.Write([]byte(completenessDomainTag))
	binary.BigEndian.PutUint64(u64[:], blockNumber)
	h.Write(u64[:])
	binary.BigEndian.PutUint64(u64[:], uint64(len(matchedLogs)))
	h.Write(u64[:])

	for i := range matchedLogs {
		log := &matchedLogs[i]
		h.Write(log.Address[:])
		binary.BigEndian.PutUint32(u32[:], uint32(len(log.Topics)))
		h.Write(u32[:])
		for j := range log.Topics {
			h.Write(log.Topics[j][:])
		}
		binary.BigEndian.PutUint32(u32[:], uint32(len(log.Data)))
		h.Write(u32[:])
		h.Write(log.Data)
	}

	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// VerifyServedEvents reports whether matchedLogs re-hash to the trusted
// on-chain commitment for blockNumber. A false result means the indexer's
// served set was tampered with, incomplete, or for the wrong block.
func VerifyServedEvents(commitment [32]byte, blockNumber uint64, matchedLogs []Log) bool {
	return CanonicalEventSetHash(blockNumber, matchedLogs) == commitment
}
