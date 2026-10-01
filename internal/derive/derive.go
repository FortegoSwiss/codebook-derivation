// Package derive implements this module's HKDF-SHA-256 key-derivation chain
// (see README.md's "Derivation" section): BatchKey, RecoveryCodeData,
// and UserKey. Every function here operates
// on plain byte values (entropy, batchNumber, entryIndex) rather than root
// package derivation's own identifier types, so that this package never
// needs to import package derivation -- derivation imports derive, and the
// reverse would be an import cycle. Root's batch.go does the thin
// conversion between its own BatchNumber/EntryIndex/UserKey types (plus the
// 256-bit entropy the public bip39 package's Mnemonic.Entropy extracts
// from each caller-supplied mnemonic string) and this package's plain
// values at every call site.
package derive

import (
	"errors"

	"github.com/FortegoSwiss/codebook-derivation/internal/hkdf"
	"github.com/FortegoSwiss/codebook-derivation/internal/recoverycode"
)

// DerivationV1 is the one protocol derivation version this package defines.
// It is encoded in every derivation context and is also the Batch wire
// header's version byte: v1 has exactly one derivation suite and one wire
// layout, so the two must advance together.
const (
	DerivationV1 uint8 = 1
)

// minBatchNumber/maxBatchNumber and minEntryIndex/maxEntryIndex mirror root's
// BatchNumber domain (1..1023) and EntryIndex/MaxEntriesPerBatch domain
// (1..100_000) (keys.go's BatchNumber.valid
// and EntryIndex.valid). This package cannot call those methods without
// importing package derivation, which would be an import cycle (derivation
// imports this package), so the two magic numbers are intentionally
// duplicated here as a deliberate, minor exception to DRY -- every call
// site in root pre-validates batchNumber/entryIndex before ever reaching this
// package (BatchGenerator.Generate checks batchNumber.valid()/size before deriving
// anything; RecoverUserKey only ever passes a batchNumber that
// parseRecoveryCode has already range-checked), so these checks are
// defense-in-depth here, not the primary enforcement point -- but they
// keep this package correct and self-contained even if called some other
// way in the future.
const (
	minBatchNumber = 1
	maxBatchNumber = 1023
	minEntryIndex  = 1
	maxEntryIndex  = 100_000
)

var (
	// ErrInvalidBatchNumber is returned when batchNumber is outside 1..1023. Its
	// message text matches root's own ErrInvalidBatchNumber (keys.go)
	// exactly, but it is a distinct error value: every call site in root
	// pre-validates batchNumber before calling into this package, so this
	// branch is unreachable via the public API today.
	ErrInvalidBatchNumber = errors.New("derivation: BatchNumber must be in 1..1023")
	// ErrInvalidEntryIndex is returned when entryIndex is outside
	// 1..MaxEntriesPerBatch. See ErrInvalidBatchNumber's doc for the same
	// "message matches, value is distinct, unreachable via the public API
	// today" note.
	ErrInvalidEntryIndex = errors.New("derivation: EntryIndex must be in 1..MaxEntriesPerBatch")
)

func validBatchNumber(v uint16) bool {
	return v >= minBatchNumber && v <= maxBatchNumber
}

func validEntryIndex(v uint32) bool {
	return v >= minEntryIndex && v <= maxEntryIndex
}

// DeriveBatchKey computes the 32-byte BatchKey HKDF-derived
// (see README.md's "Derivation" section) from entropy (a batch mnemonic's
// already-extracted 256-bit entropy) and a batchNumber:
//
//	salt = ctx("batch-key-salt")
//	info = ctx("batch-key", u8(1), u16(batchNumber))
//	PRK  = HKDF-Extract(SHA-256, salt, IKM = entropy)
//	BatchKey = HKDF-Expand(SHA-256, PRK, info, 32)
//
// DeriveBatchKey rejects an out-of-domain batchNumber before deriving
// anything. It is pure and deterministic and never panics.
func DeriveBatchKey(entropy [32]byte, batchNumber uint16) ([32]byte, error) {
	if !validBatchNumber(batchNumber) {
		return [32]byte{}, ErrInvalidBatchNumber
	}

	salt := hkdf.Ctx("batch-key-salt")
	info := hkdf.Ctx("batch-key", hkdf.U8(DerivationV1), hkdf.U16(batchNumber))

	okm, err := hkdf.ExtractExpand(entropy[:], salt, info, 32)
	if err != nil {
		return [32]byte{}, err
	}
	var k [32]byte
	copy(k[:], okm)
	return k, nil
}

// DeriveRecoveryCodeData computes the 16-byte RecoveryCodeData HKDF-derived
// (see README.md's "Derivation" section) from entropy (a recovery-code mnemonic's already
// -extracted 256-bit entropy), a batchNumber and an entryIndex:
//
//	salt = ctx("recovery-code-data-salt")
//	info = ctx("recovery-code-data", u8(1), u16(batchNumber), u32(entryIndex))
//	PRK  = HKDF-Extract(SHA-256, salt, IKM = entropy)
//	RecoveryCodeData = HKDF-Expand(SHA-256, PRK, info, 16)
//
// DeriveRecoveryCodeData rejects an out-of-domain batchNumber or entryIndex
// before deriving anything. It never panics.
func DeriveRecoveryCodeData(entropy [32]byte, batchNumber uint16, entryIndex uint32) ([16]byte, error) {
	if !validBatchNumber(batchNumber) {
		return [16]byte{}, ErrInvalidBatchNumber
	}
	if !validEntryIndex(entryIndex) {
		return [16]byte{}, ErrInvalidEntryIndex
	}

	salt := hkdf.Ctx("recovery-code-data-salt")
	info := hkdf.Ctx("recovery-code-data", hkdf.U8(DerivationV1), hkdf.U16(batchNumber), hkdf.U32(entryIndex))

	okm, err := hkdf.ExtractExpand(entropy[:], salt, info, 16)
	if err != nil {
		return [16]byte{}, err
	}
	var d [16]byte
	copy(d[:], okm)
	return d, nil
}

// DeriveUserKey computes the 32-byte UserKey by combining batchKey and
// data as one HKDF-Extract input key material:
//
//	salt = ctx("user-key-salt")
//	IKM  = BatchKey ‖ RecoveryCodeData                 // 32 + 16 = 48 bytes
//	info = ctx("user-key", u8(1), u16(batchNumber), u8(0))    // Extension fixed to 0
//	PRK  = HKDF-Extract(SHA-256, salt, IKM)
//	UserKey = HKDF-Expand(SHA-256, PRK, info, 32)
//
// DeriveUserKey rejects an out-of-domain batchNumber before deriving
// anything. It is pure and deterministic and never panics.
func DeriveUserKey(batchKey [32]byte, batchNumber uint16, data [16]byte) ([32]byte, error) {
	if !validBatchNumber(batchNumber) {
		return [32]byte{}, ErrInvalidBatchNumber
	}

	salt := hkdf.Ctx("user-key-salt")
	// v2 hazard: recoverycode.ExtensionV1 (always 0 in v1) is hardcoded
	// into info rather than threaded through as a DeriveUserKey parameter.
	// If a future wire version ever allows ext != 0, two Recovery Codes
	// sharing the same batchNumber and RecoveryCodeData but differing only
	// in Extension would derive the identical UserKey, since ext plays no
	// role in this info framing today. Introducing ext != 0 must also widen
	// DeriveUserKey's signature to accept and bind the real ext value here.
	info := hkdf.Ctx("user-key", hkdf.U8(DerivationV1), hkdf.U16(batchNumber), hkdf.U8(recoverycode.ExtensionV1))

	ikm := make([]byte, 0, len(batchKey)+len(data))
	ikm = append(ikm, batchKey[:]...)
	ikm = append(ikm, data[:]...)

	okm, err := hkdf.ExtractExpand(ikm, salt, info, 32)
	if err != nil {
		return [32]byte{}, err
	}
	var k [32]byte
	copy(k[:], okm)
	return k, nil
}
