package derivation

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/FortegoSwiss/codebook-derivation/internal/crockford"
	"github.com/FortegoSwiss/codebook-derivation/internal/derive"
	"github.com/FortegoSwiss/codebook-derivation/internal/recoverycode"
)

// --- wire layout (see README.md's "Canonical Batch encoding") -------

const (
	// entrySize is one entry's fixed wire width: a 30-byte canonical,
	// ungrouped Crockford Base32 RecoveryCode string (recoverycode.UngroupedLen)
	// followed by a 32-byte UserKey (secretSize). entryIndex is not part of
	// the wire form at all -- it is always an entry's 1-based position, so
	// storing it would be redundant with, and could otherwise
	// desynchronize from, that position.
	entrySize = recoverycode.UngroupedLen + secretSize // 30 + 32 = 62

	// headerSize is the fixed wire width of a Batch's header:
	// version(1 byte) ‖ batchNumber(2 bytes, big-endian) ‖
	// entryCount(4 bytes, big-endian).
	headerSize = 1 + 2 + 4 // 7

	// maxBatchEncodedBytes bounds the raw encoded Batch bytes
	// DecodeBatch will read before trusting any header field:
	// headerSize + MaxEntriesPerBatch*entrySize, the worst case for the
	// maximum entry count regardless of what an actual input's own header
	// claims. Verified against this literal by
	// TestMaxBatchEncodedBytesMatchesConstant.
	maxBatchEncodedBytes = headerSize + MaxEntriesPerBatch*entrySize
)

// --- errors ------------------------------------------------------------

var (
	// ErrInvalidBatchSize is returned by BatchGenerator.Generate when size is outside
	// 1..MaxEntriesPerBatch.
	ErrInvalidBatchSize = errors.New("derivation: Batch size must be in 1..MaxEntriesPerBatch")
	// ErrInvalidBatch is returned by Encode or DecodeBatch when a
	// Batch is invalid, including the zero value.
	ErrInvalidBatch = errors.New("derivation: Batch is invalid or zero-value")

	// Recovery Code parsing errors are re-exported from the wire-format
	// implementation so callers can test their identity with errors.Is.
	//
	// recoverycode.ErrInvalidBatchNumber is deliberately not re-exported
	// alongside these: unlike the other five, it does not get a new
	// ErrRecoveryCodeXxx name of its own. Root package derivation already
	// has its own ErrInvalidBatchNumber (keys.go) -- textually identical but
	// a distinct Go error value, since internal/recoverycode cannot import
	// this package to reuse it without an import cycle. DecodeRecoveryCode
	// and RecoverUserKey both translate recoverycode.ErrInvalidBatchNumber
	// to this package's own ErrInvalidBatchNumber via
	// translateRecoveryCodeParseError below, so callers get the one public
	// sentinel regardless of which internal package rejected the code.
	ErrRecoveryCodeLength    = recoverycode.ErrLength
	ErrRecoveryCodeHyphen    = recoverycode.ErrHyphen
	ErrRecoveryCodeChar      = recoverycode.ErrChar
	ErrRecoveryCodeCRC       = recoverycode.ErrCRC
	ErrRecoveryCodeExtension = recoverycode.ErrExtension
)

// translateRecoveryCodeParseError maps recoverycode.Parse's own
// ErrInvalidBatchNumber to this package's own, public ErrInvalidBatchNumber
// (keys.go) so errors.Is(err, derivation.ErrInvalidBatchNumber) succeeds
// regardless of whether the rejection came from BatchGenerator.Generate's
// own domain check or from parsing a CRC-valid Recovery Code whose embedded
// BatchNumber is out of range -- both call this rejection
// "derivation: BatchNumber must be in 1..1023", and both should be the same
// error to a caller using errors.Is. Every other recoverycode sentinel
// already has its own direct public re-export above and is returned
// unchanged. Both err's message and every other error stay as-is.
func translateRecoveryCodeParseError(err error) error {
	if errors.Is(err, recoverycode.ErrInvalidBatchNumber) {
		return ErrInvalidBatchNumber
	}
	return err
}

// --- Entry -------------------------------------------------------------

// Entry atomically binds one Batch position's 1-based EntryIndex, canonical
// Recovery Code string, and opaque UserKey. Both the Recovery Code and the
// UserKey an Entry exposes are produced by the same internal derivation —
// there is no separate Recovery-Code output slice or second derivation
// path. Entry is immutable and has no public constructor; the only way to
// obtain one is via BatchGenerator.Generate or DecodeBatch's Batch.Entries().
type Entry struct {
	index        EntryIndex
	recoveryCode string
	userKey      UserKey
}

// Index returns e's 1-based, contiguous EntryIndex.
func (e Entry) Index() EntryIndex { return e.index }

// RecoveryCode returns e's canonical Recovery Code string: the same
// 30-character ungrouped Crockford Base32 wire form embedded in a Batch's
// encoded bytes.
func (e Entry) RecoveryCode() string { return e.recoveryCode }

// UserKey returns e's opaque UserKey.
func (e Entry) UserKey() UserKey { return e.userKey }

// Format implements fmt.Formatter so that no verb — %v, %+v, %s, %x, %#v or
// any other — ever renders e's plaintext RecoveryCode or UserKey bytes. Go's
// default struct formatting recurses into unexported fields regardless of
// their own type's protections (UserKey's own Format method is bypassed
// when UserKey is only reachable as an unexported field of a struct, like
// Entry, that itself has no Format method), so without this override a bare
// fmt.Sprintf("%+v", entry) would print both directly.
func (e Entry) Format(f fmt.State, verb rune) {
	redactedFormat(f, "Entry")
}

// --- Batch ---------------------------------------------------------------

// Batch is the one public semantic aggregate this package produces and
// consumes: an immutable collection of Entries, independently verifiable via
// Fingerprint. Batch has no public constructor and no exported, mutable
// field; the only ways to obtain one are BatchGenerator.Generate and
// DecodeBatch. Its zero value is invalid; len(entries) == 0 is
// sufficient to distinguish it, since every successful Generate or
// DecodeBatch call always produces at least one Entry.
type Batch struct {
	version     uint8
	batchNumber BatchNumber
	entries     []Entry
}

// Format implements fmt.Formatter so that no verb — %v, %+v, %s, %x, %#v or
// any other — ever renders b's Entries (each of which carries a plaintext
// RecoveryCode and UserKey). Go's default struct formatting recurses
// into unexported fields regardless of their own type's protections, so
// without this override a bare fmt.Sprintf("%+v", batch) would print every
// Entry's plaintext RecoveryCode string directly (UserKey alone would
// still redact via its own Format method, but RecoveryCode would not,
// since RecoveryCode is intentionally not a secret type). Encode is the one
// intentional plaintext serialization boundary for a Batch as a whole;
// Format keeps every other formatting path from silently reproducing the
// same content.
func (b Batch) Format(f fmt.State, verb rune) {
	redactedFormat(f, "Batch")
}

// BatchNumber returns b's BatchNumber.
func (b Batch) BatchNumber() BatchNumber { return b.batchNumber }

// Len returns the number of Entries in b.
func (b Batch) Len() int { return len(b.entries) }

// Entries returns a defensive copy of b's ordered Entries; mutating the
// returned slice never affects b.
func (b Batch) Entries() []Entry {
	out := make([]Entry, len(b.entries))
	copy(out, b.entries)
	return out
}

// Fingerprint returns b's human-verifiable, independently recomputable
// fingerprint (see README.md's "Fingerprint"): 20 Crockford Base32 characters
// grouped as 4x5, derived from b's version, batchNumber, and
// every Entry (RecoveryCode and UserKey included) — the entire encoded
// form. A matching independently pinned Fingerprint gives 100-bit
// second-preimage resistance against a substituted Batch; it is not
// literal proof of byte-for-byte identity. Fingerprint returns "" for a
// zero-value (or otherwise invalid) Batch, which has no meaningful
// encoded form to fingerprint.
func (b Batch) Fingerprint() string {
	if len(b.entries) == 0 {
		return ""
	}
	return computeFingerprint(b.encodedBytes())
}

// encodedBytes returns b's encoded Batch bytes (see README.md's
// "Canonical Batch encoding"), regardless of whether b is otherwise
// valid. It is shared by Encode and Fingerprint so the two can never
// silently disagree about what "encoded" means.
func (b Batch) encodedBytes() []byte {
	return encodeBatch(b.version, b.batchNumber, b.entries)
}

// Encode returns b's encoded Batch bytes (see README.md's "Canonical
// Batch encoding"): a fixed-width binary layout — 1-byte version,
// 2-byte batchNumber, 4-byte entryCount, followed by each Entry's
// 30-byte RecoveryCode and 32-byte UserKey back to back. These bytes
// contain Recovery Codes and UserKeys in plaintext, so the output is
// confidential material despite being fingerprintable; encryption, if wanted, is an
// entirely separate, later, optional step via the sibling transport
// package, never something Encode itself performs. Encode rejects an
// invalid (including zero-value) Batch with ErrInvalidBatch
// rather than emitting any partial or meaningless bytes.
func (b Batch) Encode() ([]byte, error) {
	if len(b.entries) == 0 {
		return nil, ErrInvalidBatch
	}
	return b.encodedBytes(), nil
}

// --- canonical binary wire schema (see README.md's "Canonical Batch encoding") --

// encodeBatch hand-assembles exactly the encoded byte form documented
// in README.md's "Canonical Batch encoding". It is used both by
// Batch.encodedBytes (already-validated, already-normalized field
// values) and by BatchGenerator.Generate — the same function guarantees every
// producer of encoded Batch bytes agrees on the exact layout.
func encodeBatch(version uint8, batchNumber BatchNumber, entries []Entry) []byte {
	out := make([]byte, headerSize, headerSize+len(entries)*entrySize)
	out[0] = version
	binary.BigEndian.PutUint16(out[1:3], uint16(batchNumber))
	binary.BigEndian.PutUint32(out[3:7], uint32(len(entries)))
	for _, e := range entries {
		out = append(out, e.recoveryCode...)
		out = append(out, e.userKey.Bytes()...)
	}
	return out
}

// --- Fingerprint (see README.md's "Fingerprint") ----------------------------

// fingerprintPrefix is Fingerprint's fixed input ASCII prefix.
const fingerprintPrefix = "fortego:codebook-derivation:v1:fingerprint:"

// computeFingerprint implements the Fingerprint formula exactly as
// documented in README.md's "Fingerprint": a literal ASCII prefix directly
// prepended to encoded (Batch.encodedBytes' output — the same bytes
// Encode returns and DecodeBatch validates), SHA-256, first 100 bits,
// Crockford Base32, grouped 4x5.
// Covering the entire encoded form — entries included — makes Fingerprint
// alone sufficient to detect any change to a Batch's Recovery Codes or
// UserKeys, not just its header fields.
func computeFingerprint(encoded []byte) string {
	input := make([]byte, 0, len(fingerprintPrefix)+len(encoded))
	input = append(input, []byte(fingerprintPrefix)...)
	input = append(input, encoded...)
	digest := sha256.Sum256(input)

	const fingerprintChars = 20 // 100 bits / 5 bits per Crockford char
	var chars [fingerprintChars]byte
	for i := 0; i < fingerprintChars; i++ {
		v := crockford.ReadBits5(digest[:], i*5)
		chars[i] = crockford.EncodeDigit(v)
	}

	var out strings.Builder
	out.Grow(fingerprintChars + 3)
	for i, c := range chars {
		if i > 0 && i%5 == 0 {
			out.WriteByte('-')
		}
		out.WriteByte(c)
	}
	return out.String()
}

// --- BatchGenerator -------------------------------------------------------------

// BatchGenerator binds the two mnemonic roles to one batch number. Its zero
// value is invalid; Generate validates all inputs before deriving anything.
type BatchGenerator struct {
	batchEntropy    BatchEntropy
	recoveryEntropy RecoveryCodeEntropy
	batchNumber     BatchNumber
}

// Format implements fmt.Formatter so that no verb — %v, %+v, %s, %x, %#v or
// any other — ever renders g's batchEntropy or recoveryEntropy bytes. Go's
// default struct formatting recurses into unexported fields regardless of
// their own type's protections (BatchEntropy and RecoveryCodeEntropy each
// have their own redacting Format method, but that method is bypassed when
// the value is only reachable as an unexported field of a struct, like
// BatchGenerator, that itself has no Format method), so without this
// override a bare fmt.Sprintf("%+v", generator) would print both 256-bit
// root secrets directly — from which every BatchKey, Recovery Code, and
// UserKey of every Batch ever derived from that generator can be
// reconstructed.
func (g BatchGenerator) Format(f fmt.State, verb rune) {
	redactedFormat(f, "BatchGenerator")
}

// NewBatchGenerator binds two entropy roles to batchNumber. Validation occurs
// in Generate so construction is always error-free.
func NewBatchGenerator(batchEntropy BatchEntropy, recoveryEntropy RecoveryCodeEntropy, batchNumber BatchNumber) BatchGenerator {
	return BatchGenerator{batchEntropy: batchEntropy, recoveryEntropy: recoveryEntropy, batchNumber: batchNumber}
}

// Generate validates the BatchGenerator and size, derives size Entries, and
// returns one complete, immutable Batch. Any failure returns a zero
// Batch and a non-nil error, never a partial Batch.
func (g BatchGenerator) Generate(size int) (Batch, error) {
	if !g.batchEntropy.initialized {
		return Batch{}, ErrInvalidBatchEntropy
	}
	if !g.recoveryEntropy.initialized {
		return Batch{}, ErrInvalidRecoveryCodeEntropy
	}
	batchNumber := g.batchNumber
	if !batchNumber.valid() {
		return Batch{}, ErrInvalidBatchNumber
	}
	if size < 1 || size > MaxEntriesPerBatch {
		return Batch{}, ErrInvalidBatchSize
	}

	batchKey, err := g.batchEntropy.batchKey(batchNumber)
	if err != nil {
		return Batch{}, err
	}

	entries := make([]Entry, size)
	for i := 0; i < size; i++ {
		idx := EntryIndex(i + 1)

		data, err := g.recoveryEntropy.recoveryCodeData(batchNumber, idx)
		if err != nil {
			return Batch{}, err
		}
		userKeyBytes, err := derive.DeriveUserKey(batchKey, uint16(batchNumber), data)
		if err != nil {
			return Batch{}, err
		}
		userKey, err := NewUserKey(userKeyBytes[:])
		if err != nil {
			return Batch{}, err
		}
		code, err := recoverycode.New(uint16(batchNumber), data, recoverycode.ExtensionV1)
		if err != nil {
			return Batch{}, err
		}

		entries[i] = Entry{index: idx, recoveryCode: code.WireString(), userKey: userKey}
	}

	return Batch{version: derive.DerivationV1, batchNumber: batchNumber, entries: entries}, nil
}

// --- DecodeBatch (see README.md's "Batch handoff and verification") --

// DecodeBatch parses and validates encoded per this package's fixed
// binary Batch layout. It does not establish provenance: callers that
// carry an independently trusted Fingerprint must compare it themselves with
// the returned Batch's Fingerprint. Any invalid input returns a zero
// Batch and ErrInvalidBatch, never a partial Batch.
func DecodeBatch(encoded []byte) (Batch, error) {
	// Step 1: bound checks before any header field is trusted.
	if len(encoded) > maxBatchEncodedBytes {
		return Batch{}, ErrInvalidBatch
	}
	if len(encoded) < headerSize {
		return Batch{}, ErrInvalidBatch
	}

	// Step 2: header fields.
	version := encoded[0]
	if version != derive.DerivationV1 {
		return Batch{}, ErrInvalidBatch
	}
	batchNumber := BatchNumber(binary.BigEndian.Uint16(encoded[1:3]))
	if !batchNumber.valid() {
		return Batch{}, ErrInvalidBatch
	}
	entryCount := binary.BigEndian.Uint32(encoded[3:7])
	if entryCount < 1 || entryCount > MaxEntriesPerBatch {
		return Batch{}, ErrInvalidBatch
	}

	// Step 3: exact length. This fixed-width layout has no whitespace,
	// field-order, or duplicate-field ambiguity the way the module's
	// earlier canonical-JSON encoding did; the only remaining
	// well-formedness question is whether encoded's total length matches
	// exactly what its own header declares, with nothing missing and
	// nothing trailing.
	wantLen := headerSize + int(entryCount)*entrySize
	if len(encoded) != wantLen {
		return Batch{}, ErrInvalidBatch
	}

	// Step 4: entry invariants. entries[i]'s EntryIndex is implicit -- its
	// position, i+1 -- so there is no separate wire field that could ever
	// desynchronize from entry order.
	entries := make([]Entry, entryCount)
	for i := 0; i < int(entryCount); i++ {
		off := headerSize + i*entrySize
		codeStr := string(encoded[off : off+recoverycode.UngroupedLen])
		keyBytes := encoded[off+recoverycode.UngroupedLen : off+entrySize]

		code, err := recoverycode.Parse(codeStr)
		if err != nil {
			return Batch{}, ErrInvalidBatch
		}
		if code.WireString() != codeStr {
			return Batch{}, ErrInvalidBatch
		}
		if code.BatchNumber() != uint16(batchNumber) {
			return Batch{}, ErrInvalidBatch
		}

		userKey, err := NewUserKey(keyBytes)
		if err != nil {
			// Unreachable: keyBytes is always exactly secretSize bytes,
			// sliced at a fixed offset within entrySize.
			return Batch{}, ErrInvalidBatch
		}

		entries[i] = Entry{index: EntryIndex(i + 1), recoveryCode: codeStr, userKey: userKey}
	}

	// Step 5: success.
	return Batch{version: version, batchNumber: batchNumber, entries: entries}, nil
}
