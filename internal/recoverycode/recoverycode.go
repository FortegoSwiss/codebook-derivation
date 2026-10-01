// Package recoverycode implements this module's Recovery Code wire value
// (see README.md's "The Recovery Code" section): BatchNumber(10 bits) ‖
// RecoveryCodeData(128 bits) ‖ Extension(2 bits) ‖ CRC-10(10 bits), packed
// MSB-first as one contiguous 150-bit bitstream and presented as 30
// Crockford Base32 characters (optionally grouped 6x5 with literal
// hyphens). It depends on internal/crockford for the alphabet/alias rules,
// but — unlike root package derivation, which it must not import (derivation
// imports this package; the reverse would be a cycle) — it operates on a
// plain uint16 batchNumber and a plain [16]byte data value rather than root's
// own BatchNumber/RecoveryCodeData types, and returns its own sentinel
// errors rather than reaching into root's.
package recoverycode

import (
	"errors"

	"github.com/FortegoSwiss/codebook-derivation/internal/crockford"
)

// DataSize is the exact required length, in bytes, of a Code's data field
// (see README.md's "The Recovery Code" section).
const DataSize = 16

const (
	// protectedBits is the CRC-10-protected field width:
	// BatchNumber(10) ‖ RecoveryCodeData(128) ‖ Extension(2).
	protectedBits = 10 + 8*DataSize + 2 // 140
	// crcBits is the CRC field width.
	crcBits = 10
	// totalBits is Code's total wire width.
	totalBits = protectedBits + crcBits // 150
	// crockfordChars is the ungrouped Crockford presentation length: 150
	// bits is exactly divisible by 5 bits/char, so this encoding has no
	// padding bits to account for.
	crockfordChars = totalBits / 5 // 30
	// GroupedLen is the canonical grouped presentation length: 30 payload
	// characters plus 5 literal hyphen separators (6 groups of 5). Parse
	// accepts this form as input; nothing in the v1 public API produces it
	// as output (the Batch wire schema embeds only the ungrouped
	// form).
	GroupedLen = crockfordChars + 5 // 35
)

// UngroupedLen is the length of Code.WireString()'s output: 30
// Crockford characters, no hyphens.
const UngroupedLen = crockfordChars

// minBatchNumber/maxBatchNumber mirror root's BatchNumber domain
// (1..1023). This package cannot call root's BatchNumber.valid() without
// importing package derivation, which would be an import cycle, so the two
// magic numbers are intentionally duplicated here -- see package doc.
const (
	minBatchNumber = 1
	maxBatchNumber = 1023
)

func validBatchNumber(v uint16) bool {
	return v >= minBatchNumber && v <= maxBatchNumber
}

// ExtensionV1 is the only Recovery Code extension v1 accepts; 1..3 are
// reserved for a future wire-format extension that does not yet exist.
const ExtensionV1 uint8 = 0

var (
	// ErrInvalidBatchNumber is returned by New when batchNumber is outside
	// 1..1023. Its message text matches root's own ErrInvalidBatchNumber
	// (keys.go) exactly, but it is a distinct error value.
	ErrInvalidBatchNumber = errors.New("derivation: BatchNumber must be in 1..1023")
	// ErrLength is returned by Parse when the trimmed input is neither
	// the 35-character grouped form nor the 30-character ungrouped form.
	ErrLength = errors.New("derivation: RecoveryCode has invalid length")
	// ErrHyphen is returned by Parse when a 35-character input has a
	// hyphen in a position other than the 5 canonical group-separator
	// positions, or is missing one there.
	ErrHyphen = errors.New("derivation: RecoveryCode has a hyphen in an invalid position")
	// ErrChar is returned by Parse when a payload character, after
	// uppercasing and Crockford alias substitution, is not one of the 32
	// canonical Crockford symbols (this includes literal U).
	ErrChar = errors.New("derivation: RecoveryCode contains an invalid character")
	// ErrCRC is returned by Parse when the decoded CRC-10 does not match
	// the CRC-10 recomputed over the first 140 protected bits.
	ErrCRC = errors.New("derivation: RecoveryCode CRC mismatch")
	// ErrExtension is returned by New or Parse when the Extension field is
	// not 0b00 — for Parse, checked only after the
	// CRC-10 has already been confirmed valid, so a corrupted Extension
	// bit is caught by the CRC first.
	ErrExtension = errors.New("derivation: RecoveryCode has an unsupported Extension value")
)

// Code is the 150-bit wire value BatchNumber(10 bits) ‖ RecoveryCodeData(128
// bits) ‖ Extension(2 bits) ‖ CRC(10 bits) (see README.md's "The Recovery
// Code" section), MSB-first as one contiguous bitstream — its sub-fields are not
// byte-aligned (140 protected bits is not a multiple of 8, and 150 total
// bits is not a multiple of 8 either, though it is a multiple of 5, which
// is what makes the 30-character Crockford encoding exact with no padding
// bits).
//
// Code has no public constructor besides New and Parse; both always
// produce a fully-formed value (New validates its inputs, Parse only
// returns successfully after CRC-10 verification), so unlike this module's
// other zero-value-invalid types, Code needs no separate validity flag —
// its zero value (batchNumber 0, an out-of-domain BatchNumber) is
// simply never produced by either constructor, and every operation on Code
// works from its own fields directly rather than consulting one.
type Code struct {
	batchNumber uint16
	data        [DataSize]byte
	ext         uint8
}

// BatchNumber returns c's BatchNumber field.
func (c Code) BatchNumber() uint16 { return c.batchNumber }

// Data returns c's 16-byte RecoveryCodeData field.
func (c Code) Data() [DataSize]byte { return c.data }

// Extension returns c's Extension field: reserved, always 0 in v1. Exported
// so package derivation's DecodeRecoveryCode (see README.md's "The Recovery
// Code" section) can expose it without this package widening any other part
// of its surface.
func (c Code) Extension() uint8 { return c.ext }

// New packs batchNumber, data and ext into a validly-constructed Code: it
// computes the CRC-10 over the 140-bit protected field. ext must currently
// be 0. New never panics.
func New(batchNumber uint16, data [DataSize]byte, ext uint8) (Code, error) {
	if !validBatchNumber(batchNumber) {
		return Code{}, ErrInvalidBatchNumber
	}
	if ext != ExtensionV1 {
		return Code{}, ErrExtension
	}
	return Code{batchNumber: batchNumber, data: data, ext: ext}, nil
}

// WireString returns c's canonical Batch wire-schema presentation:
// the 30-character ungrouped Crockford Base32 form, uppercase,
// already CRC-valid. This is the exact 30-byte string embedded in a
// Batch's encoded entry bytes and the exact string Entry.RecoveryCode
// returns — there is no separate Recovery-Code output/second derivation
// path.
func (c Code) WireString() string {
	full := c.pack()
	chars := encodeChars(full)
	return string(chars[:])
}

// pack returns the 150-bit wire encoding of c (BatchNumber ‖ RecoveryCodeData ‖
// Extension ‖ CRC-10), MSB-first, packed into 19 bytes with the final 2 bits
// zero-padded (150 is not a multiple of 8). The CRC-10 is computed here over
// the first 140 bits, exactly as documented in README.md's "The Recovery Code" section.
func (c Code) pack() []byte {
	var w bitWriter
	w.writeBits(uint32(c.batchNumber), 10)
	for _, b := range c.data {
		w.writeBits(uint32(b), 8)
	}
	w.writeBits(uint32(c.ext), 2)

	protected := append([]byte(nil), w.buf...)
	crc := crc10ATM(protected, protectedBits)

	w.writeBits(uint32(crc), crcBits)
	return w.buf
}

// PackForTest packs batchNumber, data and ext into a wire string exactly as
// pack()/WireString() do, but without New's business-rule rejection of
// ext != 0. It exists only so tests (in this package and in package
// derivation, which cannot reach this package's unexported bit-packing
// helpers directly) can hand-construct a CRC-valid-but-semantically-invalid
// RecoveryCode wire string, proving a caller-facing rejection happens only
// after CRC validation has already succeeded. It is never
// called by any non-test code path and performs no batchNumber validation.
func PackForTest(batchNumber uint16, data [DataSize]byte, ext uint8) string {
	c := Code{batchNumber: batchNumber, data: data, ext: ext}
	chars := encodeChars(c.pack())
	return string(chars[:])
}

// Parse parses s as a Code, accepting either the 35-character
// grouped form or the 30-character ungrouped form. It trims outer ASCII
// whitespace only, uppercases, applies the Crockford O/I/L aliases and
// rejects U and any character outside 0-9A-Z after aliasing. After decoding
// to 150 bits, the CRC-10 is recomputed over the first 140 bits and
// compared to the last 10; a mismatch is a hard rejection. Extension values
// other than 0 are rejected only after the CRC-10 has already been
// confirmed valid. A decoded BatchNumber outside 1..1023 is likewise rejected
// only after the CRC-10 check.
//
// Parse never panics, on any input string, including empty, non-ASCII, or
// arbitrarily long input.
func Parse(s string) (Code, error) {
	// Step 1: trim leading/trailing ASCII whitespace only.
	s = crockford.TrimASCIIWhitespace(s)

	// Step 2: accept the 35-character grouped form or the 30-character
	// ungrouped form; reject any other length or misplaced hyphen.
	payload, err := codePayload(s)
	if err != nil {
		return Code{}, err
	}

	// Step 3 + 4: uppercase, then apply Crockford aliases and validate every
	// payload character; U and any non-Crockford character are rejected.
	var w bitWriter
	for i := 0; i < crockfordChars; i++ {
		v, ok := crockford.DecodeChar(payload[i])
		if !ok {
			return Code{}, ErrChar
		}
		w.writeBits(uint32(v), 5)
	}
	full := w.buf // 150 bits packed into 19 bytes (2 trailing padding bits, unused).

	// Recompute the CRC-10 over the first 140 bits and compare to the last
	// 10 before interpreting any field's semantic value.
	gotCRC := uint16(readBitsMSB(full, protectedBits, crcBits))
	wantCRC := crc10ATM(full, protectedBits)
	if gotCRC != wantCRC {
		return Code{}, ErrCRC
	}

	ext := uint8(readBitsMSB(full, 10+8*DataSize, 2))
	if ext != ExtensionV1 {
		return Code{}, ErrExtension
	}

	batchNumber := uint16(readBitsMSB(full, 0, 10))
	if !validBatchNumber(batchNumber) {
		return Code{}, ErrInvalidBatchNumber
	}

	var data [DataSize]byte
	for i := 0; i < DataSize; i++ {
		data[i] = byte(readBitsMSB(full, 10+i*8, 8))
	}

	return Code{batchNumber: batchNumber, data: data, ext: ext}, nil
}

// codePayload validates s's length and hyphen positions and
// returns its 30-character payload with any group hyphens removed. It
// never panics.
func codePayload(s string) (string, error) {
	switch len(s) {
	case crockfordChars:
		for i := 0; i < len(s); i++ {
			if s[i] == '-' {
				return "", ErrHyphen
			}
		}
		return s, nil
	case GroupedLen:
		buf := make([]byte, 0, crockfordChars)
		hi := 0
		for i := 0; i < len(s); i++ {
			if hi < len(crockford.HyphenPositions) && i == crockford.HyphenPositions[hi] {
				if s[i] != '-' {
					return "", ErrHyphen
				}
				hi++
				continue
			}
			if s[i] == '-' {
				return "", ErrHyphen
			}
			buf = append(buf, s[i])
		}
		return string(buf), nil
	default:
		return "", ErrLength
	}
}

// encodeChars reads full's 150 bits as 30 consecutive 5-bit, MSB-first
// groups and Crockford-encodes each. full must be at least
// 19 bytes (150 bits); it is only ever called on Code.pack's own output.
func encodeChars(full []byte) [crockfordChars]byte {
	var chars [crockfordChars]byte
	for i := 0; i < crockfordChars; i++ {
		v := readBitsMSB(full, i*5, 5)
		chars[i] = crockford.EncodeDigit(uint8(v))
	}
	return chars
}

// bitWriter is a minimal MSB-first bit writer used only for Code's 150-bit
// (non-byte-aligned) packing and parsing. It grows its backing buffer
// lazily, one byte at a time, as bits are written.
type bitWriter struct {
	buf    []byte
	bitLen int
}

// writeBits appends the low n bits of v to w, MSB-first. n must be in
// 0..32; callers in this file only ever pass small, statically known n.
func (w *bitWriter) writeBits(v uint32, n int) {
	for i := n - 1; i >= 0; i-- {
		byteIdx := w.bitLen / 8
		for len(w.buf) <= byteIdx {
			w.buf = append(w.buf, 0)
		}
		if (v>>uint(i))&1 == 1 {
			w.buf[byteIdx] |= 1 << uint(7-(w.bitLen%8))
		}
		w.bitLen++
	}
}

// readBitsMSB reads n consecutive bits from buf starting at bitOffset,
// MSB-first, returning them right-aligned in the low n bits of the result.
// The caller is responsible for ensuring buf is long enough; it is used
// only with statically known-safe offsets in this file. n must be in 0..32.
func readBitsMSB(buf []byte, bitOffset, n int) uint32 {
	var v uint32
	for i := 0; i < n; i++ {
		bit := bitOffset + i
		byteIdx := bit / 8
		bitIdx := 7 - (bit % 8)
		b := (buf[byteIdx] >> uint(bitIdx)) & 1
		v = (v << 1) | uint32(b)
	}
	return v
}

// CRC-10/ATM parameters (see README.md's "The Recovery Code" section, normative — RevEng
// "Catalogue of parametrised CRC algorithms"): polynomial 0x233, initial
// value 0x000, RefIn = RefOut = false (MSB-first, unreflected),
// XorOut = 0x000.
const (
	crc10ATMPoly = 0x233
	crc10ATMMask = 0x3FF // 10-bit register
)

// crc10ATM computes the CRC-10/ATM checksum of the first nBits
// bits of data, MSB-first, using the bit-serial algorithm documented
// precisely in README.md's "The Recovery Code" section.
//
// data is read MSB-first, byte 0's most significant bit first; nBits may be
// less than len(data)*8 (Code's own use always packs data into a
// byte-padded buffer with trailing padding bits beyond nBits that must not
// be read). The caller is responsible for ensuring data is at least
// ceil(nBits/8) bytes long; crc10ATM never panics for any nBits <=
// len(data)*8.
func crc10ATM(data []byte, nBits int) uint16 {
	var crc uint16
	for i := 0; i < nBits; i++ {
		byteIdx := i / 8
		bitIdx := 7 - (i % 8)
		bit := (data[byteIdx] >> uint(bitIdx)) & 1

		topBit := (crc >> 9) & 1
		crc = (crc << 1) & crc10ATMMask
		if topBit^uint16(bit) == 1 {
			crc ^= crc10ATMPoly
		}
	}
	return crc
}
