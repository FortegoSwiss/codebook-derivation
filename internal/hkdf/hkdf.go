// Package hkdf implements the domain-separated HKDF-SHA-256 primitive this
// module's derivations build on (see README.md's "Exact HKDF parameters"
// and "Derivation" sections): the fixed domain literal, the
// ctx(role, fields...) salt/info framing (length-prefixed field framing plus
// fixed-width big-endian integer encoding), and the Extract+Expand /
// Expand-only tails every derivation reduces to once its salt/info bytes are
// built.
package hkdf

import (
	"encoding/binary"
	"fmt"

	stdhkdf "crypto/hkdf"
	"crypto/sha256"
)

// Domain is the one fixed domain literal shared by every HKDF salt and info
// field this module derives. It never changes across roles; only the role
// literal and bound fields passed to Ctx change per derivation.
const Domain = "fortego:codebook-derivation:v1"

// AppendEncField appends the canonical, length-prefixed binary encoding of
// b to dst and returns the extended slice:
//
//	enc(b) = uint32-BE(len(b)) ‖ b
//
// This is the one implementation of enc() used throughout this module, so
// every caller building a ctx() framing can never silently diverge from
// another. Every field this module ever passes to AppendEncField is a
// short, fixed-width or literal-ASCII value far below math.MaxUint32, so
// this helper has no overflow guard to keep it a trivial, obviously-correct
// primitive; it never panics for any input reachable from this module's own
// callers.
func AppendEncField(dst, b []byte) []byte {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(b)))
	dst = append(dst, lenBuf[:]...)
	dst = append(dst, b...)
	return dst
}

// U8 encodes v as its single verbatim byte.
func U8(v uint8) []byte {
	return []byte{v}
}

// U16 encodes v as 2 big-endian bytes.
func U16(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}

// U32 encodes v as 4 big-endian bytes.
func U32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

// U64 encodes v as 8 big-endian bytes.
func U64(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

// Ctx builds the canonical HKDF salt/info context bytes shared by every
// derivation in this module:
//
//	ctx(role, fields...) = enc(ascii(Domain)) ‖ enc(ascii(role))
//	                     ‖ enc(fields[0]) ‖ enc(fields[1]) ‖ ...
//
// A role's salt and info always call Ctx with the same role literal (with
// "-salt" appended for the salt) so a copy-paste divergence between the two
// changes both outputs together, never silently drifting apart.
func Ctx(role string, fields ...[]byte) []byte {
	buf := AppendEncField(nil, []byte(Domain))
	buf = AppendEncField(buf, []byte(role))
	for _, f := range fields {
		buf = AppendEncField(buf, f)
	}
	return buf
}

// ExtractExpand runs HKDF-SHA-256 Extract immediately followed by Expand
// for length bytes, using Go's standard-library crypto/hkdf. It is the
// shared Extract+Expand tail every derivation in this module reduces to once
// its salt/info bytes are built.
func ExtractExpand(ikm, salt, info []byte, length int) ([]byte, error) {
	prk, err := stdhkdf.Extract(sha256.New, ikm, salt)
	if err != nil {
		return nil, fmt.Errorf("derivation: HKDF-Extract failed: %w", err)
	}
	return Expand(prk, info, length)
}

// Expand runs HKDF-SHA-256 Expand only, for length bytes, using prk
// directly as the pseudorandom key with no fresh Extract step. This is the
// formula DeriveCodeBookSeed uses (see README.md's "Derivation" section):
// UserKey is already uniformly random HKDF output, so using it directly as
// the PRK is safe.
func Expand(prk, info []byte, length int) ([]byte, error) {
	okm, err := stdhkdf.Expand(sha256.New, prk, string(info), length)
	if err != nil {
		return nil, fmt.Errorf("derivation: HKDF-Expand failed: %w", err)
	}
	return okm, nil
}
