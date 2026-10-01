// Package transport implements one-time authenticated encryption of
// arbitrary bytes (see README.md's "Transport envelope"): a single fixed
// AES-256-GCM envelope with a fresh key and nonce drawn per Seal call. The
// envelope version byte is bound as additional authenticated data.
//
// This package is fully independent of this module's root package: it does
// not import it, and it does not parse, know about, or reference Batch,
// Entry, BatchNumber, EntryIndex, Fingerprint, or any
// signature concept. It authenticates and encrypts arbitrary bytes; the
// fact that a real caller's plaintext is usually the output of a
// Batch.Encode() call is never visible to this package — it operates on
// []byte only.
package transport

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

const (
	// keySize is the exact, required length in bytes of Key.
	keySize = 32
	// nonceSize is the exact length in bytes of the AES-256-GCM nonce:
	// 96 bits, fresh crypto/rand output per Seal call.
	nonceSize = 12
	// tagSize is the exact length in bytes of the GCM authentication tag
	// that cipher.AEAD.Seal appends at the end of its output.
	tagSize = 16
	// envelopeOverhead is the version, nonce, and authentication-tag width
	// added to every plaintext.
	envelopeOverhead = 1 + nonceSize + tagSize
	// envelopeVersion is this package's own fixed internal suite
	// discriminator — byte 0 of every envelope produced by
	// Seal. It is not root package derivation's Batch version byte,
	// and this package never reads or writes any of that package's fields.
	// A future revision of this package that freezes a different byte
	// layout gets a new envelopeVersion, never a silent reinterpretation of
	// this one's layout.
	envelopeVersion byte = 1
)

const (
	// MaxPlaintextSize is the largest plaintext Seal accepts: 64 MiB.
	// The transport package is bytes-only and deliberately independent of the
	// root package's smaller Batch limit, but still bounds encryption work and
	// the allocation performed by Open.
	MaxPlaintextSize = 64 << 20

	// MinEnvelopeSize is the smallest envelope Open accepts:
	// 1 version byte + 12 nonce bytes + 16 tag bytes, corresponding to a
	// zero-length plaintext.
	MinEnvelopeSize = envelopeOverhead

	// MaxEnvelopeSize is the largest envelope Open accepts.
	MaxEnvelopeSize = MaxPlaintextSize + envelopeOverhead
)

var (
	// ErrRandomSource is returned by Seal if crypto/rand fails to supply
	// enough random bytes for the key or nonce.
	ErrRandomSource = errors.New("transport: failed to read random bytes")

	// ErrInvalidEnvelopeSize is returned by Open when the encoded envelope is
	// outside MinEnvelopeSize..MaxEnvelopeSize. Open checks this before reading
	// envelopeVersion or slicing out the nonce/ciphertext fields.
	ErrInvalidEnvelopeSize = errors.New("transport: envelope size out of bounds")

	// ErrInvalidPlaintextSize is returned by Seal when plaintext is larger
	// than MaxPlaintextSize. Seal checks this before drawing any randomness.
	ErrInvalidPlaintextSize = errors.New("transport: plaintext size out of bounds")

	// ErrUnrecognizedVersion is returned by Open when envelope byte 0 is
	// not the one envelopeVersion this package defines. Open checks this
	// before touching bytes 1 onward.
	ErrUnrecognizedVersion = errors.New("transport: unrecognized envelope version")

	// ErrAuthenticationFailed is returned by Open whenever AEAD
	// authentication does not succeed — a wrong key, or any tampering
	// with the nonce, ciphertext, or tag. AES-256-GCM makes no
	// distinction between "wrong key" and "tampered ciphertext"; neither
	// does this error, and Open never returns partial plaintext alongside
	// it.
	ErrAuthenticationFailed = errors.New("transport: authentication failed")

	// ErrInvalidKeySize is returned by NewKey when the input is not
	// exactly 32 bytes long.
	ErrInvalidKeySize = errors.New("transport: Key must be exactly 32 bytes")

	// ErrInvalidKey is returned when Open or an internal sealing operation
	// receives a zero-value Key rather than one returned by NewKey or Seal.
	ErrInvalidKey = errors.New("transport: Key is invalid or zero-value")
)

// Key is the 32-byte AES-256-GCM key used by Seal and Open. It
// is a secret type: no exported field, no implicit String/Text/JSON
// representation, and its bytes are obtainable only via the explicit,
// copying Bytes method. A Key is never embedded inside an envelope
// produced by Seal, never logged, and never included in any error value. Its
// zero value is invalid; NewKey still accepts an explicit 32-byte all-zero key.
type Key struct {
	b           [keySize]byte
	initialized bool
}

// NewKey constructs a Key from exactly 32 explicit, caller-supplied bytes.
// Any other length is rejected with ErrInvalidKeySize; NewKey
// never panics. b is not retained — NewKey copies it, so mutating b after
// the call never changes the returned Key.
func NewKey(b []byte) (Key, error) {
	if len(b) != keySize {
		return Key{}, ErrInvalidKeySize
	}
	var k Key
	copy(k.b[:], b)
	k.initialized = true
	return k, nil
}

// Bytes returns a defensive copy of k's 32 key bytes. Mutating the returned
// slice never changes k. It returns nil for a zero-value Key.
func (k Key) Bytes() []byte {
	if !k.initialized {
		return nil
	}
	out := make([]byte, keySize)
	copy(out, k.b[:])
	return out
}

// Format implements fmt.Formatter so that no verb — %v, %+v, %s, %x, %#v or
// any other — ever renders k's key bytes, including when k is printed
// directly or wrapped in an error. Key deliberately does not implement
// fmt.Stringer: Format alone controls all fmt output.
func (k Key) Format(f fmt.State, verb rune) {
	redactedFormat(f, "Key")
}

// redactedFormat writes a fixed, content-free placeholder for typeName to
// f, regardless of verb or flags. It is the single implementation behind
// every secret type's Format method in this package. It intentionally does
// not import the root package's own redactedFormat helper (keys.go)
// — this package must not import the root package at all — see README.md's
// note that this package is independent of Batch/Entry/Fingerprint —
// so the small helper is reimplemented locally instead.
func redactedFormat(f fmt.State, typeName string) {
	_, _ = io.WriteString(f, "transport.")
	_, _ = io.WriteString(f, typeName)
	_, _ = io.WriteString(f, "{REDACTED}")
}

// Seal encrypts plaintext under a fresh, randomly generated Key and a
// fresh, randomly generated 12-byte nonce (see README.md's "Transport
// envelope"), returning the encoded envelope and the key separately: the
// key is never embedded inside encoded — the envelope's framing has no key
// field — never logged, and never retained by this package beyond the
// call. Handing key to whatever consumes it later — typically a separate
// channel from encoded — is entirely the caller's responsibility.
//
// Every Seal call draws an independent key and an independent nonce — neither is ever derived from
// the plaintext or reused across calls — so two calls over byte-identical
// plaintext produce different key, different nonce, and therefore
// different encoded.
//
// AES-256-GCM's additional authenticated data (AAD) is the single encoded
// envelopeVersion byte. This binds the ciphertext to the exact envelope
// interpretation while keeping the package independent of any plaintext
// schema. Whatever authenticity the caller's plaintext itself needs is that
// plaintext's own concern, entirely orthogonal to this package's AEAD
// authentication.
func Seal(plaintext []byte) (encoded []byte, key Key, err error) {
	if len(plaintext) > MaxPlaintextSize {
		return nil, Key{}, ErrInvalidPlaintextSize
	}

	var keyBytes [keySize]byte
	if _, err := io.ReadFull(rand.Reader, keyBytes[:]); err != nil {
		return nil, Key{}, fmt.Errorf("%w: %v", ErrRandomSource, err)
	}
	key, err = NewKey(keyBytes[:])
	if err != nil {
		// Unreachable: keyBytes is always exactly keySize bytes.
		return nil, Key{}, err
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, Key{}, fmt.Errorf("%w: %v", ErrRandomSource, err)
	}

	encoded, err = sealEnvelope(key, nonce, plaintext)
	if err != nil {
		return nil, Key{}, err
	}
	return encoded, key, nil
}

// sealEnvelope performs the core AES-256-GCM encryption and envelope
// framing step (see README.md's "Transport envelope") for an explicit key and
// nonce. It is factored out from Seal so that package tests can reproduce
// the documented fixed fixture vectors directly, without needing
// crypto/rand indirection — Seal itself always draws fresh randomness and
// cannot be used to reproduce a deterministic worked example.
//
// For a correctly sized key and nonce, AES-256-GCM-Seal over a
// well-formed, bounded-size plaintext is defined to succeed; the error
// return exists only to surface aes/cipher construction
// failures, which cannot occur for the fixed 32-byte key and 12-byte nonce
// sizes this package always supplies.
func sealEnvelope(key Key, nonce, plaintext []byte) ([]byte, error) {
	if !key.initialized {
		return nil, ErrInvalidKey
	}
	if len(plaintext) > MaxPlaintextSize {
		return nil, ErrInvalidPlaintextSize
	}

	block, err := aes.NewCipher(key.b[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	aad := []byte{envelopeVersion}
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)

	envelope := make([]byte, 0, 1+nonceSize+len(ciphertext))
	envelope = append(envelope, envelopeVersion)
	envelope = append(envelope, nonce...)
	envelope = append(envelope, ciphertext...)
	return envelope, nil
}

// Open authenticates and decrypts encoded, an envelope previously produced
// by Seal, under key. It returns plaintext only on complete
// success — never partial or unauthenticated plaintext alongside an error.
//
// Open rejects encoded outside MinEnvelopeSize..MaxEnvelopeSize before reading
// any byte of encoded as a structured field. It then rejects any envelopeVersion other than 1 with
// ErrUnrecognizedVersion, before touching the nonce or ciphertext fields
// at all. Only after both checks pass does Open call the AEAD primitive; a
// wrong key or any tampering with the nonce, ciphertext, tag, or a recognized
// version byte is a hard rejection. An unrecognized version is rejected
// structurally before GCM authentication; the recognized version byte is
// additionally authenticated as AAD.
//
// Open never inspects the decrypted plaintext for any structure — it has
// no knowledge of any schema a caller's plaintext might contain.
// Establishing that decrypted bytes mean anything in particular is
// entirely the caller's job, performed as a separate step after Open
// succeeds: Open's success proves only that ciphertext was produced by
// Seal under key, nothing about what the plaintext means.
func Open(encoded []byte, key Key) ([]byte, error) {
	if !key.initialized {
		return nil, ErrInvalidKey
	}

	if len(encoded) < MinEnvelopeSize || len(encoded) > MaxEnvelopeSize {
		return nil, ErrInvalidEnvelopeSize
	}

	if encoded[0] != envelopeVersion {
		return nil, ErrUnrecognizedVersion
	}

	nonce := encoded[1 : 1+nonceSize]
	ciphertext := encoded[1+nonceSize:]
	if len(ciphertext) < tagSize {
		// Already implied by the MinEnvelopeSize check above; restated
		// here as this step's own direct precondition on the slice it is
		// about to hand to the AEAD primitive.
		return nil, ErrAuthenticationFailed
	}

	block, err := aes.NewCipher(key.b[:])
	if err != nil {
		return nil, fmt.Errorf("transport: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("transport: %w", err)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, encoded[:1])
	if err != nil {
		return nil, ErrAuthenticationFailed
	}
	return plaintext, nil
}
