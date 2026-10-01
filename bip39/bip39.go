// Package bip39 implements this module's byte-exact support for English
// 24-word/256-bit-entropy BIP-39 mnemonics: parsing and validating a
// mnemonic sentence into a Mnemonic value, constructing a Mnemonic
// directly from known entropy, reading a Mnemonic's canonical words back
// out, and deriving the standard BIP-39 seed from a Mnemonic.
//
// Supported subset: the English wordlist only, exactly 24 words (256 bits
// of entropy plus an 8-bit checksum) -- no other mnemonic length and no
// other language. Mnemonic.Seed always derives under the fixed, empty
// ("") BIP-39 passphrase: this package deliberately does not expose a
// general passphrase parameter. BIP-39 requires Unicode NFKD
// normalization of both the mnemonic sentence and a non-ASCII passphrase
// before hashing; this package implements neither. Its wordlist is pure
// lowercase ASCII, for which NFKD is always a no-op, so no normalization
// gap exists as long as no passphrase -- and therefore no arbitrary
// Unicode input -- is ever accepted. Adding a passphrase parameter without
// first implementing and testing full NFKD would silently misderive seeds
// for any caller who passed non-ASCII passphrase text.
//
// Mnemonic is an opaque value, mirroring this module's other secret and
// validated-value types (see the root derivation package's UserKey,
// CodeBookSeed, BatchEntropy and RecoveryCodeEntropy): Parse and
// FromEntropy are its only constructors, and both always return an
// already-checksum-valid value -- there is no way to construct a non-zero,
// invalid Mnemonic through this package's API. Its zero value is invalid
// and is distinct from FromEntropy([32]byte{}), which is a valid Mnemonic
// representing real, all-zero entropy. Mnemonic values are immutable after
// construction: every accessor either returns a defensive copy (Words) or
// a value with Go's own by-value copy semantics ([32]byte from Entropy,
// a freshly allocated []byte from Seed).
//
// This package deliberately does not support any language other than
// English, any word count other than 24, or any BIP-39 passphrase other
// than the empty string, and it has no plans to grow into a
// general-purpose, multi-language, multi-length BIP-39 library. Any
// Fortego-specific role semantics for a mnemonic's entropy (e.g. which
// derivation role it supplies) belong in importing packages, not here.
package bip39

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/FortegoSwiss/codebook-derivation/internal/crockford"
)

// wordCount is the only word count this package accepts: the other
// BIP-39-valid counts (12, 15, 18, 21) are rejected.
const wordCount = 24

// entropyBits and checksumBits are the fixed 256/8 split of the 264 bits
// produced by 24 words at 11 bits each.
const (
	entropyBits  = 256
	checksumBits = 8
)

// seedSaltPrefix, seedIterations and seedLength are BIP-39's fixed
// mnemonic-to-seed PBKDF2 parameters (BIP-39's "From mnemonic to seed"
// section): salt = "mnemonic" || passphrase (NFKD-normalized). This
// package always uses passphrase = "" -- see the package doc comment for
// why no passphrase parameter is exposed.
const (
	seedSaltPrefix = "mnemonic"
	seedIterations = 2048
	seedLength     = 64
)

var (
	// ErrWordCount is returned by Parse when words does not contain
	// exactly 24 elements, including a nil or empty slice.
	ErrWordCount = errors.New("bip39: mnemonic must have exactly 24 words")
	// ErrWordChar is returned by Parse when a word, after ASCII-only
	// lowercasing, contains a byte outside a-z.
	ErrWordChar = errors.New("bip39: mnemonic word contains a character outside a-z")
	// ErrWordUnknown is returned by Parse when a word is not present in
	// the fixed 2048-entry BIP-39 English wordlist.
	ErrWordUnknown = errors.New("bip39: mnemonic word is not in the BIP-39 English wordlist")
	// ErrChecksum is returned by Parse when the candidate checksum bits do
	// not match the top 8 bits of SHA-256(candidate entropy).
	ErrChecksum = errors.New("bip39: mnemonic checksum mismatch")
)

// wordlistIndex is a word -> 11-bit BIP-39 index lookup table, built once
// from englishWordlist (wordlist.go).
var wordlistIndex = func() map[string]uint16 {
	m := make(map[string]uint16, len(englishWordlist))
	for i, w := range englishWordlist {
		m[w] = uint16(i)
	}
	return m
}()

// Mnemonic is a validated English 24-word/256-bit-entropy BIP-39
// mnemonic. See the package doc comment for its opaque-value contract.
type Mnemonic struct {
	entropy     [32]byte
	initialized bool
}

// Parse validates words as one 24-word BIP-39 English mnemonic sentence
// and returns the Mnemonic it decodes to. It implements the standard
// BIP-39 decode procedure: exactly 24 words, each trimmed of
// leading/trailing ASCII whitespace, ASCII-lowercased, looked up in the
// fixed BIP-39 English wordlist, and the resulting 264 bits split into 256
// bits of candidate entropy plus an 8-bit checksum verified against
// SHA-256(candidate entropy). words is one already-split word per element
// and is never retained. Parse never panics, on any input including a nil
// or empty slice, wrong element count, or arbitrarily long/non-ASCII
// words.
func Parse(words []string) (Mnemonic, error) {
	var entropy [32]byte

	if len(words) != wordCount {
		return Mnemonic{}, ErrWordCount
	}

	indices := make([]uint16, wordCount)
	for i, raw := range words {
		w := crockford.TrimASCIIWhitespace(raw)

		lower := make([]byte, len(w))
		for j := 0; j < len(w); j++ {
			b := w[j]
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			if b < 'a' || b > 'z' {
				return Mnemonic{}, ErrWordChar
			}
			lower[j] = b
		}

		idx, ok := wordlistIndex[string(lower)]
		if !ok {
			return Mnemonic{}, ErrWordUnknown
		}
		indices[i] = idx
	}

	var bits [wordCount * 11]bool
	for i, idx := range indices {
		for b := 0; b < 11; b++ {
			bits[i*11+b] = (idx>>(10-b))&1 == 1
		}
	}

	for i := 0; i < entropyBits; i++ {
		if bits[i] {
			entropy[i/8] |= 1 << uint(7-(i%8))
		}
	}
	var candidateChecksum byte
	for i := 0; i < checksumBits; i++ {
		if bits[entropyBits+i] {
			candidateChecksum |= 1 << uint(7-i)
		}
	}

	sum := sha256.Sum256(entropy[:])
	if sum[0] != candidateChecksum {
		return Mnemonic{}, ErrChecksum
	}

	return Mnemonic{entropy: entropy, initialized: true}, nil
}

// FromEntropy constructs the Mnemonic representing entropy directly,
// computing its checksum and word indices per the standard BIP-39 encode
// procedure -- the exact inverse of Parse's decode direction. Every
// possible 32-byte value of entropy produces a valid Mnemonic, so
// FromEntropy never fails.
func FromEntropy(entropy [32]byte) Mnemonic {
	return Mnemonic{entropy: entropy, initialized: true}
}

// Words returns m's canonical 24-word sentence: lowercase ASCII wordlist
// entries, in BIP-39 index order. Each call allocates and returns a fresh
// slice; mutating the returned slice never changes m. Words returns nil
// for the zero-value Mnemonic.
func (m Mnemonic) Words() []string {
	if !m.initialized {
		return nil
	}
	return encodeWords(m.entropy)
}

// encodeWords implements the standard BIP-39 encode direction shared by
// Words and Seed: it packs entropy || SHA-256(entropy)[0] (256 + 8 = 264
// bits) into 24 eleven-bit indices, MSB-first, and looks each index up in
// the fixed 2048-entry BIP-39 English wordlist.
func encodeWords(entropy [32]byte) []string {
	sum := sha256.Sum256(entropy[:])

	var bits [wordCount * 11]bool
	for i := 0; i < entropyBits; i++ {
		bits[i] = entropy[i/8]&(1<<uint(7-(i%8))) != 0
	}
	for i := 0; i < checksumBits; i++ {
		bits[entropyBits+i] = sum[0]&(1<<uint(7-i)) != 0
	}

	words := make([]string, wordCount)
	for i := 0; i < wordCount; i++ {
		var idx uint16
		for b := 0; b < 11; b++ {
			idx <<= 1
			if bits[i*11+b] {
				idx |= 1
			}
		}
		words[i] = englishWordlist[idx]
	}
	return words
}

// Entropy returns m's underlying 256-bit entropy. Because [32]byte is a
// Go value type, the returned array is already an independent copy;
// mutating it never changes m. Entropy returns the zero [32]byte for the
// zero-value Mnemonic -- a value indistinguishable, by itself, from
// FromEntropy([32]byte{})'s entropy, so a caller that must tell the two
// apart needs a Mnemonic it knows was validly constructed, not this
// method's return value in isolation.
func (m Mnemonic) Entropy() [32]byte {
	return m.entropy
}

// Seed derives m's standard 64-byte BIP-39 seed:
//
//	Seed = PBKDF2-HMAC-SHA512(password = sentence, salt = "mnemonic", iterations = 2048, dkLen = 64)
//
// where sentence is m.Words() joined by a single ASCII space -- m's
// canonical wordlist form, not any raw text a caller originally passed to
// Parse -- and the BIP-39 passphrase is fixed to the empty string (see the
// package doc comment for why no passphrase parameter is exposed). Seed
// returns nil for the zero-value Mnemonic.
func (m Mnemonic) Seed() []byte {
	if !m.initialized {
		return nil
	}
	return deriveSeed(encodeWords(m.entropy), "")
}

// deriveSeed implements BIP-39's mnemonic-to-seed PBKDF2 formula for an
// arbitrary passphrase. It is unexported and has exactly one non-test
// caller (Seed, which always passes passphrase = ""); its own tests pin it
// directly against the officially published Trezor python-mnemonic
// reference vector under passphrase "TREZOR" (see bip39-seed.v1.json),
// independently of Seed's fixed-empty-passphrase policy, so that policy
// choice and PBKDF2 correctness are checked separately.
func deriveSeed(words []string, passphrase string) []byte {
	sentence := strings.Join(words, " ")
	salt := []byte(seedSaltPrefix + passphrase)
	seed, err := pbkdf2.Key(sha512.New, sentence, salt, seedIterations, seedLength)
	if err != nil {
		// Unreachable: pbkdf2.Key only errors for a nil hash constructor or
		// a non-positive iteration count/key length, none of which this
		// call ever passes. Fail loudly rather than silently return a
		// wrong-length seed if that ever changes.
		panic("bip39: pbkdf2.Key failed with fixed, always-valid parameters: " + err.Error())
	}
	return seed
}

// Format implements fmt.Formatter so that no verb -- %v, %+v, %s, %x, %#v
// or any other -- ever renders m's entropy, including when m is printed
// directly or wrapped in an error. Mnemonic deliberately does not
// implement fmt.Stringer: Format alone controls all fmt output.
func (m Mnemonic) Format(f fmt.State, verb rune) {
	_, _ = io.WriteString(f, "bip39.Mnemonic{REDACTED}")
}
