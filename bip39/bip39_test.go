package bip39

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
)

//go:embed bip39.v1.json
var bip39VectorsJSON []byte

//go:embed bip39-seed.v1.json
var bip39SeedVectorsJSON []byte

func loadBIP39Vectors(t *testing.T) struct {
	Version int `json:"version"`
	Vectors []struct {
		Name       string   `json:"name"`
		Words      []string `json:"words"`
		EntropyHex string   `json:"entropyHex"`
	} `json:"vectors"`
} {
	t.Helper()
	var file struct {
		Version int `json:"version"`
		Vectors []struct {
			Name       string   `json:"name"`
			Words      []string `json:"words"`
			EntropyHex string   `json:"entropyHex"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(bip39VectorsJSON, &file); err != nil {
		t.Fatalf("loading BIP-39 vectors: %v", err)
	}
	return file
}

// batchFixtureWords and batchFixtureEntropy are the batch mnemonic worked
// example: entropy 0x00 * 32.
var batchFixtureWords = strings.Fields(
	"abandon abandon abandon abandon abandon abandon abandon abandon " +
		"abandon abandon abandon abandon abandon abandon abandon abandon " +
		"abandon abandon abandon abandon abandon abandon abandon art")

var batchFixtureEntropy = [32]byte{} // all-zero

// recoveryFixtureWords and recoveryFixtureEntropy are the recovery code
// batch mnemonic worked example: entropy 0x7f * 32.
var recoveryFixtureWords = strings.Fields(
	"legal winner thank year wave sausage worth useful legal winner " +
		"thank year wave sausage worth useful legal winner thank year " +
		"wave sausage worth title")

var recoveryFixtureEntropy = func() [32]byte {
	var e [32]byte
	for i := range e {
		e[i] = 0x7f
	}
	return e
}()

// TestParseFixtures proves both worked examples parse successfully and
// extract exactly their documented entropy, byte-exact.
func TestParseFixtures(t *testing.T) {
	got, err := Parse(batchFixtureWords)
	if err != nil {
		t.Fatalf("Parse(batch fixture) = %v, want success", err)
	}
	if got.Entropy() != batchFixtureEntropy {
		t.Errorf("entropy = %x, want %x", got.Entropy(), batchFixtureEntropy)
	}

	got, err = Parse(recoveryFixtureWords)
	if err != nil {
		t.Fatalf("Parse(recovery fixture) = %v, want success", err)
	}
	if got.Entropy() != recoveryFixtureEntropy {
		t.Errorf("entropy = %x, want %x", got.Entropy(), recoveryFixtureEntropy)
	}
}

// TestParseExtraOfficialVectors adds two more of the well-known public
// BIP-39 English reference vectors (0x80 * 32 and 0xff * 32 entropy) for
// extra confidence beyond the two spec-pinned fixtures.
func TestParseExtraOfficialVectors(t *testing.T) {
	cases := []struct {
		name     string
		words    string
		fillByte byte
	}{
		{
			name: "0x80",
			words: "letter advice cage absurd amount doctor acoustic avoid " +
				"letter advice cage absurd amount doctor acoustic avoid " +
				"letter advice cage absurd amount doctor acoustic bless",
			fillByte: 0x80,
		},
		{
			name: "0xff",
			words: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo " +
				"zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
			fillByte: 0xff,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			words := strings.Fields(tc.words)
			var want [32]byte
			for i := range want {
				want[i] = tc.fillByte
			}

			got, err := Parse(words)
			if err != nil {
				t.Fatalf("Parse = %v, want success", err)
			}
			if got.Entropy() != want {
				t.Errorf("entropy = %x, want %x", got.Entropy(), want)
			}
		})
	}
}

// TestParseWordCount covers the normalization boundary/word-count
// coverage: every BIP-39-valid count other than 24 (12, 15, 18, 21), plus
// 0, 23, 25 and nil, must all be rejected with ErrWordCount, and none may
// panic.
func TestParseWordCount(t *testing.T) {
	base := batchFixtureWords // 24 words, all valid individually

	counts := []int{0, 12, 15, 18, 21, 23, 25}
	for _, n := range counts {
		t.Run(wordCountName(n), func(t *testing.T) {
			var words []string
			if n <= len(base) {
				words = append([]string{}, base[:n]...)
			} else {
				words = append(append([]string{}, base...), base[:n-len(base)]...)
			}
			if _, err := Parse(words); !errors.Is(err, ErrWordCount) {
				t.Errorf("Parse(%d words) error = %v, want ErrWordCount", n, err)
			}
		})
	}
}

func wordCountName(n int) string {
	if n == 0 {
		return "zero"
	}
	return "n" + strconv.Itoa(n)
}

// TestParseNilAndEmptySlice proves nil and empty slices are rejected
// without panicking.
func TestParseNilAndEmptySlice(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panicked: %v", r)
		}
	}()

	if _, err := Parse(nil); !errors.Is(err, ErrWordCount) {
		t.Errorf("Parse(nil) error = %v, want ErrWordCount", err)
	}
	if _, err := Parse([]string{}); !errors.Is(err, ErrWordCount) {
		t.Errorf("Parse([]string{}) error = %v, want ErrWordCount", err)
	}
}

// TestParseUnknownWord proves a word absent from the fixed 2048-entry
// wordlist is rejected with ErrWordUnknown, and does not panic on an
// arbitrarily long non-wordlist token.
func TestParseUnknownWord(t *testing.T) {
	words := append([]string{}, batchFixtureWords...)
	words[5] = "notarealbipwordxyz"
	if _, err := Parse(words); !errors.Is(err, ErrWordUnknown) {
		t.Errorf("error = %v, want ErrWordUnknown", err)
	}

	words[5] = strings.Repeat("x", 10000)
	if _, err := Parse(words); !errors.Is(err, ErrWordUnknown) {
		t.Errorf("very long non-wordlist token: error = %v, want ErrWordUnknown", err)
	}
}

// TestParseNonASCIIOrInvalidChar proves a word containing a byte outside
// a-z after ASCII-only lowercasing -- including any non-ASCII byte, and
// including digits/punctuation -- is rejected with ErrWordChar, and does
// not panic.
func TestParseNonASCIIOrInvalidChar(t *testing.T) {
	cases := []string{"légal", "abandon1", "aban-don", "日本語", "art!"}
	for _, bad := range cases {
		t.Run(bad, func(t *testing.T) {
			words := append([]string{}, batchFixtureWords...)
			words[0] = bad
			if _, err := Parse(words); !errors.Is(err, ErrWordChar) {
				t.Errorf("word %q: error = %v, want ErrWordChar", bad, err)
			}
		})
	}
}

// TestParseCorruptedChecksum proves a checksum mismatch is rejected with
// ErrChecksum, using a last-word substitution that keeps the candidate
// entropy identical (both "art" and its replacement "abandon" have an
// 11-bit index below 256, so the entropy-contributing top 3 bits of the
// last word's index are 0 in both cases) but changes the
// checksum-contributing low 8 bits, so the failure is specifically a
// checksum mismatch, not an unknown word or a different entropy.
func TestParseCorruptedChecksum(t *testing.T) {
	words := append([]string{}, batchFixtureWords...)
	words[23] = "abandon" // was "art"; still a valid wordlist word
	if _, err := Parse(words); !errors.Is(err, ErrChecksum) {
		t.Errorf("error = %v, want ErrChecksum", err)
	}
}

// TestParseMixedCaseNormalization proves ASCII-only lowercasing lets a
// mixed-case variant of a fixture parse identically to the canonical
// lowercase form.
func TestParseMixedCaseNormalization(t *testing.T) {
	mixed := []string{
		"LEGAL", "Winner", "tHANK", "YEAR", "Wave", "SAUSAGE",
		"worth", "USEFUL", "Legal", "WINNER", "thank", "Year",
		"WAVE", "sausage", "WORTH", "Useful", "legal", "WINNER",
		"Thank", "year", "WAVE", "Sausage", "worth", "TITLE",
	}
	got, err := Parse(mixed)
	if err != nil {
		t.Fatalf("mixed-case fixture: error = %v, want success", err)
	}
	if got.Entropy() != recoveryFixtureEntropy {
		t.Errorf("mixed-case fixture entropy = %x, want %x", got.Entropy(), recoveryFixtureEntropy)
	}
}

// TestParseWhitespaceTrimming proves leading/trailing ASCII whitespace on
// individual words is trimmed before validation.
func TestParseWhitespaceTrimming(t *testing.T) {
	padded := append([]string{}, batchFixtureWords...)
	padded[0] = "  abandon\t"
	padded[10] = "\r\nabandon "
	padded[23] = " art\r\n"

	got, err := Parse(padded)
	if err != nil {
		t.Fatalf("whitespace-padded fixture: error = %v, want success", err)
	}
	if got.Entropy() != batchFixtureEntropy {
		t.Errorf("entropy = %x, want %x", got.Entropy(), batchFixtureEntropy)
	}
}

// TestZeroValueMnemonic proves the zero-value Mnemonic behaves like the
// rest of this module's zero-value-invalid secret types: its accessors
// return nil/zero rather than panicking, and it is distinct from
// FromEntropy of real all-zero entropy despite an equal Entropy() value.
func TestZeroValueMnemonic(t *testing.T) {
	var zero Mnemonic
	if got := zero.Words(); got != nil {
		t.Errorf("zero.Words() = %v, want nil", got)
	}
	if got := zero.Seed(); got != nil {
		t.Errorf("zero.Seed() = %v, want nil", got)
	}
	if got := zero.Entropy(); got != ([32]byte{}) {
		t.Errorf("zero.Entropy() = %x, want all-zero", got)
	}

	// FromEntropy([32]byte{}) is a *valid* Mnemonic (the real
	// "abandon...art" mnemonic) despite sharing zero's Entropy() value.
	fromZeroEntropy := FromEntropy([32]byte{})
	if got := fromZeroEntropy.Words(); len(got) != wordCount {
		t.Errorf("FromEntropy([32]byte{}).Words() = %v, want %d words", got, wordCount)
	}
	if got := fromZeroEntropy.Seed(); got == nil {
		t.Error("FromEntropy([32]byte{}).Seed() = nil, want a real seed")
	}
}

// TestWordsDefensiveCopy proves Words returns an independent slice on
// every call: mutating one call's result must never affect another.
func TestWordsDefensiveCopy(t *testing.T) {
	m, err := Parse(batchFixtureWords)
	if err != nil {
		t.Fatal(err)
	}
	a := m.Words()
	b := m.Words()
	a[0] = "mutated"
	if b[0] == "mutated" {
		t.Fatal("Words() results share backing storage")
	}
	if m.Words()[0] == "mutated" {
		t.Fatal("mutating a Words() result changed the Mnemonic's own canonical words")
	}
}

// TestFromEntropyParseRoundTrip proves FromEntropy and Parse are exact
// inverses across a handful of entropy values, including the all-zero and
// all-0xff extremes.
func TestFromEntropyParseRoundTrip(t *testing.T) {
	cases := [][32]byte{
		{},
		func() [32]byte {
			var e [32]byte
			for i := range e {
				e[i] = 0xff
			}
			return e
		}(),
		func() [32]byte {
			var e [32]byte
			for i := range e {
				e[i] = byte(i)
			}
			return e
		}(),
	}
	for _, entropy := range cases {
		words := FromEntropy(entropy).Words()
		if len(words) != wordCount {
			t.Fatalf("FromEntropy(%x).Words() returned %d words, want %d", entropy, len(words), wordCount)
		}
		got, err := Parse(words)
		if err != nil {
			t.Fatalf("Parse(FromEntropy(%x).Words()): unexpected error %v", entropy, err)
		}
		if got.Entropy() != entropy {
			t.Errorf("round trip = %x, want %x", got.Entropy(), entropy)
		}
	}
}

// TestWordlistShape sanity-checks the embedded wordlist itself: exactly
// 2048 unique entries, index 0 == "abandon", used by every worked example
// above.
func TestWordlistShape(t *testing.T) {
	if len(englishWordlist) != 2048 {
		t.Fatalf("len(englishWordlist) = %d, want 2048", len(englishWordlist))
	}
	if englishWordlist[0] != "abandon" {
		t.Errorf("englishWordlist[0] = %q, want %q", englishWordlist[0], "abandon")
	}
	if len(wordlistIndex) != 2048 {
		t.Fatalf("len(wordlistIndex) = %d, want 2048 (duplicate or missing entries)", len(wordlistIndex))
	}
	for i, w := range englishWordlist {
		if got := wordlistIndex[w]; int(got) != i {
			t.Fatalf("wordlistIndex[%q] = %d, want %d", w, got, i)
		}
	}
}

// TestVectorsBip39Entropy pins BIP-39 mnemonic -> raw 256-bit entropy
// extraction through Parse against every checked-in vector in
// bip39.v1.json. Expected values are loaded, never computed here: a
// divergence must fail this test, not be silently accepted.
func TestVectorsBip39Entropy(t *testing.T) {
	f := loadBIP39Vectors(t)
	if f.Version != 1 {
		t.Fatalf("BIP-39 vector version = %d, want 1", f.Version)
	}
	if len(f.Vectors) == 0 {
		t.Fatal("no bip39 vectors loaded")
	}

	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			want, err := hex.DecodeString(v.EntropyHex)
			if err != nil {
				t.Fatalf("decoding entropyHex %q: %v", v.EntropyHex, err)
			}

			got, err := Parse(v.Words)
			if err != nil {
				t.Fatalf("Parse(%s): unexpected error %v", v.Name, err)
			}
			gotEntropy := got.Entropy()
			if !bytesEqual(gotEntropy[:], want) {
				t.Errorf("Parse(%s) entropy = %x, want %x", v.Name, gotEntropy, want)
			}

			// FromEntropy on the same expected entropy must re-encode to
			// exactly the vector's own words: the encode and decode
			// directions must agree, not just each round-trip with itself.
			var wantEntropy [32]byte
			copy(wantEntropy[:], want)
			gotWords := FromEntropy(wantEntropy).Words()
			if len(gotWords) != len(v.Words) {
				t.Fatalf("FromEntropy(%s).Words() has %d words, vector has %d", v.Name, len(gotWords), len(v.Words))
			}
			for i := range gotWords {
				if gotWords[i] != v.Words[i] {
					t.Errorf("FromEntropy(%s).Words()[%d] = %q, want %q", v.Name, i, gotWords[i], v.Words[i])
				}
			}
		})
	}
}

// --- Mnemonic.Seed / deriveSeed (BIP-39 PBKDF2) ---------------------------

type bip39SeedVectorFile struct {
	Version int `json:"version"`
	Vectors []struct {
		Name                    string `json:"name"`
		EntropyHex              string `json:"entropyHex"`
		Mnemonic                string `json:"mnemonic"`
		TrezorPassphraseSeedHex string `json:"trezorPassphraseSeedHex"`
		EmptyPassphraseSeedHex  string `json:"emptyPassphraseSeedHex"`
	} `json:"vectors"`
}

func loadBIP39SeedVectors(t *testing.T) bip39SeedVectorFile {
	t.Helper()
	var f bip39SeedVectorFile
	if err := json.Unmarshal(bip39SeedVectorsJSON, &f); err != nil {
		t.Fatalf("loading bip39-seed vectors: %v", err)
	}
	if f.Version != 1 {
		t.Fatalf("bip39-seed vector: version = %d, want 1", f.Version)
	}
	if len(f.Vectors) == 0 {
		t.Fatal("no bip39-seed vectors loaded")
	}
	return f
}

// TestVectorsSeed pins Mnemonic.Seed -- this package's only public
// seed-derivation entry point, always under the fixed empty passphrase --
// against every checked-in vector's emptyPassphraseSeedHex.
// bip39-seed.v1.json's own description explains that value's provenance:
// self-computed, not independently published, but cross-checked by
// TestDeriveSeedMatchesPublishedTrezorVector below reproducing a genuinely
// published seed with the same code path.
func TestVectorsSeed(t *testing.T) {
	f := loadBIP39SeedVectors(t)
	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			entropyBytes, err := hex.DecodeString(v.EntropyHex)
			if err != nil {
				t.Fatalf("decoding entropyHex: %v", err)
			}
			var entropy [32]byte
			copy(entropy[:], entropyBytes)

			m := FromEntropy(entropy)

			// Cross-check the fixture's own entropyHex/mnemonic pairing
			// against this package's encoder, so a typo in the fixture
			// itself fails loudly here.
			wantWords := strings.Fields(v.Mnemonic)
			gotWords := m.Words()
			if len(gotWords) != len(wantWords) {
				t.Fatalf("test setup: fixture mnemonic has %d words, FromEntropy(entropyHex).Words() has %d", len(wantWords), len(gotWords))
			}
			for i := range gotWords {
				if gotWords[i] != wantWords[i] {
					t.Fatalf("test setup: fixture mnemonic word %d = %q, FromEntropy(entropyHex).Words() = %q", i, wantWords[i], gotWords[i])
				}
			}

			want, err := hex.DecodeString(v.EmptyPassphraseSeedHex)
			if err != nil {
				t.Fatalf("decoding emptyPassphraseSeedHex: %v", err)
			}
			got := m.Seed()
			if !bytesEqual(got, want) {
				t.Errorf("Seed() = %x, want %x", got, want)
			}
		})
	}
}

// TestDeriveSeedMatchesPublishedTrezorVector pins the unexported
// deriveSeed helper -- which Seed calls internally with a fixed empty
// passphrase -- against the genuinely externally published Trezor
// python-mnemonic seed for the SAME mnemonic under passphrase "TREZOR".
// This is the one assertion in this package backed by an independently
// published seed value (see bip39-seed.v1.json's description); it exists
// so the PBKDF2 wiring itself (salt framing, iteration count, key length,
// hash function) is checked against an external source, not only against
// this repository's own computation.
func TestDeriveSeedMatchesPublishedTrezorVector(t *testing.T) {
	f := loadBIP39SeedVectors(t)
	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			words := strings.Fields(v.Mnemonic)
			want, err := hex.DecodeString(v.TrezorPassphraseSeedHex)
			if err != nil {
				t.Fatalf("decoding trezorPassphraseSeedHex: %v", err)
			}
			got := deriveSeed(words, "TREZOR")
			if !bytesEqual(got, want) {
				t.Errorf("deriveSeed(words, \"TREZOR\") = %x, want %x", got, want)
			}
		})
	}
}

// TestSeedEmptyPassphraseDiffersFromNonEmpty proves deriveSeed's
// passphrase actually participates in the derivation (i.e. Seed's fixed
// empty passphrase is not accidentally ignored).
func TestSeedEmptyPassphraseDiffersFromNonEmpty(t *testing.T) {
	m, err := Parse(batchFixtureWords)
	if err != nil {
		t.Fatal(err)
	}
	empty := m.Seed()
	nonEmpty := deriveSeed(m.Words(), "TREZOR")
	if bytesEqual(empty, nonEmpty) {
		t.Error("Seed() (empty passphrase) must differ from deriveSeed(words, \"TREZOR\")")
	}
	if len(empty) != seedLength {
		t.Errorf("len(Seed()) = %d, want %d", len(empty), seedLength)
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
