package derivation

import (
	"bytes"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"testing"
)

//go:embed codebook-seed.v1.json
var codeBookSeedVectorsJSON []byte

type codeBookSeedVectorFile struct {
	Version int `json:"version"`
	Vectors []struct {
		Name            string `json:"name"`
		UserKeyHex      string `json:"userKeyHex"`
		Index           string `json:"index"`
		CodeBookSeedHex string `json:"codeBookSeedHex"`
	} `json:"vectors"`
}

func loadCodeBookSeedVectors(t *testing.T) codeBookSeedVectorFile {
	t.Helper()
	var f codeBookSeedVectorFile
	if err := json.Unmarshal(codeBookSeedVectorsJSON, &f); err != nil {
		t.Fatalf("loading CodeBook seed vectors: %v", err)
	}
	return f
}

// mustHex and bytesEqual are small shared test helpers used across this
// package's test files (batch_test.go, batch_vectors_test.go,
// mnemonic_test.go, and this file).

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decoding hex %q: %v", s, err)
	}
	return b
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

// --- CodeBookSeed secret-type shape ---------------------------------------
//
// CodeBookSeed's type shape (32 opaque bytes, defensive-copy Bytes, redacted
// Format); these tests exercise the
// NewCodeBookSeed/Bytes/Format guarantees that used to live in hkdf_test.go
// before DeriveCodeBookSeed's HKDF-Expand-only formula moved onto
// internal/hkdf (keys.go).

func TestCodeBookSeedLengthBoundaries(t *testing.T) {
	for _, n := range []int{0, 1, 16, 31, 33, 64, 1000} {
		if _, err := NewCodeBookSeed(make([]byte, n)); err != ErrInvalidCodeBookSeedSize {
			t.Errorf("NewCodeBookSeed(len %d): err = %v, want %v", n, err, ErrInvalidCodeBookSeedSize)
		}
	}

	b := make([]byte, secretSize)
	for i := range b {
		b[i] = byte(i)
	}
	s, err := NewCodeBookSeed(b)
	if err != nil {
		t.Fatalf("NewCodeBookSeed(32 bytes): unexpected error %v", err)
	}
	if got := s.Bytes(); !bytesEqual(got, b) {
		t.Errorf("Bytes() = %v, want %v", got, b)
	}
}

func TestCodeBookSeedDefensiveCopy(t *testing.T) {
	orig := make([]byte, secretSize)
	for i := range orig {
		orig[i] = byte(i)
	}
	input := append([]byte(nil), orig...)

	s, err := NewCodeBookSeed(input)
	if err != nil {
		t.Fatal(err)
	}
	for i := range input {
		input[i] ^= 0xFF
	}
	if got := s.Bytes(); !bytesEqual(got, orig) {
		t.Errorf("mutating input after construction changed the value: got %v, want %v", got, orig)
	}

	b1 := s.Bytes()
	for i := range b1 {
		b1[i] ^= 0xFF
	}
	b2 := s.Bytes()
	if !bytesEqual(b2, orig) {
		t.Errorf("mutating a returned slice changed internal state: got %v, want %v", b2, orig)
	}
}

func TestCodeBookSeedNeverFormatsSecretBytes(t *testing.T) {
	const secretByte = 0xCD
	real := make([]byte, secretSize)
	for i := range real {
		real[i] = secretByte
	}
	s, err := NewCodeBookSeed(real)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := any(s).(fmt.Stringer); ok {
		t.Error("CodeBookSeed must not implement fmt.Stringer")
	}

	const want = "derivation.CodeBookSeed{REDACTED}"
	for _, verb := range []string{"%v", "%+v", "%s", "%#v", "%x", "%X", "%q", "%d"} {
		if got := fmt.Sprintf(verb, s); got != want {
			t.Errorf("Sprintf(%q, s) = %q, want %q", verb, got, want)
		}
	}
	if got := fmt.Sprintf("wrapped: %v", s); !strings.HasSuffix(got, want) {
		t.Errorf("error wrapping leaked: %q", got)
	}
}

// --- DeriveCodeBookSeed ----------------------------------------------------

// codeBookSeedFixtureUserKey is the worked example's own UserKey output
// (DerivationV1=1, BatchNumber=1, Extension=0), reused verbatim as
// DeriveCodeBookSeed's input, exactly as internal/derive/derive_test.go's
// TestVectorsDeriveUserKey reuses the same worked example's inputs.
func codeBookSeedFixtureUserKey(t *testing.T) UserKey {
	t.Helper()
	k, err := NewUserKey(mustHex(t, "42103e59c04a69a73ee5c9304c8db91ee030e38c9e74895cec8836af900bcf43"))
	if err != nil {
		t.Fatalf("test setup: NewUserKey: %v", err)
	}
	return k
}

// TestVectorsDeriveCodeBookSeed pins DeriveCodeBookSeed against
// every checked-in vector in codebook-seed.v1.json -- including
// CodeBookIndex's 2^64-1 boundary, encoded as a decimal-ASCII JSON string
// rather than a JSON number. Expected values are loaded, never
// computed here: a divergence must fail this test, not be silently
// accepted.
func TestVectorsDeriveCodeBookSeed(t *testing.T) {
	f := loadCodeBookSeedVectors(t)
	if f.Version != 1 {
		t.Fatalf("CodeBook seed vector: version = %d, want 1", f.Version)
	}
	if len(f.Vectors) == 0 {
		t.Fatal("no codeBookSeed vectors loaded")
	}

	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			key, err := NewUserKey(mustHex(t, v.UserKeyHex))
			if err != nil {
				t.Fatalf("NewUserKey: %v", err)
			}
			index, err := strconv.ParseUint(v.Index, 10, 64)
			if err != nil {
				t.Fatalf("parsing index %q: %v", v.Index, err)
			}

			got, err := DeriveCodeBookSeed(key, CodeBookIndex(index))
			if err != nil {
				t.Fatalf("index=%s: DeriveCodeBookSeed: unexpected error %v", v.Index, err)
			}
			want := mustHex(t, v.CodeBookSeedHex)
			if gotBytes := got.Bytes(); !bytesEqual(gotBytes, want) {
				t.Errorf("index=%s: DeriveCodeBookSeed = %x, want %x", v.Index, gotBytes, want)
			}
		})
	}
}

// TestDeriveCodeBookSeedDeterminism confirms repeated calls with identical
// inputs always produce the identical CodeBookSeed.
func TestDeriveCodeBookSeedDeterminism(t *testing.T) {
	key := codeBookSeedFixtureUserKey(t)
	idx := CodeBookIndex(42)

	s1, err := DeriveCodeBookSeed(key, idx)
	if err != nil {
		t.Fatalf("DeriveCodeBookSeed: unexpected error %v", err)
	}
	for i := 0; i < 5; i++ {
		s2, err := DeriveCodeBookSeed(key, idx)
		if err != nil {
			t.Fatalf("DeriveCodeBookSeed (repeat %d): unexpected error %v", i, err)
		}
		if !bytesEqual(s1.Bytes(), s2.Bytes()) {
			t.Fatalf("DeriveCodeBookSeed is not deterministic: call 1 = %x, call %d = %x", s1.Bytes(), i, s2.Bytes())
		}
	}
}

// TestDeriveCodeBookSeedContextSeparation confirms changing only the
// UserKey, or only the CodeBookIndex, changes the derived CodeBookSeed.
func TestDeriveCodeBookSeedContextSeparation(t *testing.T) {
	keyA := codeBookSeedFixtureUserKey(t)
	keyBBytes := keyA.Bytes()
	keyBBytes[0] ^= 0xFF
	keyB, err := NewUserKey(keyBBytes)
	if err != nil {
		t.Fatalf("test setup: NewUserKey: %v", err)
	}

	base, err := DeriveCodeBookSeed(keyA, CodeBookIndex(1))
	if err != nil {
		t.Fatalf("DeriveCodeBookSeed: unexpected error %v", err)
	}

	byKey, err := DeriveCodeBookSeed(keyB, CodeBookIndex(1))
	if err != nil {
		t.Fatalf("DeriveCodeBookSeed: unexpected error %v", err)
	}
	if bytesEqual(base.Bytes(), byKey.Bytes()) {
		t.Error("DeriveCodeBookSeed ignored UserKey: different keys produced the same CodeBookSeed")
	}

	byIndex, err := DeriveCodeBookSeed(keyA, CodeBookIndex(2))
	if err != nil {
		t.Fatalf("DeriveCodeBookSeed: unexpected error %v", err)
	}
	if bytesEqual(base.Bytes(), byIndex.Bytes()) {
		t.Error("DeriveCodeBookSeed ignored CodeBookIndex: different indexes produced the same CodeBookSeed")
	}
}

// TestDeriveCodeBookSeedIndexBoundaries confirms CodeBookIndex's exact
// domain boundaries: 0 rejected, 1 accepted, math.MaxUint64 accepted, and
// that the two extremes do not collide.
func TestDeriveCodeBookSeedIndexBoundaries(t *testing.T) {
	key := codeBookSeedFixtureUserKey(t)

	if _, err := DeriveCodeBookSeed(key, CodeBookIndex(0)); err != ErrInvalidCodeBookIndex {
		t.Errorf("DeriveCodeBookSeed(index 0): err = %v, want %v", err, ErrInvalidCodeBookIndex)
	}

	one, err := DeriveCodeBookSeed(key, CodeBookIndex(1))
	if err != nil {
		t.Fatalf("DeriveCodeBookSeed(index 1): unexpected error %v", err)
	}
	max, err := DeriveCodeBookSeed(key, CodeBookIndex(math.MaxUint64))
	if err != nil {
		t.Fatalf("DeriveCodeBookSeed(index MaxUint64): unexpected error %v", err)
	}
	if bytesEqual(one.Bytes(), max.Bytes()) {
		t.Error("DeriveCodeBookSeed(1) and DeriveCodeBookSeed(MaxUint64) collided")
	}
}

// TestDeriveCodeBookSeedFixedWidthEncodingHasNoAmbiguity is the binary-u64
// analog of the superseded design's TestDeriveCodeBookSeedNoLeadingZeroAmbiguity:
// since CodeBookIndex is now encoded as a fixed 8-byte big-endian u64,
// rather than variable-length decimal ASCII text, there is no
// leading-zero-style encoding ambiguity to guard against by construction —
// this test simply confirms a spread of indexes (including values that
// would be prefixes of one another in decimal, like 1/10/100) never
// collide.
func TestDeriveCodeBookSeedFixedWidthEncodingHasNoAmbiguity(t *testing.T) {
	key := codeBookSeedFixtureUserKey(t)

	seen := make(map[string]CodeBookIndex)
	for _, idx := range []CodeBookIndex{1, 10, 100, 11, 21} {
		s, err := DeriveCodeBookSeed(key, idx)
		if err != nil {
			t.Fatalf("DeriveCodeBookSeed(%d): unexpected error %v", idx, err)
		}
		hexKey := fmt.Sprintf("%x", s.Bytes())
		if prev, ok := seen[hexKey]; ok {
			t.Errorf("DeriveCodeBookSeed(%d) collided with DeriveCodeBookSeed(%d)", idx, prev)
		}
		seen[hexKey] = idx
	}
}

func TestBatchNumberDomain(t *testing.T) {
	for _, tc := range []struct {
		v     uint16
		valid bool
	}{{0, false}, {1, true}, {2, true}, {1023, true}, {1024, false}, {65535, false}} {
		if got := BatchNumber(tc.v).valid(); got != tc.valid {
			t.Errorf("BatchNumber(%d).valid() = %v, want %v", tc.v, got, tc.valid)
		}
	}
}

func TestEntryIndexDomain(t *testing.T) {
	for _, tc := range []struct {
		v     uint32
		valid bool
	}{{0, false}, {1, true}, {2, true}, {MaxEntriesPerBatch, true}, {MaxEntriesPerBatch + 1, false}} {
		if got := EntryIndex(tc.v).valid(); got != tc.valid {
			t.Errorf("EntryIndex(%d).valid() = %v, want %v", tc.v, got, tc.valid)
		}
	}
}

func TestMaxEntriesPerBatchValue(t *testing.T) {
	if MaxEntriesPerBatch != 100_000 {
		t.Errorf("MaxEntriesPerBatch = %d, want 100000", MaxEntriesPerBatch)
	}
}

func TestNewCodeBookIndex(t *testing.T) {
	if _, err := NewCodeBookIndex(0); err != ErrInvalidCodeBookIndex {
		t.Errorf("NewCodeBookIndex(0): err = %v, want %v", err, ErrInvalidCodeBookIndex)
	}
	for _, v := range []uint64{1, ^uint64(0)} {
		got, err := NewCodeBookIndex(v)
		if err != nil || got != CodeBookIndex(v) {
			t.Errorf("NewCodeBookIndex(%d) = %d, %v", v, got, err)
		}
	}
}

func TestUserKey(t *testing.T) {
	b := make([]byte, secretSize)
	for i := range b {
		b[i] = byte(i)
	}
	k, err := NewUserKey(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k.Bytes(), b) {
		t.Errorf("Bytes() = %x, want %x", k.Bytes(), b)
	}
	b[0] ^= 0xff
	if k.Bytes()[0] == b[0] {
		t.Error("UserKey retained the caller's input slice")
	}
	want := k.Bytes()
	returned := k.Bytes()
	returned[0] ^= 0xff
	if !bytes.Equal(k.Bytes(), want) {
		t.Error("mutating Bytes() output changed UserKey")
	}
	for _, n := range []int{0, 1, 16, 31, 33, 64} {
		if _, err := NewUserKey(make([]byte, n)); err != ErrInvalidUserKeySize {
			t.Errorf("NewUserKey(len %d): err = %v, want %v", n, err, ErrInvalidUserKeySize)
		}
	}
	var zero UserKey
	if zero.Bytes() != nil {
		t.Errorf("zero-value UserKey.Bytes() = %x, want nil", zero.Bytes())
	}
	if _, err := DeriveCodeBookSeed(zero, CodeBookIndex(1)); err != ErrInvalidUserKey {
		t.Errorf("DeriveCodeBookSeed(zero UserKey): err = %v, want %v", err, ErrInvalidUserKey)
	}
}

func TestExplicitAllZeroSecretsAreValid(t *testing.T) {
	key, err := NewUserKey(make([]byte, secretSize))
	if err != nil {
		t.Fatal(err)
	}
	if got := key.Bytes(); !bytes.Equal(got, make([]byte, secretSize)) {
		t.Errorf("explicit all-zero UserKey.Bytes() = %x", got)
	}
	seed, err := NewCodeBookSeed(make([]byte, secretSize))
	if err != nil {
		t.Fatal(err)
	}
	if got := seed.Bytes(); !bytes.Equal(got, make([]byte, secretSize)) {
		t.Errorf("explicit all-zero CodeBookSeed.Bytes() = %x", got)
	}
	var zeroSeed CodeBookSeed
	if zeroSeed.Bytes() != nil {
		t.Errorf("zero-value CodeBookSeed.Bytes() = %x, want nil", zeroSeed.Bytes())
	}
}

func TestUserKeyNeverFormatsSecretBytes(t *testing.T) {
	k, err := NewUserKey(bytes.Repeat([]byte{0xcd}, secretSize))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := any(k).(fmt.Stringer); ok {
		t.Error("UserKey must not implement fmt.Stringer")
	}
	const want = "derivation.UserKey{REDACTED}"
	for _, verb := range []string{"%v", "%+v", "%s", "%#v", "%x", "%X", "%q", "%d"} {
		if got := fmt.Sprintf(verb, k); got != want {
			t.Errorf("Sprintf(%q, k) = %q, want %q", verb, got, want)
		}
	}
	if got := fmt.Sprintf("wrapped: %v", k); !strings.HasSuffix(got, want) {
		t.Errorf("error wrapping leaked: %q", got)
	}
}
