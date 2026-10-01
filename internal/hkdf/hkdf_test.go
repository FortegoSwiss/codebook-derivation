package hkdf

import (
	"bytes"
	"encoding/hex"
	"testing"

	stdhkdf "crypto/hkdf"
	"crypto/sha256"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decoding hex %q: %v", s, err)
	}
	return b
}

// TestAppendEncFieldMatchesCanonicalFieldAlgorithm exercises AppendEncField
// directly against hand-computed enc(b) = uint32-BE(len(b)) || b for a
// handful of inputs, confirming it implements the exact algorithm
// documented in README.md's "Exact HKDF parameters" section.
func TestAppendEncFieldMatchesCanonicalFieldAlgorithm(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		[]byte("a"),
		[]byte("fortego:codebook-derivation:v1"),
		bytes.Repeat([]byte{0xAB}, 300),
	}
	for _, b := range cases {
		want := make([]byte, 0, 4+len(b))
		var lenBuf [4]byte
		lenBuf[0] = byte(len(b) >> 24)
		lenBuf[1] = byte(len(b) >> 16)
		lenBuf[2] = byte(len(b) >> 8)
		lenBuf[3] = byte(len(b))
		want = append(want, lenBuf[:]...)
		want = append(want, b...)

		got := AppendEncField(nil, b)
		if !bytes.Equal(got, want) {
			t.Errorf("AppendEncField(nil, %x) = %x, want %x", b, got, want)
		}
	}
}

// TestFixedWidthIntEncoders checks U8/U16/U32/U64 produce the exact
// big-endian byte widths (see README.md's "Exact HKDF parameters" section).
func TestFixedWidthIntEncoders(t *testing.T) {
	if got := U8(0xAB); !bytes.Equal(got, []byte{0xAB}) {
		t.Errorf("U8(0xAB) = %x, want ab", got)
	}
	if got := U16(0x0102); !bytes.Equal(got, []byte{0x01, 0x02}) {
		t.Errorf("U16(0x0102) = %x, want 0102", got)
	}
	if got := U32(0x01020304); !bytes.Equal(got, []byte{0x01, 0x02, 0x03, 0x04}) {
		t.Errorf("U32(0x01020304) = %x, want 01020304", got)
	}
	if got := U64(0x0102030405060708); !bytes.Equal(got, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}) {
		t.Errorf("U64(...) = %x, want 0102030405060708", got)
	}
}

// TestU64EncodingIsFixedWidth confirms U64's encoding is always exactly 8
// bytes regardless of value, exercised from the root package against
// DeriveCodeBookSeed.
func TestU64EncodingIsFixedWidth(t *testing.T) {
	for _, idx := range []uint64{0, 1, 10, 100, 1<<64 - 1} {
		if got := len(U64(idx)); got != 8 {
			t.Errorf("len(U64(%d)) = %d, want 8", idx, got)
		}
	}
}

// TestCtxBatchKeySaltAndInfo pins Ctx's output, byte-for-byte,
// against README.md's "Exact HKDF parameters" worked salt/info hex for
// DerivationV1 = 1, BatchNumber = 1 — never runtime-generated, always
// frozen reference bytes.
func TestCtxBatchKeySaltAndInfo(t *testing.T) {
	wantSalt := mustHex(t, "0000001e666f727465676f3a636f6465626f6f6b2d64657269766174696f6e3a"+
		"76310000000e62617463682d6b65792d73616c74")
	if len(wantSalt) != 52 {
		t.Fatalf("test setup: want salt length 52, got %d", len(wantSalt))
	}
	gotSalt := Ctx("batch-key-salt")
	if !bytes.Equal(gotSalt, wantSalt) {
		t.Errorf("salt = %x, want %x", gotSalt, wantSalt)
	}

	wantInfo := mustHex(t, "0000001e666f727465676f3a636f6465626f6f6b2d64657269766174696f6e3a"+
		"7631000000096261746368"+
		"2d6b6579000000010100000002"+
		"0001")
	if len(wantInfo) != 58 {
		t.Fatalf("test setup: want info length 58, got %d", len(wantInfo))
	}
	gotInfo := Ctx("batch-key", U8(1), U16(1))
	if !bytes.Equal(gotInfo, wantInfo) {
		t.Errorf("info = %x, want %x", gotInfo, wantInfo)
	}
}

// TestDomainLiteralLength confirms the fixed domain literal encodes to the
// exact 30-byte / 0x0000001e-length-prefixed field the spec's own
// salt/info hex dumps above both start with (uint32-BE(30) = 0x0000001e).
func TestDomainLiteralLength(t *testing.T) {
	if len(Domain) != 30 {
		t.Fatalf("Domain length = %d, want 30", len(Domain))
	}
}

// TestVectorsHKDFPrimitiveCrossCheckRFC5869 reproduces RFC 5869 Appendix
// A.1 Test Case 1 directly against Go 1.25's standard-library
// crypto/hkdf — the same primitive ExtractExpand wraps — independent of
// this package's own ctx()/enc() wrapper, confirming Extract/Expand are
// called in the RFC-conformant order and shape.
func TestVectorsHKDFPrimitiveCrossCheckRFC5869(t *testing.T) {
	ikm := mustHex(t, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt := mustHex(t, "000102030405060708090a0b0c")
	info := mustHex(t, "f0f1f2f3f4f5f6f7f8f9")
	const l = 42

	wantPRK := mustHex(t, "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
	wantOKM := mustHex(t, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5b"+
		"f34007208d5b887185865")

	prk, err := stdhkdf.Extract(sha256.New, ikm, salt)
	if err != nil {
		t.Fatalf("hkdf.Extract: unexpected error %v", err)
	}
	if !bytes.Equal(prk, wantPRK) {
		t.Errorf("PRK = %x, want %x", prk, wantPRK)
	}

	okm, err := stdhkdf.Expand(sha256.New, prk, string(info), l)
	if err != nil {
		t.Fatalf("hkdf.Expand: unexpected error %v", err)
	}
	if !bytes.Equal(okm, wantOKM) {
		t.Errorf("OKM = %x, want %x", okm, wantOKM)
	}

	got, err := ExtractExpand(ikm, salt, info, l)
	if err != nil {
		t.Fatalf("ExtractExpand: unexpected error %v", err)
	}
	if !bytes.Equal(got, wantOKM) {
		t.Errorf("ExtractExpand = %x, want %x", got, wantOKM)
	}

	// Expand alone, using the same PRK, must reproduce the identical OKM
	// ExtractExpand's own internal Expand call produces — the two code
	// paths must never silently diverge.
	gotExpand, err := Expand(prk, info, l)
	if err != nil {
		t.Fatalf("Expand: unexpected error %v", err)
	}
	if !bytes.Equal(gotExpand, wantOKM) {
		t.Errorf("Expand = %x, want %x", gotExpand, wantOKM)
	}
}
