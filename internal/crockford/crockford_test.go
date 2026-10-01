package crockford

import "testing"

// TestDecodeCharValid confirms every canonical alphabet character decodes,
// case-insensitively, to its documented index in Alphabet.
func TestDecodeCharValid(t *testing.T) {
	for i := 0; i < len(alphabet); i++ {
		upper := alphabet[i]
		lower := upper
		if lower >= 'A' && lower <= 'Z' {
			lower += 'a' - 'A'
		}
		for _, c := range []byte{upper, lower} {
			got, ok := DecodeChar(c)
			if !ok {
				t.Errorf("DecodeChar(%q) ok = false, want true", c)
				continue
			}
			if got != uint8(i) {
				t.Errorf("DecodeChar(%q) = %d, want %d", c, got, i)
			}
		}
	}
}

// TestDecodeCharAliases confirms the documented O -> 0 and I, L -> 1
// aliases apply case-insensitively, and that the aliased character decodes
// to the exact same value EncodeDigit's canonical '0'/'1' would.
func TestDecodeCharAliases(t *testing.T) {
	zero, ok := DecodeChar('0')
	if !ok {
		t.Fatal("DecodeChar('0') ok = false")
	}
	one, ok := DecodeChar('1')
	if !ok {
		t.Fatal("DecodeChar('1') ok = false")
	}

	cases := []struct {
		alias byte
		want  uint8
	}{
		{'O', zero},
		{'o', zero},
		{'I', one},
		{'i', one},
		{'L', one},
		{'l', one},
	}
	for _, tc := range cases {
		got, ok := DecodeChar(tc.alias)
		if !ok {
			t.Errorf("DecodeChar(%q) ok = false, want true", tc.alias)
			continue
		}
		if got != tc.want {
			t.Errorf("DecodeChar(%q) = %d, want %d (alias of %q)", tc.alias, got, tc.want, tc.alias)
		}
	}
}

// TestDecodeCharRejected confirms U (deliberately not an alias, unlike
// O/I/L) and every byte outside 0-9A-Z (after case-folding and alias
// substitution) is rejected, never panics, and returns (0, false).
func TestDecodeCharRejected(t *testing.T) {
	rejected := []byte{
		'U', 'u', // U is explicitly not a Crockford alias
		' ', '-', '_', '.', ',',
		'!', '@', '#', '$', '%',
		'\x00', '\n', '\t', '\r',
		0xFF, 0x80,
	}
	for _, c := range rejected {
		got, ok := DecodeChar(c)
		if ok {
			t.Errorf("DecodeChar(%q) ok = true, want false", c)
		}
		if got != 0 {
			t.Errorf("DecodeChar(%q) = %d, want 0 on rejection", c, got)
		}
	}

	// DecodeChar must never panic for any possible byte value, including
	// ones no other case above exercises.
	for c := 0; c < 256; c++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("DecodeChar(%d) panicked: %v", c, r)
				}
			}()
			DecodeChar(byte(c))
		}()
	}
}

// TestDecodeCharEncodeDigitRoundTrip confirms DecodeChar inverts
// EncodeDigit for every 5-bit value: the canonicity guarantee both this
// package's callers (recoverycode's wire packing) and README.md's "The
// Recovery Code" section depend on.
func TestDecodeCharEncodeDigitRoundTrip(t *testing.T) {
	for v := 0; v < 32; v++ {
		c := EncodeDigit(uint8(v))
		got, ok := DecodeChar(c)
		if !ok {
			t.Fatalf("DecodeChar(EncodeDigit(%d)=%q) ok = false", v, c)
		}
		if got != uint8(v) {
			t.Errorf("DecodeChar(EncodeDigit(%d)=%q) = %d, want %d", v, c, got, v)
		}
	}
}
