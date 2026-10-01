// Package crockford implements the Crockford Base32 alphabet (see README.md's
// "The Recovery Code" section). It is internal because encoding and decoding are
// implementation details of the wire formats built on top of it.
package crockford

// Alphabet is the 32-symbol Crockford Base32 alphabet, values 0-31 in index
// order. It excludes I, L, O and U.
const Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// alphabet is the unexported alias EncodeDigit/decodeTable use internally.
const alphabet = Alphabet

// decodeTable maps every possible byte to its 5-bit Crockford value, or -1
// if the byte (after case-folding and alias substitution, see DecodeChar)
// is not a valid Crockford symbol.
var decodeTable = func() [256]int8 {
	var t [256]int8
	for i := range t {
		t[i] = -1
	}
	for i := 0; i < len(alphabet); i++ {
		t[alphabet[i]] = int8(i)
	}
	return t
}()

// EncodeDigit returns the canonical uppercase Crockford character for a
// 5-bit value. Only the low 5 bits of v are consulted; callers pass values
// already known to fit in 5 bits.
func EncodeDigit(v uint8) byte {
	return alphabet[v&0x1F]
}

// DecodeChar decodes a single byte as a Crockford digit: case-insensitive,
// with aliases O -> 0 and I, L -> 1 applied before lookup. U is not an
// alias and, like any byte outside 0-9A-Z (after case-folding and
// aliasing), is rejected. It never panics.
func DecodeChar(c byte) (uint8, bool) {
	switch {
	case c >= 'a' && c <= 'z':
		c -= 'a' - 'A'
	}
	switch c {
	case 'O':
		c = '0'
	case 'I', 'L':
		c = '1'
	}
	v := decodeTable[c]
	if v < 0 {
		return 0, false
	}
	return uint8(v), true
}

// ReadBits5 reads the 5-bit value starting at bitOffset (MSB-first) out of
// data. Both protocols' wire formats pack a Crockford-encoded payload as a
// contiguous MSB-first bitstream, so this bit-reader is shared the same way
// the alphabet above is.
func ReadBits5(data []byte, bitOffset int) uint8 {
	var v uint8
	for i := 0; i < 5; i++ {
		bit := bitOffset + i
		byteIdx := bit / 8
		bitIdx := 7 - (bit % 8)
		b := (data[byteIdx] >> bitIdx) & 1
		v = (v << 1) | b
	}
	return v
}

// HyphenPositions are the 0-indexed character offsets of the 5 literal
// hyphens in package recoverycode's canonical grouped Recovery Code display
// form (see README.md's "The Recovery Code" section): 30 Crockford
// characters in 6 groups of 5.
var HyphenPositions = [5]int{5, 11, 17, 23, 29}

// TrimASCIIWhitespace trims leading and trailing ASCII space, tab, LF and CR
// bytes from s. Both protocols tolerate exactly this whitespace set around
// an otherwise-canonical wire string.
func TrimASCIIWhitespace(s string) string {
	isWS := func(b byte) bool {
		return b == ' ' || b == '\t' || b == '\n' || b == '\r'
	}
	i, j := 0, len(s)
	for i < j && isWS(s[i]) {
		i++
	}
	for j > i && isWS(s[j-1]) {
		j--
	}
	return s[i:j]
}
