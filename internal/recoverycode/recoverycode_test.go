package recoverycode

import (
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"testing"
)

//go:embed recovery-code.v1.json
var recoveryCodeVectorsJSON []byte

//go:embed crc10.v1.json
var crc10VectorsJSON []byte

type rejectedInputVector struct {
	Name      string `json:"name"`
	Input     string `json:"input"`
	WantError string `json:"wantError"`
}

type recoveryCodeVectorFile struct {
	Version       int `json:"version"`
	WorkedExample struct {
		RecoveryCodeDataHex  string `json:"recoveryCodeDataHex"`
		BatchNumber          int    `json:"batchNumber"`
		Extension            int    `json:"extension"`
		ProtectedCRCHex      string `json:"protectedCrcHex"`
		Ungrouped            string `json:"ungrouped"`
		Grouped              string `json:"grouped"`
		TamperedDataHex      string `json:"tamperedDataHex"`
		TamperedCRCHex       string `json:"tamperedCrcHex"`
		TamperedStaleCRCWire string `json:"tamperedStaleCrcWireGrouped"`
	} `json:"workedExample"`
	ToleratedVariants []struct {
		Name            string `json:"name"`
		Input           string `json:"input"`
		ExpectedGrouped string `json:"expectedGrouped"`
	} `json:"toleratedVariants"`
	Rejected []rejectedInputVector `json:"rejected"`
}

type crc10VectorFile struct {
	Version           int `json:"version"`
	CatalogCheckValue struct {
		InputASCII string `json:"inputAscii"`
		CRCHex     string `json:"crcHex"`
	} `json:"catalogCheckValue"`
	Vectors []struct {
		Name     string `json:"name"`
		InputHex string `json:"inputHex"`
		NBits    int    `json:"nBits"`
		CRCHex   string `json:"crcHex"`
	} `json:"vectors"`
}

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

// workedExampleData returns recovery-code.v1.json's worked-example RecoveryCodeData
// (EntryIndex = 1): c3cf21909321f45c9bdf72ab5e47e9f5.
func workedExampleData(t *testing.T) [DataSize]byte {
	t.Helper()
	b := mustHex(t, "c3cf21909321f45c9bdf72ab5e47e9f5")
	var d [DataSize]byte
	copy(d[:], b)
	return d
}

// loadRecoveryCodeVectors is a small test helper shared by every test in
// this package that consumes recovery-code.v1.json.
func loadRecoveryCodeVectors(t *testing.T) recoveryCodeVectorFile {
	t.Helper()
	var f recoveryCodeVectorFile
	if err := json.Unmarshal(recoveryCodeVectorsJSON, &f); err != nil {
		t.Fatalf("loading recovery-code vectors: %v", err)
	}
	if f.Version != 1 {
		t.Fatalf("recovery-code vector version = %d, want 1", f.Version)
	}
	return f
}

// groupedForm renders c's 30-character ungrouped wire form (WireString)
// grouped as 6 groups of 5 with literal hyphens (see README.md's "The Recovery
// Code" section). Nothing in the v1 public API needs grouped RecoveryCode
// output — the Batch wire schema embeds only the ungrouped form — so
// this exists solely so this file's tests can compare against recovery-code.v1.json's
// expectedGrouped/grouped fields without adding unused display surface to
// recoverycode.go itself.
func groupedForm(c Code) string {
	ungrouped := c.WireString()
	out := make([]byte, 0, GroupedLen)
	for i := 0; i < len(ungrouped); i++ {
		if i > 0 && i%5 == 0 {
			out = append(out, '-')
		}
		out = append(out, ungrouped[i])
	}
	return string(out)
}

// TestVectorsRecoveryCodeWorkedExample pins Code packing/encoding against
// recovery-code.v1.json's workedExample: CRC-10 over
// the protected field, ungrouped and grouped Crockford forms. Expected
// values are loaded, never computed here: a divergence must fail this
// test, not be silently accepted.
func TestVectorsRecoveryCodeWorkedExample(t *testing.T) {
	v := loadRecoveryCodeVectors(t).WorkedExample

	var data [DataSize]byte
	copy(data[:], mustHex(t, v.RecoveryCodeDataHex))
	batchNumber := uint16(v.BatchNumber)

	c, err := New(batchNumber, data, uint8(v.Extension))
	if err != nil {
		t.Fatalf("New: unexpected error %v", err)
	}

	// Independently confirm the CRC-10 over the 140-bit protected field.
	full := c.pack()
	gotCRC := crc10ATM(full, protectedBits)
	wantCRCBytes := mustHex(t, v.ProtectedCRCHex)
	if len(wantCRCBytes) != 2 {
		t.Fatalf("test setup: protectedCrcHex %q must decode to 2 bytes", v.ProtectedCRCHex)
	}
	wantCRC := binary.BigEndian.Uint16(wantCRCBytes)
	if gotCRC != wantCRC {
		t.Errorf("CRC-10/ATM(protected) = %#04x, want %#04x", gotCRC, wantCRC)
	}

	if got := c.WireString(); got != v.Ungrouped {
		t.Errorf("WireString() = %q, want %q", got, v.Ungrouped)
	}
	if got := groupedForm(c); got != v.Grouped {
		t.Errorf("groupedForm() = %q, want %q", got, v.Grouped)
	}
}

// TestVectorsRecoveryCodeTamperCheck reproduces the tamper check
// against recovery-code.v1.json's workedExample: flipping the low
// bit of RecoveryCodeData's first byte recomputes the CRC to a mismatching
// value, and a parser must reject a wire string carrying the tampered data
// alongside the original (now-stale) CRC.
func TestVectorsRecoveryCodeTamperCheck(t *testing.T) {
	v := loadRecoveryCodeVectors(t).WorkedExample

	var tamperedData [DataSize]byte
	copy(tamperedData[:], mustHex(t, v.TamperedDataHex))
	batchNumber := uint16(v.BatchNumber)

	tamperedCode, err := New(batchNumber, tamperedData, uint8(v.Extension))
	if err != nil {
		t.Fatal(err)
	}
	tamperedProtected := tamperedCode.pack()
	gotTamperedCRC := crc10ATM(tamperedProtected, protectedBits)
	wantTamperedCRCBytes := mustHex(t, v.TamperedCRCHex)
	if len(wantTamperedCRCBytes) != 2 {
		t.Fatalf("test setup: tamperedCrcHex %q must decode to 2 bytes", v.TamperedCRCHex)
	}
	wantTamperedCRC := binary.BigEndian.Uint16(wantTamperedCRCBytes)
	if gotTamperedCRC != wantTamperedCRC {
		t.Errorf("CRC-10/ATM(tampered protected) = %#04x, want %#04x", gotTamperedCRC, wantTamperedCRC)
	}

	// The checked-in wire string carries the tampered RecoveryCodeData but
	// the *original* (now-stale) CRC; a parser must reject it as a CRC
	// mismatch.
	if _, err := Parse(v.TamperedStaleCRCWire); err != ErrCRC {
		t.Errorf("Parse(tampered) err = %v, want ErrCRC", err)
	}
}

// TestRecoveryCodeRoundTrip confirms construct -> WireString -> Parse ->
// equal fields, for both the ungrouped and grouped forms.
func TestRecoveryCodeRoundTrip(t *testing.T) {
	data := workedExampleData(t)

	c, err := New(1, data, 0)
	if err != nil {
		t.Fatal(err)
	}

	ungrouped := c.WireString()
	grouped := groupedForm(c)

	for _, s := range []string{grouped, ungrouped} {
		parsed, err := Parse(s)
		if err != nil {
			t.Fatalf("Parse(%q): unexpected error %v", s, err)
		}
		if parsed.batchNumber != c.batchNumber {
			t.Errorf("batchNumber = %v, want %v", parsed.batchNumber, c.batchNumber)
		}
		if parsed.ext != c.ext {
			t.Errorf("ext = %v, want %v", parsed.ext, c.ext)
		}
		if !bytesEqual(parsed.data[:], c.data[:]) {
			t.Errorf("data = %x, want %x", parsed.data, c.data)
		}
		if parsed.WireString() != ungrouped {
			t.Errorf("round-tripped WireString() = %q, want %q", parsed.WireString(), ungrouped)
		}
	}
}

// TestNewRejectsInvalidBatchNumber confirms New validates batchNumber before
// constructing.
func TestNewRejectsInvalidBatchNumber(t *testing.T) {
	data := workedExampleData(t)
	if _, err := New(0, data, 0); err != ErrInvalidBatchNumber {
		t.Errorf("err = %v, want ErrInvalidBatchNumber", err)
	}
	if _, err := New(1024, data, 0); err != ErrInvalidBatchNumber {
		t.Errorf("err = %v, want ErrInvalidBatchNumber", err)
	}
}

// TestNewRejectsInvalidExtension confirms New rejects any Extension other
// than 0.
func TestNewRejectsInvalidExtension(t *testing.T) {
	data := workedExampleData(t)
	for _, v := range []uint8{1, 2, 3} {
		if _, err := New(1, data, v); err != ErrExtension {
			t.Errorf("Extension(%d): err = %v, want ErrExtension", v, err)
		}
	}
}

// TestParseCrockfordAliases confirms every approved Crockford alias (O/I/L,
// both cases) is accepted on parse, U is rejected, and a non-Crockford
// character is rejected.
func TestParseCrockfordAliases(t *testing.T) {
	data := workedExampleData(t)
	c, err := New(1, data, 0)
	if err != nil {
		t.Fatal(err)
	}
	canonical := groupedForm(c)

	if canonical[0] != '0' {
		t.Fatalf("test assumption violated: canonical[0] = %q, want '0'", canonical[0])
	}

	aliasCases := []struct {
		name string
		from byte
		to   byte
	}{
		{"O-upper-for-0", '0', 'O'},
		{"o-lower-for-0", '0', 'o'},
	}
	for _, tc := range aliasCases {
		t.Run(tc.name, func(t *testing.T) {
			b := []byte(canonical)
			replaced := false
			for i := range b {
				if b[i] == tc.from {
					b[i] = tc.to
					replaced = true
					break
				}
			}
			if !replaced {
				t.Fatalf("test setup: no %q found to replace", tc.from)
			}
			parsed, err := Parse(string(b))
			if err != nil {
				t.Fatalf("Parse(%q): unexpected error %v", b, err)
			}
			if groupedForm(parsed) != canonical {
				t.Errorf("alias-substituted parse groupedForm() = %q, want %q", groupedForm(parsed), canonical)
			}
		})
	}

	idx := -1
	for i := 0; i < len(canonical); i++ {
		if canonical[i] == '1' {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Fatal("test assumption violated: no '1' found in canonical form")
	}
	for _, alias := range []byte{'I', 'i', 'L', 'l'} {
		t.Run(string(alias)+"-for-1", func(t *testing.T) {
			b := []byte(canonical)
			b[idx] = alias
			parsed, err := Parse(string(b))
			if err != nil {
				t.Fatalf("Parse(%q): unexpected error %v", b, err)
			}
			if groupedForm(parsed) != canonical {
				t.Errorf("alias-substituted parse groupedForm() = %q, want %q", groupedForm(parsed), canonical)
			}
		})
	}

	t.Run("U-rejected", func(t *testing.T) {
		b := []byte(canonical)
		b[idx] = 'U'
		if _, err := Parse(string(b)); err != ErrChar {
			t.Errorf("err = %v, want ErrChar", err)
		}
	})

	t.Run("non-crockford-char-rejected", func(t *testing.T) {
		b := []byte(canonical)
		b[idx] = '!'
		if _, err := Parse(string(b)); err != ErrChar {
			t.Errorf("err = %v, want ErrChar", err)
		}
	})
}

// TestParseBothLengthsEquivalent confirms both the 30-char ungrouped and
// 35-char grouped forms are accepted and produce the same parsed value.
func TestParseBothLengthsEquivalent(t *testing.T) {
	data := workedExampleData(t)
	c, err := New(1, data, 0)
	if err != nil {
		t.Fatal(err)
	}
	grouped := groupedForm(c)
	ungrouped := c.WireString()

	if len(grouped) != GroupedLen {
		t.Fatalf("len(grouped) = %d, want %d", len(grouped), GroupedLen)
	}
	if len(ungrouped) != UngroupedLen {
		t.Fatalf("len(ungrouped) = %d, want %d", len(ungrouped), UngroupedLen)
	}

	pGrouped, err := Parse(grouped)
	if err != nil {
		t.Fatalf("Parse(grouped): %v", err)
	}
	pUngrouped, err := Parse(ungrouped)
	if err != nil {
		t.Fatalf("Parse(ungrouped): %v", err)
	}
	if pGrouped.WireString() != pUngrouped.WireString() {
		t.Errorf("grouped/ungrouped parse mismatch: %q vs %q", pGrouped.WireString(), pUngrouped.WireString())
	}
}

// TestParseWrongLengthRejected confirms lengths other than 30/35 are
// rejected with ErrLength.
func TestParseWrongLengthRejected(t *testing.T) {
	cases := []string{
		"",
		"0",
		"01RF7J344K47T5S6YZEANNWHZ9YMK",        // 29 chars
		"01RF7J344K47T5S6YZEANNWHZ9YMKVV",      // 31 chars
		"01RF7-J344K-47T5S-6YZEA-NNWHZ-9YMK",   // 34 chars
		"01RF7-J344K-47T5S-6YZEA-NNWHZ-9YMKVV", // 36 chars
	}
	for _, s := range cases {
		if _, err := Parse(s); err != ErrLength {
			t.Errorf("Parse(%q) err = %v, want ErrLength", s, err)
		}
	}
}

// TestParseMisplacedHyphenRejected confirms a 35-character input with a
// hyphen in the wrong position is rejected.
func TestParseMisplacedHyphenRejected(t *testing.T) {
	bad := "01RF7J-344K-47T5S-6YZEA-NNWHZ-9YMKV"
	if len(bad) != GroupedLen {
		t.Fatalf("test setup: len(bad) = %d, want %d", len(bad), GroupedLen)
	}
	if _, err := Parse(bad); err != ErrHyphen {
		t.Errorf("err = %v, want ErrHyphen", err)
	}
}

// TestParseExtensionRejectedAfterCRC hand-constructs a wire value whose
// Extension field is not 0 but whose CRC-10 is correctly computed over that
// exact (invalid-Extension) 140-bit protected field, and confirms Parse
// rejects it with ErrExtension, not ErrCRC — proving Extension validity is
// checked only after CRC validation has already succeeded (see README.md's
// "The Recovery Code" section).
func TestParseExtensionRejectedAfterCRC(t *testing.T) {
	data := workedExampleData(t)
	s := PackForTest(1, data, 1) // Extension = 0b01, invalid

	_, err := Parse(s)
	if err != ErrExtension {
		t.Errorf("Parse(invalid-extension, CRC-valid) err = %v, want ErrExtension", err)
	}
}

// TestParseNeverPanics feeds a battery of adversarial inputs (empty,
// non-ASCII, arbitrarily long) through Parse and confirms it always
// returns an error rather than panicking.
func TestParseNeverPanics(t *testing.T) {
	inputs := []string{
		"",
		" ",
		"\t\n\r",
		"日本語テストストリングは長い日本語テストストリングは長い",
		string(make([]byte, 10000)),
		"01RF7-J344K-47T5S-6YZEA-NNWHZ-9YMKU", // trailing U
		"\x00\x01\x02",
	}
	for _, s := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Parse(%q) panicked: %v", s, r)
				}
			}()
			if _, err := Parse(s); err == nil {
				t.Errorf("Parse(%q): expected error, got nil", s)
			}
		}()
	}
}

// TestVectorsCRC10ATMCatalogCheckValue pins crc10ATM against the published
// CRC-10/ATM catalog check value (RevEng "Catalogue of parametrised CRC
// algorithms"), loaded from crc10.v1.json rather than hardcoded
// here: CRC-10/ATM of the ASCII bytes of "123456789", fed MSB-first byte by
// byte, is 0x199.
func TestVectorsCRC10ATMCatalogCheckValue(t *testing.T) {
	var f crc10VectorFile
	if err := json.Unmarshal(crc10VectorsJSON, &f); err != nil {
		t.Fatalf("loading CRC-10 vectors: %v", err)
	}
	if f.Version != 1 {
		t.Fatalf("CRC-10 vector: version = %d, want 1", f.Version)
	}
	cc := f.CatalogCheckValue

	input := []byte(cc.InputASCII)
	wantBytes := mustHex(t, cc.CRCHex)
	if len(wantBytes) != 2 {
		t.Fatalf("test setup: crcHex %q must decode to 2 bytes", cc.CRCHex)
	}
	want := binary.BigEndian.Uint16(wantBytes)
	if got := crc10ATM(input, len(input)*8); got != want {
		t.Errorf("crc10ATM(%q) = %#04x, want %#04x", input, got, want)
	}
}

// TestVectorsCRC10ATM pins crc10ATM against every checked-in worked value in
// crc10.v1.json: plain ASCII inputs and RecoveryCode-shaped
// protected-field inputs alike. Expected values are loaded, never
// computed here: a divergence must fail this test, not be silently
// accepted.
func TestVectorsCRC10ATM(t *testing.T) {
	var f crc10VectorFile
	if err := json.Unmarshal(crc10VectorsJSON, &f); err != nil {
		t.Fatalf("loading CRC-10 vectors: %v", err)
	}
	if f.Version != 1 {
		t.Fatalf("CRC-10 vector: version = %d, want 1", f.Version)
	}
	if len(f.Vectors) == 0 {
		t.Fatal("no CRC-10 vectors loaded")
	}

	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			input := mustHex(t, v.InputHex)
			wantBytes := mustHex(t, v.CRCHex)
			if len(wantBytes) != 2 {
				t.Fatalf("test setup: crcHex %q must decode to 2 bytes", v.CRCHex)
			}
			want := binary.BigEndian.Uint16(wantBytes)
			if got := crc10ATM(input, v.NBits); got != want {
				t.Errorf("crc10ATM(%x, %d) = %#04x, want %#04x", input, v.NBits, got, want)
			}
		})
	}
}

// TestVectorsRecoveryCodeTolerated pins Parse's Crockford O/I/L alias
// tolerance against every checked-in tolerated-input vector in
// recovery-code.v1.json.
func TestVectorsRecoveryCodeTolerated(t *testing.T) {
	f := loadRecoveryCodeVectors(t)
	if len(f.ToleratedVariants) == 0 {
		t.Fatal("no tolerated-input vectors loaded")
	}

	for _, v := range f.ToleratedVariants {
		t.Run(v.Name, func(t *testing.T) {
			got, err := Parse(v.Input)
			if err != nil {
				t.Fatalf("Parse(%q): unexpected error %v", v.Input, err)
			}
			if groupedForm(got) != v.ExpectedGrouped {
				t.Errorf("Parse(%q) grouped = %q, want %q", v.Input, groupedForm(got), v.ExpectedGrouped)
			}
		})
	}
}

// TestVectorsRecoveryCodeRejected pins Parse's rejection rules
// against every checked-in rejected-input vector in
// recovery-code.v1.json, matching the exact sentinel error named
// by wantError -- never merely "some error".
func TestVectorsRecoveryCodeRejected(t *testing.T) {
	f := loadRecoveryCodeVectors(t)
	if len(f.Rejected) == 0 {
		t.Fatal("no rejected-input vectors loaded")
	}

	errByName := map[string]error{
		"ErrRecoveryCodeLength":    ErrLength,
		"ErrRecoveryCodeHyphen":    ErrHyphen,
		"ErrRecoveryCodeChar":      ErrChar,
		"ErrRecoveryCodeCRC":       ErrCRC,
		"ErrRecoveryCodeExtension": ErrExtension,
		"ErrInvalidBatchNumber":    ErrInvalidBatchNumber,
	}

	for _, v := range f.Rejected {
		t.Run(v.Name, func(t *testing.T) {
			want, ok := errByName[v.WantError]
			if !ok {
				t.Fatalf("vector %q: unknown wantError name %q", v.Name, v.WantError)
			}
			_, err := Parse(v.Input)
			if err != want {
				t.Errorf("Parse(%q) = %v, want %v", v.Input, err, want)
			}
		})
	}
}
