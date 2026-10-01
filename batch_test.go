package derivation

import (
	"bytes"
	"encoding"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/FortegoSwiss/codebook-derivation/bip39"
	"github.com/FortegoSwiss/codebook-derivation/internal/derive"
	"github.com/FortegoSwiss/codebook-derivation/internal/recoverycode"
)

func createBatch(batchEntropy BatchEntropy, recoveryEntropy RecoveryCodeEntropy, batchNumber BatchNumber, size int) (Batch, error) {
	return NewBatchGenerator(batchEntropy, recoveryEntropy, batchNumber).Generate(size)
}

// recoveryCodeWorkedExampleData returns the worked example's
// RecoveryCodeData (EntryIndex = 1): e90b44f1b99c487b93b1670dfa1c6ead.
func recoveryCodeWorkedExampleData(t *testing.T) [16]byte {
	t.Helper()
	b := mustHex(t, "e90b44f1b99c487b93b1670dfa1c6ead")
	var d [16]byte
	copy(d[:], b)
	return d
}

// --- fixtures ---------------------------------------------------------

func batchEntropyFixtureFor(t *testing.T) BatchEntropy {
	t.Helper()
	return batchEntropyFixture(t)
}

func recoveryCodeEntropyFixtureFor(t *testing.T) RecoveryCodeEntropy {
	t.Helper()
	return recoveryCodeEntropyFixture(t)
}

// --- golden worked examples ------------------------------------------------
//
// These hex/fingerprint literals are this package's own frozen reference
// bytes -- the same worked example batch.v1.json's vectors pin
// independently -- never computed at test-run time.

const (
	workedSingleEntryHex = "0100010000000130315834354d395744534b483437513458484357365a4d3733454e4d435242103e59c04a69a73ee5c9304c8db91ee030e38c9e74895cec8836af900bcf43"

	workedSingleEntryFingerprint = "6B12T-AZY0M-XDW8M-SJR95"

	workedTwoEntryHex = "0100010000000230315834354d395744534b483437513458484357365a4d3733454e4d435242103e59c04a69a73ee5c9304c8db91ee030e38c9e74895cec8836af900bcf43303134334e4a5a333239424e3852345838314e46594651333132455252470460db75076cdd2c8b1df21a9616e9434dcd30ddd8788fa714e7613634c791a4"

	workedTwoEntryFingerprint = "F32WR-GV91R-BM42K-5AE0B"
)

// TestVectorsGenerateSingleEntryWorkedExample reproduces the worked example's
// single-entry Batch byte-for-byte: encoded bytes and Fingerprint.
// Expected values are the checked-in vectors' own frozen reference bytes,
// never computed here.
func TestVectorsGenerateSingleEntryWorkedExample(t *testing.T) {
	b, err := createBatch(batchEntropyFixtureFor(t), recoveryCodeEntropyFixtureFor(t), BatchNumber(1), 1)
	if err != nil {
		t.Fatalf("Generate: unexpected error %v", err)
	}

	encoded, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: unexpected error %v", err)
	}
	if hex.EncodeToString(encoded) != workedSingleEntryHex {
		t.Errorf("Encode() = %x, want %s", encoded, workedSingleEntryHex)
	}

	if got := b.Fingerprint(); got != workedSingleEntryFingerprint {
		t.Errorf("Fingerprint() = %q, want %q", got, workedSingleEntryFingerprint)
	}

	// The Batch must also decode back from its own encoded bytes.
	if _, err := DecodeBatch(encoded); err != nil {
		t.Fatalf("DecodeBatch(own output): unexpected error %v", err)
	}
}

// TestVectorsGenerateTwoEntryWorkedExample reproduces the worked example's
// two-entry Batch byte-for-byte.
func TestVectorsGenerateTwoEntryWorkedExample(t *testing.T) {
	b, err := createBatch(batchEntropyFixtureFor(t), recoveryCodeEntropyFixtureFor(t), BatchNumber(1), 2)
	if err != nil {
		t.Fatalf("Generate: unexpected error %v", err)
	}

	encoded, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: unexpected error %v", err)
	}
	if hex.EncodeToString(encoded) != workedTwoEntryHex {
		t.Errorf("Encode() = %x, want %s", encoded, workedTwoEntryHex)
	}

	if got := b.Fingerprint(); got != workedTwoEntryFingerprint {
		t.Errorf("Fingerprint() = %q, want %q", got, workedTwoEntryFingerprint)
	}
}

// TestDecodeBatchWorkedExampleLiteralBytes decodes the worked example's
// literal encoded bytes directly (independent of Generate), confirming
// DecodeBatch's own parsing path succeeds.
func TestDecodeBatchWorkedExampleLiteralBytes(t *testing.T) {
	b1, err := DecodeBatch(mustHex(t, workedSingleEntryHex))
	if err != nil {
		t.Fatalf("DecodeBatch(single-entry literal): unexpected error %v", err)
	}
	if b1.Len() != 1 {
		t.Errorf("Len() = %d, want 1", b1.Len())
	}

	b2, err := DecodeBatch(mustHex(t, workedTwoEntryHex))
	if err != nil {
		t.Fatalf("DecodeBatch(two-entry literal): unexpected error %v", err)
	}
	if b2.Len() != 2 {
		t.Errorf("Len() = %d, want 2", b2.Len())
	}
}

// TestMaxBatchEncodedBytesMatchesConstant pins the computed
// maxBatchEncodedBytes constant against README.md's documented number
// (6,200,007), so a future MaxEntriesPerBatch or entrySize change
// cannot silently drift this bound without a test noticing.
func TestMaxBatchEncodedBytesMatchesConstant(t *testing.T) {
	if maxBatchEncodedBytes != 6_200_007 {
		t.Errorf("maxBatchEncodedBytes = %d, want 6200007", maxBatchEncodedBytes)
	}
}

// TestEntrySizeAndHeaderSizeMatchConstants pins headerSize (7) and
// entrySize (62) against README.md's documented "Canonical Batch
// encoding" byte layout.
func TestEntrySizeAndHeaderSizeMatchConstants(t *testing.T) {
	if headerSize != 7 {
		t.Errorf("headerSize = %d, want 7", headerSize)
	}
	if entrySize != 62 {
		t.Errorf("entrySize = %d, want 62", entrySize)
	}
}

// --- Generate ---------------------------------------------------------------

func TestGenerateEntryAssociation(t *testing.T) {
	b, err := createBatch(batchEntropyFixtureFor(t), recoveryCodeEntropyFixtureFor(t), BatchNumber(1), 3)
	if err != nil {
		t.Fatalf("Generate: unexpected error %v", err)
	}
	entries := b.Entries()
	if len(entries) != 3 {
		t.Fatalf("len(entries) = %d, want 3", len(entries))
	}
	for i, e := range entries {
		if int(e.Index()) != i+1 {
			t.Errorf("entries[%d].Index() = %d, want %d", i, e.Index(), i+1)
		}
		// The same derivation must supply both the RecoveryCode string and
		// the UserKey: recomputing UserKey via RecoverUserKey
		// from the entry's own RecoveryCode string must match exactly.
		recovered, err := batchEntropyFixtureFor(t).RecoverUserKey(e.RecoveryCode())
		if err != nil {
			t.Fatalf("RecoverUserKey(entries[%d]): unexpected error %v", i, err)
		}
		if !bytes.Equal(recovered.Bytes(), e.UserKey().Bytes()) {
			t.Errorf("entries[%d]: RecoverUserKey = %x, want %x", i, recovered.Bytes(), e.UserKey().Bytes())
		}
	}
}

// TestMnemonicConstructorsRejectInvalidInput confirms validation happens at
// the role-specific constructor boundary.
func TestGenerateRejectsInvalidMnemonics(t *testing.T) {
	if _, err := DecodeBatchMnemonic(nil); err != ErrMnemonicWordCount {
		t.Errorf("empty batch mnemonic: err = %v, want ErrMnemonicWordCount", err)
	}
	if _, err := DecodeRecoveryCodeMnemonic(nil); err != ErrMnemonicWordCount {
		t.Errorf("empty recovery mnemonic: err = %v, want ErrMnemonicWordCount", err)
	}
}

func TestGenerateRejectsInvalidBatchNumber(t *testing.T) {
	if _, err := createBatch(batchEntropyFixtureFor(t), recoveryCodeEntropyFixtureFor(t), BatchNumber(0), 1); err != ErrInvalidBatchNumber {
		t.Errorf("err = %v, want ErrInvalidBatchNumber", err)
	}
	if _, err := createBatch(batchEntropyFixtureFor(t), recoveryCodeEntropyFixtureFor(t), BatchNumber(1024), 1); err != ErrInvalidBatchNumber {
		t.Errorf("err = %v, want ErrInvalidBatchNumber", err)
	}
}

func TestGenerateSizeBoundaries(t *testing.T) {
	if _, err := createBatch(batchEntropyFixtureFor(t), recoveryCodeEntropyFixtureFor(t), BatchNumber(1), 0); err != ErrInvalidBatchSize {
		t.Errorf("size=0: err = %v, want ErrInvalidBatchSize", err)
	}
	if _, err := createBatch(batchEntropyFixtureFor(t), recoveryCodeEntropyFixtureFor(t), BatchNumber(1), -1); err != ErrInvalidBatchSize {
		t.Errorf("size=-1: err = %v, want ErrInvalidBatchSize", err)
	}
	if _, err := createBatch(batchEntropyFixtureFor(t), recoveryCodeEntropyFixtureFor(t), BatchNumber(1), MaxEntriesPerBatch+1); err != ErrInvalidBatchSize {
		t.Errorf("size=MaxEntriesPerBatch+1: err = %v, want ErrInvalidBatchSize", err)
	}
}

// TestGenerateMaxSizeBoundary confirms size == MaxEntriesPerBatch (100,000)
// is accepted and produces a Batch with exactly that many contiguous
// Entries that DecodeBatch can, in turn, accept. This is the full
// MaxEntriesPerBatch boundary itself, not a reduced stand-in —
// it runs in a few seconds, well within normal `go test` timeouts.
func TestGenerateMaxSizeBoundary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping MaxEntriesPerBatch boundary test in -short mode")
	}
	b, err := createBatch(batchEntropyFixtureFor(t), recoveryCodeEntropyFixtureFor(t), BatchNumber(1), MaxEntriesPerBatch)
	if err != nil {
		t.Fatalf("createBatch(size=MaxEntriesPerBatch): unexpected error %v", err)
	}
	if b.Len() != MaxEntriesPerBatch {
		t.Fatalf("Len() = %d, want %d", b.Len(), MaxEntriesPerBatch)
	}
	entries := b.Entries()
	if int(entries[len(entries)-1].Index()) != MaxEntriesPerBatch {
		t.Errorf("last entry Index() = %d, want %d", entries[len(entries)-1].Index(), MaxEntriesPerBatch)
	}

	encoded, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: unexpected error %v", err)
	}
	if len(encoded) > maxBatchEncodedBytes {
		t.Errorf("len(encoded) = %d, exceeds maxBatchEncodedBytes = %d", len(encoded), maxBatchEncodedBytes)
	}
	if _, err := DecodeBatch(encoded); err != nil {
		t.Fatalf("DecodeBatch(max-size Batch): unexpected error %v", err)
	}
}

func TestGenerateNumberPartialResultOnFailure(t *testing.T) {
	got, err := createBatch(batchEntropyFixtureFor(t), recoveryCodeEntropyFixtureFor(t), BatchNumber(0), 1)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !reflect.DeepEqual(got, Batch{}) {
		t.Errorf("got = %+v, want zero-value Batch", got)
	}
}

// --- Batch/Entry immutability and zero-value handling ----------------------

func TestBatchEntriesReturnsDefensiveCopy(t *testing.T) {
	b, err := createBatch(batchEntropyFixtureFor(t), recoveryCodeEntropyFixtureFor(t), BatchNumber(1), 2)
	if err != nil {
		t.Fatal(err)
	}
	e1 := b.Entries()
	e1[0] = Entry{}
	e2 := b.Entries()
	if e2[0].Index() != 1 {
		t.Error("mutating the slice returned by Entries() affected a subsequent call")
	}
}

func TestZeroValueBatchUnusable(t *testing.T) {
	var b Batch
	if _, err := b.Encode(); err != ErrInvalidBatch {
		t.Errorf("Encode() err = %v, want ErrInvalidBatch", err)
	}
	if b.BatchNumber() != 0 {
		t.Errorf("BatchNumber() = %v, want 0", b.BatchNumber())
	}
	if b.Len() != 0 {
		t.Errorf("Len() = %d, want 0", b.Len())
	}
	if got := b.Entries(); len(got) != 0 {
		t.Errorf("Entries() = %v, want empty", got)
	}
	// A zero-value Batch has no meaningful encoded form, so Fingerprint
	// must not compute a plausible-looking digest for it.
	if got := b.Fingerprint(); got != "" {
		t.Errorf("Fingerprint() = %q, want empty", got)
	}
}

func TestZeroValueEntryUnusable(t *testing.T) {
	var e Entry
	if e.Index() != 0 {
		t.Errorf("Index() = %v, want 0", e.Index())
	}
	if e.RecoveryCode() != "" {
		t.Errorf("RecoveryCode() = %q, want empty", e.RecoveryCode())
	}
	if e.UserKey().Bytes() != nil {
		t.Errorf("UserKey().Bytes() = %x, want nil", e.UserKey().Bytes())
	}
}

// --- DecodeBatch: malformed/non-canonical rejection ---------------------------------

func mustCreateTwoEntryBatch(t *testing.T) (Batch, []byte) {
	t.Helper()
	b, err := createBatch(batchEntropyFixtureFor(t), recoveryCodeEntropyFixtureFor(t), BatchNumber(1), 2)
	if err != nil {
		t.Fatalf("Generate: unexpected error %v", err)
	}
	encoded, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: unexpected error %v", err)
	}
	return b, encoded
}

func TestDecodeBatchRejectsTooLarge(t *testing.T) {
	oversized := make([]byte, maxBatchEncodedBytes+1)
	if _, err := DecodeBatch(oversized); err != ErrInvalidBatch {
		t.Errorf("err = %v, want ErrInvalidBatch", err)
	}
}

func TestDecodeBatchMalformedAndNonCanonicalRejection(t *testing.T) {
	_, encoded := mustCreateTwoEntryBatch(t)

	// Sanity: baseline decodes.
	if _, err := DecodeBatch(encoded); err != nil {
		t.Fatalf("baseline DecodeBatch: unexpected error %v", err)
	}

	cases := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{
			name: "truncatedHeader",
			mutate: func(b []byte) []byte {
				return b[:3]
			},
		},
		{
			name: "trailingByte",
			mutate: func(b []byte) []byte {
				return append(append([]byte(nil), b...), 0x00)
			},
		},
		{
			name: "truncatedLastEntry",
			mutate: func(b []byte) []byte {
				return b[:len(b)-1]
			},
		},
		{
			name: "unsupportedVersion",
			mutate: func(b []byte) []byte {
				out := append([]byte(nil), b...)
				out[0] = 2
				return out
			},
		},
		{
			name: "batchNumberZero",
			mutate: func(b []byte) []byte {
				out := append([]byte(nil), b...)
				out[1], out[2] = 0, 0
				return out
			},
		},
		{
			name: "entryCountZero",
			mutate: func(b []byte) []byte {
				out := append([]byte(nil), b...)
				out[3], out[4], out[5], out[6] = 0, 0, 0, 0
				return out
			},
		},
		{
			name: "entryCountTooLarge",
			mutate: func(b []byte) []byte {
				out := append([]byte(nil), b...)
				out[3], out[4], out[5], out[6] = 0, 1, 0x86, 0xA1 // 100001
				return out
			},
		},
		{
			name: "nonCanonicalRecoveryCodeAlias",
			mutate: func(b []byte) []byte {
				out := append([]byte(nil), b...)
				if out[headerSize] != '0' {
					t.Fatalf("test assumption violated: entries[0].recoveryCode[0] != '0'")
				}
				out[headerSize] = 'O' // valid Crockford alias for '0', but not canonical.
				return out
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutated := tc.mutate(append([]byte(nil), encoded...))
			got, err := DecodeBatch(mutated)
			if err != ErrInvalidBatch {
				t.Errorf("DecodeBatch(%s): err = %v, want ErrInvalidBatch", tc.name, err)
			}
			if !reflect.DeepEqual(got, Batch{}) {
				t.Errorf("DecodeBatch(%s): got = %+v, want zero-value Batch", tc.name, got)
			}
		})
	}
}

// --- Fingerprint -------------------------------------------------------------

func TestFingerprintDetectsFieldMutation(t *testing.T) {
	b, _ := mustCreateTwoEntryBatch(t)

	flipByte := func(bs []byte, i int) []byte {
		out := append([]byte(nil), bs...)
		out[i] ^= 0xFF
		return out
	}

	cases := []struct {
		name  string
		build func() []byte
	}{
		{"version", func() []byte {
			return encodeBatch(2, b.batchNumber, b.entries)
		}},
		{"batchNumber", func() []byte {
			return encodeBatch(b.version, b.batchNumber+1, b.entries)
		}},
		{"recoveryCode", func() []byte {
			es := append([]Entry(nil), b.entries...)
			es[0].recoveryCode = string(flipByte([]byte(es[0].recoveryCode), 2))
			return encodeBatch(b.version, b.batchNumber, es)
		}},
		{"userKey", func() []byte {
			es := append([]Entry(nil), b.entries...)
			tampered, err := NewUserKey(flipByte(es[0].userKey.Bytes(), 0))
			if err != nil {
				t.Fatal(err)
			}
			es[0].userKey = tampered
			return encodeBatch(b.version, b.batchNumber, es)
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutated := tc.build()
			got, err := DecodeBatch(mutated)
			if tc.name == "userKey" {
				if err != nil {
					t.Fatalf("DecodeBatch(tampered %s): unexpected error %v", tc.name, err)
				}
				if got.Fingerprint() == b.Fingerprint() {
					t.Errorf("Fingerprint did not change after tampering %s", tc.name)
				}
				return
			}
			if err != ErrInvalidBatch {
				t.Errorf("DecodeBatch(tampered %s): err = %v, want ErrInvalidBatch", tc.name, err)
			}
		})
	}
}

// --- RecoverUserKey ------------------------------------------------

func TestRecoverUserKeyMatchesBatchEntry(t *testing.T) {
	b, err := createBatch(batchEntropyFixtureFor(t), recoveryCodeEntropyFixtureFor(t), BatchNumber(1), 1)
	if err != nil {
		t.Fatal(err)
	}
	entry := b.Entries()[0]

	got, err := batchEntropyFixtureFor(t).RecoverUserKey(entry.RecoveryCode())
	if err != nil {
		t.Fatalf("RecoverUserKey: unexpected error %v", err)
	}
	if !bytes.Equal(got.Bytes(), entry.UserKey().Bytes()) {
		t.Errorf("RecoverUserKey = %x, want %x", got.Bytes(), entry.UserKey().Bytes())
	}
}

func TestRecoverUserKeyDeterministic(t *testing.T) {
	m := batchEntropyFixtureFor(t)
	code := workedRecoveryCode
	k1, err := m.RecoverUserKey(code)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := m.RecoverUserKey(code)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1.Bytes(), k2.Bytes()) {
		t.Error("RecoverUserKey is not deterministic")
	}
}

func TestRecoverUserKeyRejectsInvalidMnemonic(t *testing.T) {
	if _, err := (BatchEntropy{}).RecoverUserKey(workedRecoveryCode); err != ErrInvalidBatchEntropy {
		t.Errorf("zero batch entropy: err = %v, want ErrInvalidBatchEntropy", err)
	}
}

// workedRecoveryCode is the worked example's RecoveryCode, ungrouped.
const workedRecoveryCode = "01X45M9WDSKH47Q4XHCW6ZM73ENMCR"

func TestRecoverUserKeyRejectsInvalidRecoveryCode(t *testing.T) {
	m := batchEntropyFixtureFor(t)
	cases := []struct {
		name string
		code string
	}{
		{"bad CRC", "01RF7J344K47T5S6YZEANNWHZ9YMKW"}, // last char changed
		{"wrong length", "01RF7J344K47T5S6YZEANNWHZ9YMK"},
		{"invalid alphabet", "01RF7J344K47T5S6YZEANNWHZ9YM!!"},
		{"empty", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := m.RecoverUserKey(tc.code); err == nil {
				t.Errorf("RecoverUserKey(%q): expected error, got nil", tc.code)
			}
		})
	}
}

// TestRecoverUserKeyRejectsNonZeroExtension hand-constructs a
// structurally valid (CRC-correct) RecoveryCode wire string whose Extension
// bits are non-zero and confirms RecoverUserKey rejects it.
func TestRecoverUserKeyRejectsNonZeroExtension(t *testing.T) {
	m := batchEntropyFixtureFor(t)
	data := recoveryCodeWorkedExampleData(t)

	// recoverycode.PackForTest packs a CRC-valid wire string without
	// New's business-rule rejection of ext != 0 -- the only way to
	// hand-construct this scenario now that the bit-packing internals
	// live in internal/recoverycode, a different package.
	wireStr := recoverycode.PackForTest(1, data, 1) // Extension = 0b01

	if _, err := m.RecoverUserKey(wireStr); err != ErrRecoveryCodeExtension {
		t.Errorf("err = %v, want ErrRecoveryCodeExtension", err)
	}
}

// TestDecodeBatchRejectsEntryWithWrongEmbeddedBatchNumber hand-constructs a
// Batch whose entry's RecoveryCode was derived under a different
// BatchNumber than the Batch header declares, and confirms DecodeBatch rejects
// it.
func TestDecodeBatchRejectsEntryWithWrongEmbeddedBatchNumber(t *testing.T) {
	batchMnemonic, err := bip39.Parse(batchMnemonicFixtureWords)
	if err != nil {
		t.Fatal(err)
	}
	recoveryMnemonic, err := bip39.Parse(recoveryCodeMnemonicFixtureWords)
	if err != nil {
		t.Fatal(err)
	}
	batchEntropy := batchMnemonic.Entropy()
	recoveryEntropy := recoveryMnemonic.Entropy()

	// Derive a batchNumber=2 RecoveryCode/UserKey pair for EntryIndex 1, then
	// splice it into an otherwise-valid batchNumber=1 Batch's header.
	batchKey2, err := derive.DeriveBatchKey(batchEntropy, 2)
	if err != nil {
		t.Fatal(err)
	}
	data2, err := derive.DeriveRecoveryCodeData(recoveryEntropy, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	userKey2Bytes, err := derive.DeriveUserKey(batchKey2, 2, data2)
	if err != nil {
		t.Fatal(err)
	}
	userKey2, err := NewUserKey(userKey2Bytes[:])
	if err != nil {
		t.Fatal(err)
	}
	code2, err := recoverycode.New(2, data2, recoverycode.ExtensionV1)
	if err != nil {
		t.Fatal(err)
	}

	entries := []Entry{{index: 1, recoveryCode: code2.WireString(), userKey: userKey2}}

	mutated := encodeBatch(derive.DerivationV1, BatchNumber(1), entries)

	if _, err := DecodeBatch(mutated); err != ErrInvalidBatch {
		t.Errorf("err = %v, want ErrInvalidBatch", err)
	}
}

func TestDecodeBatchNeverPanics(t *testing.T) {
	inputs := [][]byte{
		nil,
		{},
		{0x00},
		{0x01},
		mustHex(t, "01"),
		[]byte(strings.Repeat("a", 1000)),
		[]byte("\x00\x01\x02"),
		append([]byte{1, 0, 1, 0, 0, 0, 1}, []byte(strings.Repeat("!", entrySize))...),
	}
	for _, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("DecodeBatch(%x) panicked: %v", in, r)
				}
			}()
			if _, err := DecodeBatch(in); err == nil {
				t.Errorf("DecodeBatch(%x): expected error, got nil", in)
			}
		}()
	}
}

// --- secret formatting -----------------------------------------------------

func TestBatchNeverFormatsSecretMaterial(t *testing.T) {
	b, err := createBatch(batchEntropyFixtureFor(t), recoveryCodeEntropyFixtureFor(t), BatchNumber(1), 1)
	if err != nil {
		t.Fatal(err)
	}
	// Batch itself carries no secret formatting override, but its Entries'
	// UserKey values must still redact under fmt.
	for _, e := range b.Entries() {
		got := fmt.Sprintf("%v", e.UserKey())
		if got != "derivation.UserKey{REDACTED}" {
			t.Errorf("UserKey Sprintf = %q, want redacted", got)
		}
	}
}

// TestBatchHasNoImplicitSerialization confirms Batch.Encode is the only
// intentional plaintext Batch serialization boundary: Batch itself
// implements neither fmt.Stringer nor
// json.Marshaler/encoding.TextMarshaler, so a caller cannot accidentally
// leak an encoded (and therefore confidential, plaintext-Recovery-Code
// -and-UserKey-carrying) Batch via fmt.Sprintf, json.Marshal, or a log
// call that happens to format the value — only an explicit Encode() call
// does that.
func TestBatchHasNoImplicitSerialization(t *testing.T) {
	b, err := createBatch(batchEntropyFixtureFor(t), recoveryCodeEntropyFixtureFor(t), BatchNumber(1), 1)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := any(b).(fmt.Stringer); ok {
		t.Error("Batch must not implement fmt.Stringer")
	}
	if _, ok := any(b).(json.Marshaler); ok {
		t.Error("Batch must not implement json.Marshaler")
	}
	if _, ok := any(b).(encoding.TextMarshaler); ok {
		t.Error("Batch must not implement encoding.TextMarshaler")
	}

	// A bare %v/%+v must never contain the plaintext RecoveryCode or
	// UserKey bytes that Encode() would produce.
	entry := b.Entries()[0]
	got := fmt.Sprintf("%v %+v", b, b)
	if strings.Contains(got, entry.RecoveryCode()) {
		t.Error("default fmt formatting of Batch leaked its RecoveryCode plaintext")
	}
}
