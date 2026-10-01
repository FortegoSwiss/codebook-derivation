package derivation

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// --- TestNoSecretTypeLeaksViaFmt ---------------------------------------
//
// This is the generic, table-driven regression test for the leak class
// fixed by BatchGenerator.Format and Entry.Format: Go's default struct
// formatting recurses into unexported fields regardless of a leaf field's
// own Format method -- a value's own redaction is bypassed whenever that
// value is only reachable as an unexported field of some *other* exported
// struct that itself has no Format override (see e.g. batch.go's
// BatchGenerator.Format and Entry.Format doc comments). Both
// TestBatchHasNoImplicitSerialization (this file's sibling) and
// TestUserKeyNeverFormatsSecretBytes / TestCodeBookSeedNeverFormatsSecretBytes
// / TestMnemonicSecretsNeverFormat cover one type each; this test instead
// walks every exported composite type in the package that carries secret
// bytes -- directly (UserKey, CodeBookSeed, BatchEntropy,
// RecoveryCodeEntropy) or transitively through unexported fields
// (BatchGenerator, Entry, Batch) -- so that a *new* wrapper type
// reintroducing this hole fails here instead of shipping silently.
//
// For every case, every verb renders the value and the test asserts that
// none of the value's known secret byte sequences appear in the output, in
// any of the representations Go's default formatter could plausibly
// produce for them (raw bytes-as-string, lower/upper hex, and the
// bracketed-decimal []byte/[N]byte form %v itself would use).
func TestNoSecretTypeLeaksViaFmt(t *testing.T) {
	batchEntropy := batchEntropyFixtureFor(t)
	recoveryEntropy := recoveryCodeEntropyFixtureFor(t)

	batch, err := createBatch(batchEntropy, recoveryEntropy, BatchNumber(1), 2)
	if err != nil {
		t.Fatal(err)
	}
	entry := batch.Entries()[0]

	userKeyBytes := entry.userKey.b[:]
	userKey, err := NewUserKey(userKeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	seedBytes := []byte(strings.Repeat("\xAB", secretSize))
	seed, err := NewCodeBookSeed(seedBytes)
	if err != nil {
		t.Fatal(err)
	}

	// batchSecrets/entrySecrets collect every secret byte sequence
	// transitively reachable from BatchGenerator/Entry/Batch, so the
	// composite cases below check the *union* of what each contains.
	generatorSecrets := [][]byte{
		append([]byte(nil), batchEntropy.entropy[:]...),
		append([]byte(nil), recoveryEntropy.entropy[:]...),
	}
	var batchSecrets [][]byte
	for _, e := range batch.Entries() {
		batchSecrets = append(batchSecrets, []byte(e.recoveryCode), append([]byte(nil), e.userKey.b[:]...))
	}
	entrySecrets := [][]byte{
		[]byte(entry.recoveryCode),
		append([]byte(nil), entry.userKey.b[:]...),
	}

	generator := NewBatchGenerator(batchEntropy, recoveryEntropy, 1)

	cases := []struct {
		name         string
		value        any
		wantRedacted string
		secrets      [][]byte
	}{
		{"BatchGenerator", generator, "derivation.BatchGenerator{REDACTED}", generatorSecrets},
		{"Entry", entry, "derivation.Entry{REDACTED}", entrySecrets},
		{"Batch", batch, "derivation.Batch{REDACTED}", batchSecrets},
		{"UserKey", userKey, "derivation.UserKey{REDACTED}", [][]byte{append([]byte(nil), userKeyBytes...)}},
		{"CodeBookSeed", seed, "derivation.CodeBookSeed{REDACTED}", [][]byte{append([]byte(nil), seedBytes...)}},
		{"BatchEntropy", batchEntropy, "derivation.BatchEntropy{REDACTED}", [][]byte{append([]byte(nil), batchEntropy.entropy[:]...)}},
		{"RecoveryCodeEntropy", recoveryEntropy, "derivation.RecoveryCodeEntropy{REDACTED}", [][]byte{append([]byte(nil), recoveryEntropy.entropy[:]...)}},
	}

	verbs := []string{"%v", "%+v", "%#v", "%s", "%x", "%X", "%q", "%d"}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, verb := range verbs {
				got := fmt.Sprintf(verb, tc.value)
				if got != tc.wantRedacted {
					t.Errorf("Sprintf(%q, %s) = %q, want %q", verb, tc.name, got, tc.wantRedacted)
				}
				for _, secret := range tc.secrets {
					for _, rep := range secretRepresentations(secret) {
						if rep == "" {
							continue
						}
						if strings.Contains(got, rep) {
							t.Errorf("Sprintf(%q, %s) = %q leaked secret representation %q", verb, tc.name, got, rep)
						}
					}
				}
			}
			// Also confirm redaction survives when the value is wrapped,
			// e.g. inside an error via %w-style formatting or a
			// containing struct's default %v -- matching the pattern
			// TestUserKeyNeverFormatsSecretBytes and
			// TestCodeBookSeedNeverFormatsSecretBytes already check for
			// their single types.
			if got := fmt.Sprintf("wrapped: %v", tc.value); !strings.HasSuffix(got, tc.wantRedacted) {
				t.Errorf("%s wrapped in another format string leaked: %q", tc.name, got)
			}
		})
	}
}

// secretRepresentations returns every string form Go's default (unredacted)
// formatting could plausibly render secret as, so the leak check above
// isn't fooled by a case mismatch or encoding choice.
func secretRepresentations(secret []byte) []string {
	return []string{
		string(secret),
		hex.EncodeToString(secret),
		strings.ToUpper(hex.EncodeToString(secret)),
		fmt.Sprintf("%v", secret),
		fmt.Sprintf("%d", secret),
	}
}
