package derivation

import (
	_ "embed"
	"errors"
	"testing"
)

//go:embed internal/recoverycode/recovery-code.v1.json
var decodeRecoveryCodeVectorsJSON []byte

type decodeRecoveryCodeVectorFile struct {
	Version       int `json:"version"`
	WorkedExample struct {
		BatchNumber int    `json:"batchNumber"`
		Extension   int    `json:"extension"`
		Ungrouped   string `json:"ungrouped"`
		Grouped     string `json:"grouped"`
	} `json:"workedExample"`
	ToleratedVariants []struct {
		Name            string `json:"name"`
		Input           string `json:"input"`
		ExpectedGrouped string `json:"expectedGrouped"`
	} `json:"toleratedVariants"`
	Rejected []struct {
		Name      string `json:"name"`
		Input     string `json:"input"`
		WantError string `json:"wantError"`
	} `json:"rejected"`
}

func loadDecodeRecoveryCodeVectors(t *testing.T) decodeRecoveryCodeVectorFile {
	t.Helper()
	var f decodeRecoveryCodeVectorFile
	loadJSON(t, decodeRecoveryCodeVectorsJSON, &f)
	if f.Version != 1 {
		t.Fatalf("recovery-code vector version = %d, want 1", f.Version)
	}
	return f
}

// TestDecodeRecoveryCodeWorkedExample pins DecodeRecoveryCode's
// BatchNumber/Extension against recovery-code.v1.json's workedExample, for
// both the ungrouped and grouped forms.
func TestDecodeRecoveryCodeWorkedExample(t *testing.T) {
	v := loadDecodeRecoveryCodeVectors(t).WorkedExample

	for _, form := range []string{v.Ungrouped, v.Grouped} {
		info, err := DecodeRecoveryCode(form)
		if err != nil {
			t.Fatalf("DecodeRecoveryCode(%q): unexpected error %v", form, err)
		}
		if got := info.BatchNumber(); got != BatchNumber(v.BatchNumber) {
			t.Errorf("DecodeRecoveryCode(%q).BatchNumber() = %d, want %d", form, got, v.BatchNumber)
		}
		if got := info.Extension(); got != uint8(v.Extension) {
			t.Errorf("DecodeRecoveryCode(%q).Extension() = %d, want %d", form, got, v.Extension)
		}
	}
}

// TestDecodeRecoveryCodeToleratedVariants confirms DecodeRecoveryCode
// accepts every Crockford-alias-tolerant input recovery-code.v1.json pins,
// producing the same BatchNumber as the canonical form.
func TestDecodeRecoveryCodeToleratedVariants(t *testing.T) {
	f := loadDecodeRecoveryCodeVectors(t)
	if len(f.ToleratedVariants) == 0 {
		t.Fatal("no tolerated-input vectors loaded")
	}
	want := BatchNumber(f.WorkedExample.BatchNumber)

	for _, v := range f.ToleratedVariants {
		t.Run(v.Name, func(t *testing.T) {
			info, err := DecodeRecoveryCode(v.Input)
			if err != nil {
				t.Fatalf("DecodeRecoveryCode(%q): unexpected error %v", v.Input, err)
			}
			if got := info.BatchNumber(); got != want {
				t.Errorf("BatchNumber() = %d, want %d", got, want)
			}
		})
	}
}

// TestDecodeRecoveryCodeRejected pins DecodeRecoveryCode's rejection rules
// against every checked-in rejected-input vector in
// recovery-code.v1.json -- including CRC-corrupted and malformed-envelope
// (length, hyphen, character, extension) cases -- matching the exact
// sentinel error batch.go re-exports, never merely "some error". This is
// the same error identity RecoverUserKey returns for the equivalent
// rejection (see batch.go), so callers can rely on errors.Is regardless of
// which function rejected the code.
func TestDecodeRecoveryCodeRejected(t *testing.T) {
	f := loadDecodeRecoveryCodeVectors(t)
	if len(f.Rejected) == 0 {
		t.Fatal("no rejected-input vectors loaded")
	}

	errByName := map[string]error{
		"ErrRecoveryCodeLength":    ErrRecoveryCodeLength,
		"ErrRecoveryCodeHyphen":    ErrRecoveryCodeHyphen,
		"ErrRecoveryCodeChar":      ErrRecoveryCodeChar,
		"ErrRecoveryCodeCRC":       ErrRecoveryCodeCRC,
		"ErrRecoveryCodeExtension": ErrRecoveryCodeExtension,
		"ErrInvalidBatchNumber":    ErrInvalidBatchNumber,
	}

	for _, v := range f.Rejected {
		t.Run(v.Name, func(t *testing.T) {
			want, ok := errByName[v.WantError]
			if !ok {
				t.Fatalf("vector %q: unknown wantError name %q", v.Name, v.WantError)
			}
			info, err := DecodeRecoveryCode(v.Input)
			if err != want {
				t.Errorf("DecodeRecoveryCode(%q) err = %v, want %v", v.Input, err, want)
			}
			if info != (RecoveryCodeInfo{}) {
				t.Errorf("DecodeRecoveryCode(%q): got non-zero RecoveryCodeInfo alongside an error", v.Input)
			}
		})
	}
}

// TestDecodeRecoveryCodeMatchesRecoverUserKeyErrorIdentity confirms
// DecodeRecoveryCode and RecoverUserKey reject the same malformed input
// with the identical sentinel error, for every rejected vector -- the
// error-identity guarantee DecodeRecoveryCode's doc comment promises.
func TestDecodeRecoveryCodeMatchesRecoverUserKeyErrorIdentity(t *testing.T) {
	f := loadDecodeRecoveryCodeVectors(t)
	m := batchEntropyFixture(t)

	for _, v := range f.Rejected {
		t.Run(v.Name, func(t *testing.T) {
			_, decodeErr := DecodeRecoveryCode(v.Input)
			_, recoverErr := m.RecoverUserKey(v.Input)
			if decodeErr != recoverErr {
				t.Errorf("DecodeRecoveryCode err = %v, RecoverUserKey err = %v; want identical", decodeErr, recoverErr)
			}
		})
	}
}

// TestDecodeRecoveryCodeErrorsMatchPublicSentinels confirms every rejected
// vector's error also satisfies errors.Is against the *exported* sentinel a
// real caller outside this package would actually dispatch on --
// ErrRecoveryCodeLength, ErrRecoveryCodeHyphen, ErrRecoveryCodeChar,
// ErrRecoveryCodeCRC, ErrRecoveryCodeExtension, and ErrInvalidBatchNumber.
// TestDecodeRecoveryCodeMatchesRecoverUserKeyErrorIdentity only ever
// compares DecodeRecoveryCode against RecoverUserKey, so it stays green even
// if both functions return the same *unexported* value that never chains to
// any public sentinel at all -- exactly the gap that let
// recoverycode.ErrInvalidBatchNumber leak unre-exported for a full release.
// This test instead checks both functions directly against the errByName
// table's public values, so a future regression that reintroduces an
// unexported leaf error fails here even if DecodeRecoveryCode and
// RecoverUserKey still happen to agree with each other.
func TestDecodeRecoveryCodeErrorsMatchPublicSentinels(t *testing.T) {
	f := loadDecodeRecoveryCodeVectors(t)
	m := batchEntropyFixture(t)

	errByName := map[string]error{
		"ErrRecoveryCodeLength":    ErrRecoveryCodeLength,
		"ErrRecoveryCodeHyphen":    ErrRecoveryCodeHyphen,
		"ErrRecoveryCodeChar":      ErrRecoveryCodeChar,
		"ErrRecoveryCodeCRC":       ErrRecoveryCodeCRC,
		"ErrRecoveryCodeExtension": ErrRecoveryCodeExtension,
		"ErrInvalidBatchNumber":    ErrInvalidBatchNumber,
	}

	for _, v := range f.Rejected {
		t.Run(v.Name, func(t *testing.T) {
			want, ok := errByName[v.WantError]
			if !ok {
				t.Fatalf("vector %q: unknown wantError name %q", v.Name, v.WantError)
			}
			_, decodeErr := DecodeRecoveryCode(v.Input)
			if !errors.Is(decodeErr, want) {
				t.Errorf("DecodeRecoveryCode(%q): errors.Is(%v, %v) = false, want true", v.Input, decodeErr, want)
			}
			_, recoverErr := m.RecoverUserKey(v.Input)
			if !errors.Is(recoverErr, want) {
				t.Errorf("RecoverUserKey(%q): errors.Is(%v, %v) = false, want true", v.Input, recoverErr, want)
			}
		})
	}
}
