package derive

import (
	stdhkdf "crypto/hkdf"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/FortegoSwiss/codebook-derivation/internal/hkdf"
)

//go:embed batch-key.v1.json
var batchKeyVectorsJSON []byte

//go:embed recovery-code-data.v1.json
var recoveryCodeDataVectorsJSON []byte

//go:embed user-key.v1.json
var userKeyVectorsJSON []byte

func loadVectors(t *testing.T, data []byte, dst any) {
	t.Helper()
	if err := json.Unmarshal(data, dst); err != nil {
		t.Fatalf("loading vectors: %v", err)
	}
}

type batchKeyVectorFile struct {
	Version int `json:"version"`
	Vectors []struct {
		Name              string `json:"name"`
		EntropyHex        string `json:"entropyHex"`
		DerivationVersion int    `json:"derivationVersion"`
		BatchNumber       int    `json:"batchNumber"`
		SaltHex           string `json:"saltHex"`
		InfoHex           string `json:"infoHex"`
		PRKHex            string `json:"prkHex"`
		BatchKeyHex       string `json:"batchKeyHex"`
	} `json:"vectors"`
}

type recoveryCodeDataVectorFile struct {
	Version int `json:"version"`
	Vectors []struct {
		Name                string `json:"name"`
		EntropyHex          string `json:"entropyHex"`
		DerivationVersion   int    `json:"derivationVersion"`
		BatchNumber         int    `json:"batchNumber"`
		EntryIndex          int    `json:"entryIndex"`
		SaltHex             string `json:"saltHex"`
		InfoHex             string `json:"infoHex"`
		PRKHex              string `json:"prkHex"`
		RecoveryCodeDataHex string `json:"recoveryCodeDataHex"`
	} `json:"vectors"`
}

type userKeyVectorFile struct {
	Version int `json:"version"`
	Vectors []struct {
		Name                string `json:"name"`
		BatchKeyHex         string `json:"batchKeyHex"`
		RecoveryCodeDataHex string `json:"recoveryCodeDataHex"`
		DerivationVersion   int    `json:"derivationVersion"`
		BatchNumber         int    `json:"batchNumber"`
		Extension           int    `json:"extension"`
		IKMHex              string `json:"ikmHex"`
		PRKHex              string `json:"prkHex"`
		UserKeyHex          string `json:"userKeyHex"`
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

// batchEntropyFixture is the batch
// mnemonic worked example: entropy 0x00 * 32.
var batchEntropyFixture = [32]byte{}

// recoveryEntropyFixture is the recovery code batch mnemonic worked
// example: entropy 0x7f * 32.
var recoveryEntropyFixture = func() [32]byte {
	var e [32]byte
	for i := range e {
		e[i] = 0x7f
	}
	return e
}()

// --- DeriveBatchKey ---------------------------------------------

// TestVectorsDeriveBatchKey pins DeriveBatchKey
// against every checked-in vector in batch-key.v1.json.
// Expected values are loaded, never computed here: a divergence must fail
// this test, not be silently accepted.
func TestVectorsDeriveBatchKey(t *testing.T) {
	var f batchKeyVectorFile
	loadVectors(t, batchKeyVectorsJSON, &f)
	if f.Version != 1 {
		t.Fatalf("batch-key vector: version = %d, want 1", f.Version)
	}
	if len(f.Vectors) == 0 {
		t.Fatal("no batchKey vectors loaded")
	}

	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			if v.DerivationVersion != int(DerivationV1) {
				t.Skipf("vector uses DerivationV%d; this implementation derives only DerivationV%d", v.DerivationVersion, DerivationV1)
			}
			var entropy [32]byte
			copy(entropy[:], mustHex(t, v.EntropyHex))
			batchNumber := uint16(v.BatchNumber)

			// Cross-validate the intermediate salt/info/PRK fields too --
			// not just the final BatchKeyHex -- so every published
			// field in this vector is actually checked by a test,
			// reproducing DeriveBatchKey's internal steps directly.
			wantSalt := hkdf.Ctx("batch-key-salt")
			if hex.EncodeToString(wantSalt) != v.SaltHex {
				t.Errorf("salt = %x, want %s", wantSalt, v.SaltHex)
			}
			wantInfo := hkdf.Ctx("batch-key", hkdf.U8(uint8(v.DerivationVersion)), hkdf.U16(uint16(v.BatchNumber)))
			if hex.EncodeToString(wantInfo) != v.InfoHex {
				t.Errorf("info = %x, want %s", wantInfo, v.InfoHex)
			}
			wantPRK, err := stdhkdf.Extract(sha256.New, entropy[:], wantSalt)
			if err != nil {
				t.Fatalf("hkdf.Extract: unexpected error %v", err)
			}
			if hex.EncodeToString(wantPRK) != v.PRKHex {
				t.Errorf("PRK = %x, want %s", wantPRK, v.PRKHex)
			}

			wantKey := mustHex(t, v.BatchKeyHex)

			got, err := DeriveBatchKey(entropy, batchNumber)
			if err != nil {
				t.Fatalf("DeriveBatchKey: unexpected error %v", err)
			}
			if !bytesEqual(got[:], wantKey) {
				t.Errorf("DeriveBatchKey = %x, want %x", got[:], wantKey)
			}
		})
	}
}

func TestDeriveBatchKeyInvalidBatchNumber(t *testing.T) {
	if _, err := DeriveBatchKey(batchEntropyFixture, 0); err != ErrInvalidBatchNumber {
		t.Errorf("err = %v, want ErrInvalidBatchNumber", err)
	}
	if _, err := DeriveBatchKey(batchEntropyFixture, 1024); err != ErrInvalidBatchNumber {
		t.Errorf("err = %v, want ErrInvalidBatchNumber", err)
	}
}

// --- DeriveRecoveryCodeData -----------------------------------------------

// TestVectorsDeriveRecoveryCodeData pins DeriveRecoveryCodeData
// against every checked-in vector in recovery-code-data.v1.json:
// RecoveryCodeData is reproduced byte-exact. Expected values are loaded,
// never computed here: a divergence must fail this test, not be silently
// accepted.
func TestVectorsDeriveRecoveryCodeData(t *testing.T) {
	var f recoveryCodeDataVectorFile
	loadVectors(t, recoveryCodeDataVectorsJSON, &f)
	if f.Version != 1 {
		t.Fatalf("recovery-code-data vector: version = %d, want 1", f.Version)
	}
	if len(f.Vectors) == 0 {
		t.Fatal("no recoveryCodeData vectors loaded")
	}

	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			if v.DerivationVersion != int(DerivationV1) {
				t.Skipf("vector uses DerivationV%d; this implementation derives only DerivationV%d", v.DerivationVersion, DerivationV1)
			}
			var entropy [32]byte
			copy(entropy[:], mustHex(t, v.EntropyHex))
			batchNumber := uint16(v.BatchNumber)
			idx := uint32(v.EntryIndex)

			// Cross-validate the intermediate salt/info/PRK fields too, not
			// just the final RecoveryCodeDataHex.
			wantSalt := hkdf.Ctx("recovery-code-data-salt")
			if hex.EncodeToString(wantSalt) != v.SaltHex {
				t.Errorf("salt = %x, want %s", wantSalt, v.SaltHex)
			}
			wantInfo := hkdf.Ctx("recovery-code-data", hkdf.U8(uint8(v.DerivationVersion)), hkdf.U16(uint16(v.BatchNumber)), hkdf.U32(uint32(v.EntryIndex)))
			if hex.EncodeToString(wantInfo) != v.InfoHex {
				t.Errorf("info = %x, want %s", wantInfo, v.InfoHex)
			}
			wantPRK, err := stdhkdf.Extract(sha256.New, entropy[:], wantSalt)
			if err != nil {
				t.Fatalf("hkdf.Extract: unexpected error %v", err)
			}
			if hex.EncodeToString(wantPRK) != v.PRKHex {
				t.Errorf("PRK = %x, want %s", wantPRK, v.PRKHex)
			}

			wantData := mustHex(t, v.RecoveryCodeDataHex)

			got, err := DeriveRecoveryCodeData(entropy, batchNumber, idx)
			if err != nil {
				t.Fatalf("DeriveRecoveryCodeData: unexpected error %v", err)
			}
			if !bytesEqual(got[:], wantData) {
				t.Errorf("DeriveRecoveryCodeData = %x, want %x", got[:], wantData)
			}
		})
	}
}

// TestDeriveRecoveryCodeDataBatchNumberVariation confirms changing only BatchNumber
// changes the derived RecoveryCodeData (context separation), complementing
// the checked-in vectors' own two given EntryIndex values.
func TestDeriveRecoveryCodeDataBatchNumberVariation(t *testing.T) {
	d1, err := DeriveRecoveryCodeData(recoveryEntropyFixture, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := DeriveRecoveryCodeData(recoveryEntropyFixture, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if bytesEqual(d1[:], d2[:]) {
		t.Error("DeriveRecoveryCodeData must produce different output for different BatchNumber")
	}
}

// TestDeriveRecoveryCodeDataDomainRejections confirms every out-of-domain
// identifier is rejected with its own dedicated error, before deriving.
func TestDeriveRecoveryCodeDataDomainRejections(t *testing.T) {
	t.Run("batchNumber", func(t *testing.T) {
		if _, err := DeriveRecoveryCodeData(recoveryEntropyFixture, 0, 1); err != ErrInvalidBatchNumber {
			t.Errorf("err = %v, want ErrInvalidBatchNumber", err)
		}
		if _, err := DeriveRecoveryCodeData(recoveryEntropyFixture, 1024, 1); err != ErrInvalidBatchNumber {
			t.Errorf("err = %v, want ErrInvalidBatchNumber", err)
		}
	})
	t.Run("entryIndex", func(t *testing.T) {
		if _, err := DeriveRecoveryCodeData(recoveryEntropyFixture, 1, 0); err != ErrInvalidEntryIndex {
			t.Errorf("err = %v, want ErrInvalidEntryIndex", err)
		}
		if _, err := DeriveRecoveryCodeData(recoveryEntropyFixture, 1, maxEntryIndex+1); err != ErrInvalidEntryIndex {
			t.Errorf("err = %v, want ErrInvalidEntryIndex", err)
		}
	})
}

// TestEntryIndexDomainBoundaries exercises DeriveRecoveryCodeData at
// EntryIndex's exact domain boundaries (see README.md's "Derivation" section):
// 0 rejected, 1 accepted, MaxEntriesPerBatch accepted,
// MaxEntriesPerBatch+1 rejected.
func TestEntryIndexDomainBoundaries(t *testing.T) {
	cases := []struct {
		idx    uint32
		wantOK bool
	}{
		{0, false},
		{1, true},
		{maxEntryIndex, true},
		{maxEntryIndex + 1, false},
	}
	for _, tc := range cases {
		_, err := DeriveRecoveryCodeData(recoveryEntropyFixture, 1, tc.idx)
		if tc.wantOK && err != nil {
			t.Errorf("idx=%d: unexpected error %v", tc.idx, err)
		}
		if !tc.wantOK && err != ErrInvalidEntryIndex {
			t.Errorf("idx=%d: err = %v, want ErrInvalidEntryIndex", tc.idx, err)
		}
	}
}

// --- DeriveUserKey ---------------------------------------------------

// TestVectorsDeriveUserKey pins DeriveUserKey against
// every checked-in vector in user-key.v1.json.
func TestVectorsDeriveUserKey(t *testing.T) {
	var f userKeyVectorFile
	loadVectors(t, userKeyVectorsJSON, &f)
	if f.Version != 1 {
		t.Fatalf("user-key vector: version = %d, want 1", f.Version)
	}
	if len(f.Vectors) == 0 {
		t.Fatal("no userKey vectors loaded")
	}

	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			if v.DerivationVersion != int(DerivationV1) || v.Extension != 0 {
				t.Skipf("vector uses DerivationV%d Extension=%d; this implementation derives only DerivationV%d, extension 0", v.DerivationVersion, v.Extension, DerivationV1)
			}
			var batchKey [32]byte
			copy(batchKey[:], mustHex(t, v.BatchKeyHex))
			var data [16]byte
			copy(data[:], mustHex(t, v.RecoveryCodeDataHex))
			batchNumber := uint16(v.BatchNumber)

			// Cross-validate the intermediate IKM/PRK fields too, not just
			// the final UserKeyHex.
			wantIKM := append(append([]byte{}, batchKey[:]...), data[:]...)
			if hex.EncodeToString(wantIKM) != v.IKMHex {
				t.Errorf("IKM = %x, want %s", wantIKM, v.IKMHex)
			}
			wantSalt := hkdf.Ctx("user-key-salt")
			wantPRK, err := stdhkdf.Extract(sha256.New, wantIKM, wantSalt)
			if err != nil {
				t.Fatalf("hkdf.Extract: unexpected error %v", err)
			}
			if hex.EncodeToString(wantPRK) != v.PRKHex {
				t.Errorf("PRK = %x, want %s", wantPRK, v.PRKHex)
			}

			wantKey := mustHex(t, v.UserKeyHex)

			got, err := DeriveUserKey(batchKey, batchNumber, data)
			if err != nil {
				t.Fatalf("DeriveUserKey: unexpected error %v", err)
			}
			if !bytesEqual(got[:], wantKey) {
				t.Errorf("DeriveUserKey = %x, want %x", got[:], wantKey)
			}
		})
	}
}
