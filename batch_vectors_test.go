package derivation

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/FortegoSwiss/codebook-derivation/bip39"
)

//go:embed batch.v1.json
var batchVectorsJSON []byte

//go:embed recover-user-key.v1.json
var recoverUserKeyVectorsJSON []byte

func loadJSON(t *testing.T, data []byte, dst any) {
	t.Helper()
	if err := json.Unmarshal(data, dst); err != nil {
		t.Fatalf("loading vectors: %v", err)
	}
}

type batchVectorFile struct {
	Version              int    `json:"version"`
	BatchEntropyHex      string `json:"batchEntropyHex"`
	RecoveryEntropyHex   string `json:"recoveryEntropyHex"`
	BatchNumber          int    `json:"batchNumber"`
	HeaderSize           int    `json:"headerSize"`
	EntrySize            int    `json:"entrySize"`
	MaxBatchEncodedBytes int    `json:"maxBatchEncodedBytes"`
	WorkedExamples       []struct {
		Name        string `json:"name"`
		EntryCount  int    `json:"entryCount"`
		EncodedHex  string `json:"encodedHex"`
		Fingerprint string `json:"fingerprint"`
	} `json:"workedExamples"`
	DecodeRejections []struct {
		Name       string `json:"name"`
		EncodedHex string `json:"encodedHex"`
	} `json:"decodeRejections"`
}

type recoverUserKeyVectorFile struct {
	Version int `json:"version"`
	Vectors []struct {
		Name            string `json:"name"`
		BatchEntropyHex string `json:"batchEntropyHex"`
		RecoveryCode    string `json:"recoveryCode"`
		UserKeyHex      string `json:"userKeyHex"`
	} `json:"vectors"`
}

// TestVectorsBatchWorkedExamples pins Batch.Encode() and
// Fingerprint against every checked-in worked example in
// batch.v1.json, for both BatchGenerator.Generate's own
// output and DecodeBatch's independent re-derivation from the literal
// encoded bytes. Every field of each worked example is asserted.
func TestVectorsBatchWorkedExamples(t *testing.T) {
	var f batchVectorFile
	loadJSON(t, batchVectorsJSON, &f)
	if f.Version != 1 {
		t.Fatalf("batch vector: version = %d, want 1", f.Version)
	}
	if len(f.WorkedExamples) == 0 {
		t.Fatal("no batch worked examples loaded")
	}
	if f.HeaderSize != headerSize {
		t.Errorf("headerSize = %d, want %d", f.HeaderSize, headerSize)
	}
	if f.EntrySize != entrySize {
		t.Errorf("entrySize = %d, want %d", f.EntrySize, entrySize)
	}
	if f.MaxBatchEncodedBytes != maxBatchEncodedBytes {
		t.Errorf("maxBatchEncodedBytes = %d, want %d", f.MaxBatchEncodedBytes, maxBatchEncodedBytes)
	}

	var batchEntropy, recoveryEntropy [32]byte
	copy(batchEntropy[:], mustHex(t, f.BatchEntropyHex))
	copy(recoveryEntropy[:], mustHex(t, f.RecoveryEntropyHex))

	// bip39.FromEntropy turns each vector's known entropy into a real,
	// checksum-valid 24-word sentence. The role-specific constructors make
	// those sentences into the exact capabilities BatchGenerator.Generate consumes.
	batchWords := bip39.FromEntropy(batchEntropy).Words()
	if gotMnemonic, err := bip39.Parse(batchWords); err != nil || gotMnemonic.Entropy() != batchEntropy {
		t.Fatalf("bip39.FromEntropy/Parse round-trip failed for batch entropy: gotEntropy=%x err=%v", gotMnemonic.Entropy(), err)
	}
	recoveryWords := bip39.FromEntropy(recoveryEntropy).Words()
	if gotMnemonic, err := bip39.Parse(recoveryWords); err != nil || gotMnemonic.Entropy() != recoveryEntropy {
		t.Fatalf("bip39.FromEntropy/Parse round-trip failed for recovery entropy: gotEntropy=%x err=%v", gotMnemonic.Entropy(), err)
	}
	batch, err := DecodeBatchMnemonic(batchWords)
	if err != nil {
		t.Fatalf("DecodeBatchMnemonic: %v", err)
	}
	recovery, err := DecodeRecoveryCodeMnemonic(recoveryWords)
	if err != nil {
		t.Fatalf("DecodeRecoveryCodeMnemonic: %v", err)
	}
	batchNumber := BatchNumber(f.BatchNumber)

	for _, v := range f.WorkedExamples {
		t.Run(v.Name, func(t *testing.T) {
			b, err := createBatch(batch, recovery, batchNumber, v.EntryCount)
			if err != nil {
				t.Fatalf("Generate: unexpected error %v", err)
			}
			if b.Len() != v.EntryCount {
				t.Fatalf("Len() = %d, want %d", b.Len(), v.EntryCount)
			}

			encoded, err := b.Encode()
			if err != nil {
				t.Fatalf("Encode: unexpected error %v", err)
			}
			if hex.EncodeToString(encoded) != v.EncodedHex {
				t.Errorf("Encode() = %x, want %s", encoded, v.EncodedHex)
			}

			if got := b.Fingerprint(); got != v.Fingerprint {
				t.Errorf("Fingerprint() = %q, want %q", got, v.Fingerprint)
			}

			// DecodeBatch must independently reproduce the same
			// Fingerprint from the literal checked-in encoded bytes.
			decoded, err := DecodeBatch(mustHex(t, v.EncodedHex))
			if err != nil {
				t.Fatalf("DecodeBatch(literal vector bytes): unexpected error %v", err)
			}
			if got := decoded.Fingerprint(); got != v.Fingerprint {
				t.Errorf("DecodeBatch(literal).Fingerprint() = %q, want %q", got, v.Fingerprint)
			}
		})
	}
}

// TestVectorsBatchDecodeRejections pins every malformed Batch
// vector. DecodeBatch intentionally exposes one public parse error:
// ErrInvalidBatch.
func TestVectorsBatchDecodeRejections(t *testing.T) {
	var f batchVectorFile
	loadJSON(t, batchVectorsJSON, &f)
	if len(f.DecodeRejections) == 0 {
		t.Fatal("no batch decodeRejections vectors loaded")
	}

	for _, v := range f.DecodeRejections {
		t.Run(v.Name, func(t *testing.T) {
			got, err := DecodeBatch(mustHex(t, v.EncodedHex))
			if err != ErrInvalidBatch {
				t.Errorf("DecodeBatch(%s): err = %v, want ErrInvalidBatch", v.Name, err)
			}
			if !isZeroBatch(got) {
				t.Errorf("DecodeBatch(%s): got a non-zero Batch alongside an error", v.Name)
			}
		})
	}
}

// isZeroBatch reports whether b is the zero-value Batch --
// len(entries) == 0 is sufficient, mirroring Batch's own
// zero-value-invalid distinction (see batch.go).
func isZeroBatch(b Batch) bool {
	return b.version == 0 && b.batchNumber == 0 && len(b.entries) == 0
}

// TestVectorsRecoverUserKey pins BatchEntropy.RecoverUserKey against
// every checked-in vector in recover-user-key.v1.json.
func TestVectorsRecoverUserKey(t *testing.T) {
	var f recoverUserKeyVectorFile
	loadJSON(t, recoverUserKeyVectorsJSON, &f)
	if f.Version != 1 {
		t.Fatalf("recover-user-key vector: version = %d, want 1", f.Version)
	}
	if len(f.Vectors) == 0 {
		t.Fatal("no recoverUserKey vectors loaded")
	}

	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			var entropy [32]byte
			copy(entropy[:], mustHex(t, v.BatchEntropyHex))
			words := bip39.FromEntropy(entropy).Words()
			if parsed, err := bip39.Parse(words); err != nil || parsed.Entropy() != entropy {
				t.Fatalf("bip39.FromEntropy/Parse round-trip failed: gotEntropy=%x err=%v", parsed.Entropy(), err)
			}
			m, err := DecodeBatchMnemonic(words)
			if err != nil {
				t.Fatalf("DecodeBatchMnemonic: %v", err)
			}

			want := mustHex(t, v.UserKeyHex)

			got, err := m.RecoverUserKey(v.RecoveryCode)
			if err != nil {
				t.Fatalf("RecoverUserKey: unexpected error %v", err)
			}
			if !bytesEqual(got.Bytes(), want) {
				t.Errorf("RecoverUserKey = %x, want %x", got.Bytes(), want)
			}
		})
	}
}
