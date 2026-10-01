package derivation

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func FuzzDecodeBatch(f *testing.F) {
	valid, err := hex.DecodeString(workedTwoEntryHex)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte{})
	f.Add([]byte{1})
	f.Add(bytes.Repeat([]byte{0xff}, 64))

	f.Fuzz(func(t *testing.T, encoded []byte) {
		batch, err := DecodeBatch(encoded)
		if err != nil {
			return
		}

		roundTrip, err := batch.Encode()
		if err != nil {
			t.Fatalf("successfully decoded Batch cannot be encoded: %v", err)
		}
		if !bytes.Equal(roundTrip, encoded) {
			t.Fatalf("accepted non-canonical Batch: re-encoded bytes differ")
		}
		if batch.Fingerprint() == "" {
			t.Fatal("successfully decoded Batch has empty Fingerprint")
		}
		for i, entry := range batch.Entries() {
			if entry.Index() != EntryIndex(i+1) {
				t.Fatalf("Entry[%d].Index() = %d", i, entry.Index())
			}
			if entry.RecoveryCode() == "" || len(entry.UserKey().Bytes()) != secretSize {
				t.Fatalf("Entry[%d] exposes incomplete data", i)
			}
		}
	})
}
