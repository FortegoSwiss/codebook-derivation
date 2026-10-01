package transport

import (
	"bytes"
	"testing"
)

func FuzzOpen(f *testing.F) {
	keyBytes := bytes.Repeat([]byte{0x11}, keySize)
	key, err := NewKey(keyBytes)
	if err != nil {
		f.Fatal(err)
	}
	valid, err := sealEnvelope(key, bytes.Repeat([]byte{0x22}, nonceSize), []byte("payload"))
	if err != nil {
		f.Fatal(err)
	}

	f.Add(valid, keyBytes)
	f.Add([]byte{}, keyBytes)
	f.Add([]byte{envelopeVersion}, keyBytes)
	f.Add(valid, []byte{})

	f.Fuzz(func(t *testing.T, encoded, rawKey []byte) {
		key, err := NewKey(rawKey)
		if err != nil {
			return
		}
		plaintext, err := Open(encoded, key)
		if err != nil {
			return
		}

		roundTrip, err := sealEnvelope(key, encoded[1:1+nonceSize], plaintext)
		if err != nil {
			t.Fatalf("successfully opened envelope cannot be resealed: %v", err)
		}
		if !bytes.Equal(roundTrip, encoded) {
			t.Fatal("accepted non-canonical envelope: resealed bytes differ")
		}
	})
}
