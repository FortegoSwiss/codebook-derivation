package transport

import (
	"bytes"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
)

//go:embed transport.v1.json
var transportVectorsJSON []byte

type transportVectorFile struct {
	Version          int    `json:"version"`
	KeyHex           string `json:"keyHex"`
	NonceHex         string `json:"nonceHex"`
	AADHex           string `json:"aadHex"`
	PlaintextHex     string `json:"plaintextHex"`
	CiphertextHex    string `json:"ciphertextHex"`
	EnvelopeHex      string `json:"envelopeHex"`
	MinEnvelopeSize  int    `json:"minEnvelopeSize"`
	MaxPlaintextSize int    `json:"maxPlaintextSize"`
	MaxEnvelopeSize  int    `json:"maxEnvelopeSize"`
	Rejections       []struct {
		Name        string `json:"name"`
		EnvelopeHex string `json:"envelopeHex"`
		KeyHex      string `json:"keyHex"`
		WantError   string `json:"wantError"`
	} `json:"rejections"`
}

func loadTransportVectors(t *testing.T) transportVectorFile {
	t.Helper()
	var f transportVectorFile
	if err := json.Unmarshal(transportVectorsJSON, &f); err != nil {
		t.Fatalf("loading transport vectors: %v", err)
	}
	return f
}

// mustHexBytes decodes s as hex or fails the test; a small local helper
// mirroring the root package's own mustHex, since this package intentionally
// does not import the root package.
func mustHexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q): %v", s, err)
	}
	return b
}

// TestVectorsTransportWorkedExample pins Seal/Open's fixed key/nonce
// worked example against transport.v1.json. Every
// field is asserted: key, nonce, plaintext, ciphertext, and the full
// envelope, plus the documented size-limit constants and a round trip
// through the public Open.
func TestVectorsTransportWorkedExample(t *testing.T) {
	f := loadTransportVectors(t)
	if f.Version != 1 {
		t.Fatalf("transport vector: version = %d, want 1", f.Version)
	}
	if f.MinEnvelopeSize != MinEnvelopeSize {
		t.Errorf("minEnvelopeSize = %d, want %d", f.MinEnvelopeSize, MinEnvelopeSize)
	}
	if f.MaxPlaintextSize != MaxPlaintextSize {
		t.Errorf("maxPlaintextSize = %d, want %d", f.MaxPlaintextSize, MaxPlaintextSize)
	}
	if f.MaxEnvelopeSize != MaxEnvelopeSize {
		t.Errorf("maxEnvelopeSize = %d, want %d", f.MaxEnvelopeSize, MaxEnvelopeSize)
	}

	keyBytes := mustHexBytes(t, f.KeyHex)
	key, err := NewKey(keyBytes)
	if err != nil {
		t.Fatalf("NewKey: unexpected error %v", err)
	}
	nonce := mustHexBytes(t, f.NonceHex)
	aad := mustHexBytes(t, f.AADHex)
	plaintext := mustHexBytes(t, f.PlaintextHex)
	wantCiphertext := mustHexBytes(t, f.CiphertextHex)
	wantEnvelope := mustHexBytes(t, f.EnvelopeHex)

	envelope, err := sealEnvelope(key, nonce, plaintext)
	if err != nil {
		t.Fatalf("sealEnvelope: unexpected error %v", err)
	}
	if !bytes.Equal(envelope, wantEnvelope) {
		t.Fatalf("sealEnvelope = %x, want %x", envelope, wantEnvelope)
	}
	if !bytes.Equal(aad, envelope[:1]) {
		t.Errorf("AAD = %x, want encoded envelope version %x", aad, envelope[:1])
	}
	if gotCiphertext := envelope[1+nonceSize:]; !bytes.Equal(gotCiphertext, wantCiphertext) {
		t.Errorf("ciphertext = %x, want %x", gotCiphertext, wantCiphertext)
	}

	got, err := Open(envelope, key)
	if err != nil {
		t.Fatalf("Open: unexpected error %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("Open recovered %x, want %x", got, plaintext)
	}
}

// transportRejectionErrors maps transport.v1.json's wantError
// names to this package's own sentinel errors.
var transportRejectionErrors = map[string]error{
	"ErrAuthenticationFailed": ErrAuthenticationFailed,
	"ErrUnrecognizedVersion":  ErrUnrecognizedVersion,
	"ErrInvalidEnvelopeSize":  ErrInvalidEnvelopeSize,
}

// TestVectorsTransportRejections pins Open's rejection rules (see
// README.md's "Transport envelope") against every checked-in rejection vector in
// transport.v1.json -- each an independent single-defect
// mutation of the worked envelope, matching the exact sentinel error named
// by wantError.
func TestVectorsTransportRejections(t *testing.T) {
	f := loadTransportVectors(t)
	if len(f.Rejections) == 0 {
		t.Fatal("no transport rejection vectors loaded")
	}

	for _, v := range f.Rejections {
		t.Run(v.Name, func(t *testing.T) {
			want, ok := transportRejectionErrors[v.WantError]
			if !ok {
				t.Fatalf("vector %q: unknown wantError name %q", v.Name, v.WantError)
			}
			envelope := mustHexBytes(t, v.EnvelopeHex)
			keyBytes := mustHexBytes(t, v.KeyHex)
			key, err := NewKey(keyBytes)
			if err != nil {
				t.Fatalf("NewKey: unexpected error %v", err)
			}

			pt, err := Open(envelope, key)
			if err == nil {
				t.Fatalf("Open(%s): expected error, got nil", v.Name)
			}
			if !errors.Is(err, want) {
				t.Errorf("Open(%s): err = %v, want wrapping %v", v.Name, err, want)
			}
			if pt != nil {
				t.Errorf("Open(%s): got non-nil plaintext alongside an error", v.Name)
			}
		})
	}
}
