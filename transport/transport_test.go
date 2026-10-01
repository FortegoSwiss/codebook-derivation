package transport

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// --- golden worked-example reproduction --------------------------------

// specArbitraryPlaintext is this package's own worked-example plaintext:
// deliberately arbitrary bytes, not a Batch encoding of any format
// (old or new) -- transport.Seal/Open authenticate and encrypt []byte only
// and never parse, know about, or reference Batch, Entry, or
// Fingerprint, so this fixture is chosen to demonstrate that independence
// rather than to resemble root's Batch wire schema. Its text is a frozen
// worked-example fixture. It names current vocabulary while remaining
// deliberately independent of the root package's actual Batch encoding.
const specArbitraryPlaintext = "Transport encrypts arbitrary bytes only; it has no concept of Batch, Entry, or Fingerprint."

const specExpectedEnvelopeHex = "" +
	"0122222222222222222222222243856627b3bff02d911fbb522bd490a56be0e" +
	"d8318e3c53f202e789129831c77200c8b6d3dc480e56e31990d8e393a15ddbd" +
	"be01fa1c199bc400ca96844badd30cef741471c03f6699181ab1789bde4a8cd" +
	"3c45b719ea93a3775ff486cc0e3c93f776f8860d0aa0a73d111"

func fixtureKey(t *testing.T) Key {
	t.Helper()
	k, err := NewKey(bytes.Repeat([]byte{0x11}, keySize))
	if err != nil {
		t.Fatalf("NewKey(fixture): unexpected error %v", err)
	}
	return k
}

func fixtureNonce() []byte {
	return bytes.Repeat([]byte{0x22}, nonceSize)
}

func TestSpecWorkedExampleEnvelope(t *testing.T) {
	if got, want := len(specArbitraryPlaintext), 91; got != want {
		t.Fatalf("fixture plaintext length = %d, want %d", got, want)
	}

	key := fixtureKey(t)
	nonce := fixtureNonce()

	envelope, err := sealEnvelope(key, nonce, []byte(specArbitraryPlaintext))
	if err != nil {
		t.Fatalf("sealEnvelope: unexpected error %v", err)
	}

	wantEnvelope, err := hex.DecodeString(specExpectedEnvelopeHex)
	if err != nil {
		t.Fatalf("decoding spec fixture hex: %v", err)
	}
	if want := 120; len(wantEnvelope) != want {
		t.Fatalf("spec fixture envelope length = %d, want %d", len(wantEnvelope), want)
	}

	if !bytes.Equal(envelope, wantEnvelope) {
		t.Fatalf("sealEnvelope(fixture key/nonce, spec plaintext) =\n  %x\nwant\n  %x", envelope, wantEnvelope)
	}

	// Round-trip via the public Open using the same fixture key.
	plaintext, err := Open(envelope, key)
	if err != nil {
		t.Fatalf("Open(spec envelope, fixture key): unexpected error %v", err)
	}
	if !bytes.Equal(plaintext, []byte(specArbitraryPlaintext)) {
		t.Fatalf("Open recovered %q, want %q", plaintext, specArbitraryPlaintext)
	}

	// Tamper check: flipping the ciphertext's last byte (part of
	// the GCM tag) must make authentication fail, with no plaintext
	// returned.
	tampered := append([]byte(nil), wantEnvelope...)
	tampered[len(tampered)-1] ^= 0xFF
	if pt, err := Open(tampered, key); err == nil {
		t.Fatalf("Open(tampered tag): got plaintext %q, want error", pt)
	} else if pt != nil {
		t.Fatalf("Open(tampered tag): got non-nil plaintext %q alongside error %v", pt, err)
	}

	// Wrong-key check: a different fixture key (0x33 * 32) must
	// also fail authentication against the same envelope.
	wrongKey, err := NewKey(bytes.Repeat([]byte{0x33}, keySize))
	if err != nil {
		t.Fatalf("NewKey(wrong fixture): unexpected error %v", err)
	}
	if pt, err := Open(wantEnvelope, wrongKey); err == nil {
		t.Fatalf("Open(wrong key): got plaintext %q, want error", pt)
	} else if pt != nil {
		t.Fatalf("Open(wrong key): got non-nil plaintext %q alongside error %v", pt, err)
	}
}

// --- Round-trip, wrong-key, and tamper tests over Seal/Open ----------------

func TestRoundTripSealOpen(t *testing.T) {
	cases := map[string][]byte{
		"empty":             {},
		"small":             []byte("hello, transport"),
		"large-under-limit": bytes.Repeat([]byte("The quick brown fox jumps over the lazy dog. "), 100_000), // ~4.6MB
	}
	for name, plaintext := range cases {
		t.Run(name, func(t *testing.T) {
			encoded, key, err := Seal(plaintext)
			if err != nil {
				t.Fatalf("Seal: unexpected error %v", err)
			}
			got, err := Open(encoded, key)
			if err != nil {
				t.Fatalf("Open: unexpected error %v", err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatalf("round-trip mismatch: got %d bytes, want %d bytes", len(got), len(plaintext))
			}
		})
	}
}

func TestOpenWrongKeyRejected(t *testing.T) {
	encoded, _, err := Seal([]byte("secret payload"))
	if err != nil {
		t.Fatalf("Seal: unexpected error %v", err)
	}
	var wrongKeyBytes [keySize]byte
	if _, err := rand.Read(wrongKeyBytes[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	wrongKey, err := NewKey(wrongKeyBytes[:])
	if err != nil {
		t.Fatalf("NewKey: unexpected error %v", err)
	}

	pt, err := Open(encoded, wrongKey)
	if err == nil {
		t.Fatalf("Open(wrong key): got plaintext %q, want error", pt)
	}
	if pt != nil {
		t.Fatalf("Open(wrong key): got non-nil plaintext %q alongside error %v", pt, err)
	}
	if !errors.Is(err, ErrAuthenticationFailed) {
		t.Errorf("Open(wrong key): err = %v, want ErrAuthenticationFailed", err)
	}
}

func TestOpenTamperRejected(t *testing.T) {
	plaintext := []byte("tamper me if you can")
	encoded, key, err := Seal(plaintext)
	if err != nil {
		t.Fatalf("Seal: unexpected error %v", err)
	}

	// Flip one bit at a handful of representative offsets: the version
	// byte, inside the nonce, inside the ciphertext body, and inside the
	// trailing GCM tag.
	offsets := []int{
		0,                // envelopeVersion
		1,                // first nonce byte
		1 + nonceSize/2,  // mid-nonce
		1 + nonceSize,    // first ciphertext byte
		len(encoded) - 1, // last tag byte
		len(encoded) - 8, // mid-tag
	}
	for _, off := range offsets {
		t.Run(fmt.Sprintf("offset_%d", off), func(t *testing.T) {
			tampered := append([]byte(nil), encoded...)
			tampered[off] ^= 0x01

			pt, err := Open(tampered, key)
			if err == nil {
				t.Fatalf("Open(tampered at %d): got plaintext %q, want error", off, pt)
			}
			if pt != nil {
				t.Fatalf("Open(tampered at %d): got non-nil plaintext %q alongside error %v", off, pt, err)
			}
		})
	}
}

// --- Envelope boundaries ------------------------------------------------------

func TestOpenRejectsUndersizedEnvelope(t *testing.T) {
	key := fixtureKey(t)
	for _, n := range []int{0, 1, 12, MinEnvelopeSize - 1} {
		encoded := make([]byte, n)
		pt, err := Open(encoded, key)
		if !errors.Is(err, ErrInvalidEnvelopeSize) {
			t.Errorf("Open(len %d): err = %v, want ErrInvalidEnvelopeSize", n, err)
		}
		if pt != nil {
			t.Errorf("Open(len %d): got non-nil plaintext", n)
		}
	}
}

func TestOpenAcceptsMinEnvelopeSize(t *testing.T) {
	// A zero-length plaintext sealed for real produces exactly
	// MinEnvelopeSize bytes; confirm Open accepts it and recovers empty
	// plaintext, rather than only testing the rejection boundary.
	encoded, key, err := Seal(nil)
	if err != nil {
		t.Fatalf("Seal(nil): unexpected error %v", err)
	}
	if len(encoded) != MinEnvelopeSize {
		t.Fatalf("Seal(nil) produced %d bytes, want MinEnvelopeSize = %d", len(encoded), MinEnvelopeSize)
	}
	got, err := Open(encoded, key)
	if err != nil {
		t.Fatalf("Open(MinEnvelopeSize): unexpected error %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Open(MinEnvelopeSize) plaintext = %v, want empty", got)
	}
}

func TestSealRejectsOversizedPlaintext(t *testing.T) {
	plaintext := make([]byte, MaxPlaintextSize+1)
	encoded, key, err := Seal(plaintext)
	if !errors.Is(err, ErrInvalidPlaintextSize) {
		t.Fatalf("Seal(MaxPlaintextSize+1): err = %v, want ErrInvalidPlaintextSize", err)
	}
	if encoded != nil {
		t.Errorf("Seal(MaxPlaintextSize+1): encoded is non-nil")
	}
	if key.initialized {
		t.Errorf("Seal(MaxPlaintextSize+1): returned an initialized key")
	}
}

func TestOpenRejectsOversizedEnvelope(t *testing.T) {
	encoded := make([]byte, MaxEnvelopeSize+1)
	pt, err := Open(encoded, fixtureKey(t))
	if !errors.Is(err, ErrInvalidEnvelopeSize) {
		t.Fatalf("Open(MaxEnvelopeSize+1): err = %v, want ErrInvalidEnvelopeSize", err)
	}
	if pt != nil {
		t.Errorf("Open(MaxEnvelopeSize+1): plaintext is non-nil")
	}
}

// --- Fresh randomness per call ----------------------------------------------

func TestRepeatedSealProducesFreshRandomness(t *testing.T) {
	plaintext := []byte("identical plaintext, every time")

	const n = 8
	encodedByCall := make([][]byte, n)
	keyByCall := make([]Key, n)
	for i := 0; i < n; i++ {
		encoded, key, err := Seal(plaintext)
		if err != nil {
			t.Fatalf("Seal[%d]: unexpected error %v", i, err)
		}
		encodedByCall[i] = encoded
		keyByCall[i] = key
	}

	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			if bytes.Equal(keyByCall[i].Bytes(), keyByCall[j].Bytes()) {
				t.Errorf("Seal[%d] and Seal[%d] produced identical keys", i, j)
			}
			nonceI := encodedByCall[i][1 : 1+nonceSize]
			nonceJ := encodedByCall[j][1 : 1+nonceSize]
			if bytes.Equal(nonceI, nonceJ) {
				t.Errorf("Seal[%d] and Seal[%d] produced identical nonces", i, j)
			}
			if bytes.Equal(encodedByCall[i], encodedByCall[j]) {
				t.Errorf("Seal[%d] and Seal[%d] produced identical encoded envelopes", i, j)
			}
		}
		// Every call must still round-trip correctly under its own key.
		got, err := Open(encodedByCall[i], keyByCall[i])
		if err != nil {
			t.Fatalf("Open[%d]: unexpected error %v", i, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Errorf("Open[%d]: round-trip mismatch", i)
		}
	}
}

// --- Concurrency ------------------------------------------------------------

func TestConcurrentSealOpen(t *testing.T) {
	const workers = 32
	var wg sync.WaitGroup
	errCh := make(chan error, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			plaintext := []byte(fmt.Sprintf("worker-%d payload", i))
			encoded, key, err := Seal(plaintext)
			if err != nil {
				errCh <- fmt.Errorf("worker %d: Seal: %w", i, err)
				return
			}
			got, err := Open(encoded, key)
			if err != nil {
				errCh <- fmt.Errorf("worker %d: Open: %w", i, err)
				return
			}
			if !bytes.Equal(got, plaintext) {
				errCh <- fmt.Errorf("worker %d: round-trip mismatch", i)
				return
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

// --- Key secret-type shape ---------------------------------------------------

func TestNewKeySizeBoundaries(t *testing.T) {
	for _, n := range []int{0, 1, 16, 31, 33, 64, 1000} {
		if _, err := NewKey(make([]byte, n)); !errors.Is(err, ErrInvalidKeySize) {
			t.Errorf("NewKey(len %d): err = %v, want ErrInvalidKeySize", n, err)
		}
	}

	b := make([]byte, keySize)
	for i := range b {
		b[i] = byte(i)
	}
	k, err := NewKey(b)
	if err != nil {
		t.Fatalf("NewKey(32 bytes): unexpected error %v", err)
	}
	if got := k.Bytes(); !bytes.Equal(got, b) {
		t.Errorf("Bytes() = %v, want %v", got, b)
	}
}

func TestNewKeyDoesNotAliasInput(t *testing.T) {
	orig := make([]byte, keySize)
	for i := range orig {
		orig[i] = byte(i)
	}
	input := append([]byte(nil), orig...)

	k, err := NewKey(input)
	if err != nil {
		t.Fatal(err)
	}
	for i := range input {
		input[i] ^= 0xFF
	}
	if got := k.Bytes(); !bytes.Equal(got, orig) {
		t.Errorf("mutating input after construction changed the value: got %v, want %v", got, orig)
	}

	b1 := k.Bytes()
	for i := range b1 {
		b1[i] ^= 0xFF
	}
	b2 := k.Bytes()
	if !bytes.Equal(b2, orig) {
		t.Errorf("mutating a returned slice changed internal state: got %v, want %v", b2, orig)
	}
}

func TestKeyNeverFormatsSecretBytes(t *testing.T) {
	const secretByte = 0xCD
	real := make([]byte, keySize)
	for i := range real {
		real[i] = secretByte
	}
	k, err := NewKey(real)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := any(k).(fmt.Stringer); ok {
		t.Error("Key must not implement fmt.Stringer")
	}

	const want = "transport.Key{REDACTED}"
	for _, verb := range []string{"%v", "%+v", "%s", "%#v", "%x", "%X", "%q", "%d"} {
		if got := fmt.Sprintf(verb, k); got != want {
			t.Errorf("Sprintf(%q, k) = %q, want %q", verb, got, want)
		}
	}
	if got := fmt.Sprintf("wrapped: %v", k); !strings.HasSuffix(got, want) {
		t.Errorf("error wrapping leaked: %q", got)
	}

	// The key must not appear anywhere in Seal/Open's error output either.
	badEncoded := []byte{0xFF} // triggers ErrInvalidEnvelopeSize
	_, err = Open(badEncoded, k)
	if err == nil {
		t.Fatal("Open(too-short envelope): want error")
	}
	if strings.Contains(err.Error(), fmt.Sprintf("%x", real)) {
		t.Errorf("error message leaked key bytes: %q", err.Error())
	}
}

func TestKeyZeroValue(t *testing.T) {
	var k Key
	if got := k.Bytes(); got != nil {
		t.Errorf("zero-value Key.Bytes() = %x, want nil", got)
	}

	encoded, validKey, err := Seal([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(encoded, k); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("Open(valid envelope, zero-value Key): err = %v, want ErrInvalidKey", err)
	}
	if _, err := Open(encoded, validKey); err != nil {
		t.Errorf("Open(valid envelope, initialized Key): unexpected error %v", err)
	}
}

func TestExplicitAllZeroKeyIsValid(t *testing.T) {
	key, err := NewKey(make([]byte, keySize))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := sealEnvelope(key, fixtureNonce(), []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(envelope, key)
	if err != nil {
		t.Fatalf("Open with explicit all-zero Key: unexpected error %v", err)
	}
	if string(got) != "payload" {
		t.Errorf("Open with explicit all-zero Key = %q, want payload", got)
	}
}
