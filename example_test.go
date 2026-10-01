package derivation_test

import (
	"fmt"
	"strings"

	"github.com/FortegoSwiss/codebook-cipher"
	derivation "github.com/FortegoSwiss/codebook-derivation"
	"github.com/FortegoSwiss/codebook-derivation/transport"
)

// This example creates, transports, and decodes a two-entry Batch, then
// derives a CodeBook from an entry's UserKey. The mnemonics are fixed
// fixtures; real mnemonics must come from a trusted, freshly generated source.
func Example() {
	batchWords := strings.Fields(
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon " +
			"abandon abandon abandon abandon abandon abandon abandon abandon abandon " +
			"abandon abandon abandon abandon abandon art",
	)
	recoveryWords := strings.Fields(
		"legal winner thank year wave sausage worth useful legal winner thank " +
			"year wave sausage worth useful legal winner thank year wave sausage " +
			"worth title",
	)

	batchEntropy, err := derivation.DecodeBatchMnemonic(batchWords)
	if err != nil {
		fmt.Println("batch mnemonic error:", err)
		return
	}
	recoveryEntropy, err := derivation.DecodeRecoveryCodeMnemonic(recoveryWords)
	if err != nil {
		fmt.Println("recovery mnemonic error:", err)
		return
	}

	generator := derivation.NewBatchGenerator(batchEntropy, recoveryEntropy, 1)
	batch, err := generator.Generate(2)
	if err != nil {
		fmt.Println("create batch error:", err)
		return
	}

	// The fingerprint is recomputed independently, out of band, from the
	// Batch just returned, and pinned for later comparison —
	// never trusted from the encoded bytes themselves.
	fingerprint := batch.Fingerprint()

	// Batch.Encode's output is confidential plaintext: it carries every
	// Entry's Recovery Code and UserKey in the clear, fingerprintable but not
	// encrypted. transport.Seal is the separate, optional step
	// that actually protects these bytes for one-time transport from the
	// ceremony system to the production system -- a fresh key and nonce every call, never
	// derived from, or embedded alongside, the Batch itself.
	encoded, err := batch.Encode()
	if err != nil {
		fmt.Println("encode error:", err)
		return
	}

	sealed, transportKey, err := transport.Seal(encoded)
	if err != nil {
		fmt.Println("seal error:", err)
		return
	}

	// sealed and transportKey are handed to whatever consumes them later
	// (typically over separate channels); here they are opened back
	// immediately to complete the round trip.
	opened, err := transport.Open(sealed, transportKey)
	if err != nil {
		fmt.Println("open error:", err)
		return
	}

	decoded, err := derivation.DecodeBatch(opened)
	if err != nil {
		fmt.Println("decode error:", err)
		return
	}
	if decoded.Fingerprint() != fingerprint {
		fmt.Println("fingerprint mismatch")
		return
	}

	entry := decoded.Entries()[0]

	seed, err := derivation.DeriveCodeBookSeed(entry.UserKey(), derivation.CodeBookIndex(1))
	if err != nil {
		fmt.Println("derive codebook seed error:", err)
		return
	}

	book, err := codebook.NewBIP39English(seed.Bytes())
	if err != nil {
		fmt.Println("codebook error:", err)
		return
	}

	_, err = book.Lookup("abandon")
	if err != nil {
		fmt.Println("word lookup error:", err)
		return
	}

	fmt.Println("Entries:", decoded.Len())
	fmt.Println("Lookup succeeded:", err == nil)
	// Output:
	// Entries: 2
	// Lookup succeeded: true
}
