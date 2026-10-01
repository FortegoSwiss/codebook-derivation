# Fortego CodeBook Derivation

This [Go](https://go.dev/doc/) library deterministically derives the key
material used by Fortego's backup service.

A [mnemonic, or seed phrase](https://bips.dev/39/), represents wallet key
material as words. [Bitcoin Improvement Proposal 39 (BIP-39)](https://bips.dev/39/) defines this
format. Fortego's [CodeBook](https://github.com/FortegoSwiss/codebook-cipher)
is a [substitution cipher](https://en.wikipedia.org/wiki/Substitution_cipher)
that lets users replace those words offline, without arithmetic.

Fortego's master secret is called the _RootKey_. Each user's CodeBooks are
derived from a user-specific key, the _UserKey_. Each UserKey combines
[entropy](https://csrc.nist.gov/glossary/term/entropy) derived from the
RootKey with additional entropy. That additional entropy is encoded in the
personal _RecoveryCode_ given to the user during onboarding.

The _RecoveryCode_ lets a user reconstruct their _UserKey_ and CodeBooks
without an operational Fortego service once the authentic _RootKey_ has been
made public. This design lets users regain
access to their CodeBooks even if the Fortego service ceases to exist.

A UserKey derives a 32-byte value called a `CodeBookSeed`, which the cipher
library uses to generate a CodeBook. A user can have multiple CodeBooks,
each selected by its own index.

For operations, Recovery Codes and UserKeys generated together are packaged
in a numbered [Batch](#batch-handoff-and-verification). Its identifying
number is the `BatchNumber`; each Recovery Code and UserKey pair forms one
Entry. A Batch contains these secrets in
[plaintext](https://csrc.nist.gov/glossary/term/plaintext).

An [air gap](https://csrc.nist.gov/glossary/term/air_gap) separates systems
from network communication. For confidential Batch transfers across it, a
[transport envelope](#transport-envelope) holds the encrypted bytes and the
data needed to check their integrity. A [Batch Fingerprint](#fingerprint)
is a short [digest](https://csrc.nist.gov/glossary/term/message_digest) of the
Batch's encoded contents; comparing it with an independently trusted value
helps confirm that the intended Batch arrived.

---

- [Use from Go](#use-from-go): generate a Batch and transfer it across an air gap.
- [Recovery model](#recovery-model): how the RootKey, Recovery Code, and CodeBooks relate.
- [Recovery Code format](#recovery-code-format): encoding, validation, and BatchNumber lookup.
- [Key derivation](#key-derivation): exact derivation parameters and mnemonic validation.
- [Batch handoff and verification](#batch-handoff-and-verification): binary encoding and content verification.
- [Transport envelope](#transport-envelope): encryption, framing, and size limits.
- [Test vectors](#test-vectors): conformance values and their provenance.

---

## Use from Go

### Quick start

Batch generation takes two independent 24-word English BIP-39 mnemonics:
one supplies the batch's entropy (`BatchEntropy`), and the other supplies
entropy for the Recovery Codes (`RecoveryCodeEntropy`).

All examples and test vectors are synthetic and must never be used for a wallet.
See [security policy](SECURITY.md) for reporting and review status.

Install the library:

```sh
go get github.com/FortegoSwiss/codebook-derivation
```

The example decodes those mnemonics from `batchWords` and `recoveryWords`,
generates 100 entries for batch number 1, then reads the first Entry:

```go
batchEntropy, err := derivation.DecodeBatchMnemonic(batchWords)
if err != nil {
	return err
}
recoveryEntropy, err := derivation.DecodeRecoveryCodeMnemonic(recoveryWords)
if err != nil {
	return err
}
generator := derivation.NewBatchGenerator(batchEntropy, recoveryEntropy, 1)
batch, err := generator.Generate(100)
if err != nil {
	return err
}
entry := batch.Entries()[0]
recoveryCode := entry.RecoveryCode()
userKey := entry.UserKey()
```

### Transfer a Batch across an air gap

To transfer a Batch across an air gap, use the separate `transport` package
to encrypt and authenticate the bytes. Transfer the envelope and its key
separately. Retain or communicate the expected Fingerprint through an
independent trusted channel, then compare it with the received Batch's
Fingerprint to confirm that this is the intended Batch.

```go
expectedFingerprint := batch.Fingerprint() // Store or communicate out of band.

encoded, err := batch.Encode()
if err != nil {
	return err
}
envelope, key, err := transport.Seal(encoded)
if err != nil {
	return err
}

opened, err := transport.Open(envelope, key)
if err != nil {
	return err
}
decoded, err := derivation.DecodeBatch(opened)
if err != nil {
	return err
}
if decoded.Fingerprint() != expectedFingerprint {
	return fmt.Errorf("batch fingerprint mismatch")
}
userKey := decoded.Entries()[0].UserKey()
```

[`Example`](example_test.go) is a complete runnable end-to-end example, including the
handoff to [`github.com/FortegoSwiss/codebook-cipher`](https://github.com/FortegoSwiss/codebook-cipher).

## Recovery model

Root-to-Batch derivation follows
[Bitcoin Improvement Proposal 85 (BIP-85): Deterministic Entropy From BIP32 Keychains](https://bips.dev/85/).
The batch's identifying number (`BatchNumber`) selects its entropy. A
UserKey then derives the CodeBookSeed used by the cipher library:

```text
RootKey (external)
  └─ BIP85(BatchNumber) → BatchEntropy

RecoveryCodeEntropy → RecoveryCode
BatchEntropy + RecoveryCode → UserKey → CodeBookSeed → CodeBook
```

The caller supplies the RootKey and is responsible for generating, storing,
and protecting it. BIP85 derives a separate 24-word English BIP-39 mnemonic
for each batch; the batch number is the BIP85 index.
The separate 24-word Recovery Code mnemonic is independent entropy used to
create Recovery Codes.

Once the RootKey is public, a user can combine it with their personal Recovery
Code to derive their UserKey and CodeBooks independently. A UserKey can derive
multiple CodeBooks: a non-zero `CodeBookIndex` selects a distinct 32-byte
CodeBook seed. Recovery requires the authentic published RootKey, the correct
Recovery Code and the backup's correct CodeBook index. Keep Recovery Codes and
derived keys confidential, and store CodeBooks separately from their enciphered
backups.

## Recovery Code format

### Purpose and contents

A Recovery Code is the user's personal contribution to independent recovery.
Its batch number determines the BIP85-derived BatchEntropy used with it to
derive one UserKey. It contains:

- **BatchNumber:** identifies the BIP85-derived BatchEntropy needed for recovery.
- **RecoveryCodeData:** user-specific recovery material.
- **Extension:** a field reserved for future wire extensions; fixed to `0` in v1.
- **[Cyclic redundancy check, ATM variant (CRC-10/ATM)](https://reveng.sourceforge.io/crc-catalogue/1-15.htm#crc.cat.crc-10-atm):**
  the 10-bit check used in Asynchronous Transfer Mode; detects accidental transcription or input errors. It does not authenticate
  the code.

### Display and validation

A Recovery Code is a canonical, uppercase
[Crockford Base32](https://www.crockford.com/base32.html) value: 30
ungrouped characters, or six groups of five for display. Parsing accepts
Crockford's `O`/`I`/`L` aliases, but canonical encoding never emits them.

The encoded form packs these fields [most-significant bit (MSB)](https://en.wikipedia.org/wiki/Bit_numbering) first into
one 150-bit bitstream:

```text
BatchNumber(10 bits) ‖ RecoveryCodeData(128 bits) ‖ Extension(2 bits) ‖ CRC-10(10 bits)
```

The bitstream is not byte-aligned, but its length is exactly divisible by
5 and therefore encodes as 30 Crockford Base32 characters with no padding. The canonical form
embedded in a Batch's encoded bytes is always the 30-character ungrouped
form. For display, the equivalent form has five literal hyphens after
characters 5, 10, 15, 20, and 25. Parsing accepts both forms.

CRC-10 is checked first, over the 140 protected bits, before `Extension` or
`BatchNumber` is inspected. A corrupted field is therefore caught by the CRC
before it can be misread as semantically invalid but well-formed.

- **CRC-10/ATM parameters** (RevEng "Catalogue of parametrised CRC
  algorithms"): polynomial `0x233`, initial value `0x000`, `RefIn = RefOut =
  false` (MSB-first, unreflected), `XorOut = 0x000`, computed bit-serially
  over the 140 protected bits.
- **Crockford Base32 alphabet:** `0123456789ABCDEFGHJKMNPQRSTVWXYZ`
  (excludes `I`, `L`, `O`, `U`). Decoding case-folds and applies the aliases
  `O→0`, `I,L→1`; `U` is never an alias and, like any other non-alphabet
  byte, is rejected.

### Read the BatchNumber before deriving BatchEntropy

Read the Recovery Code's `BatchNumber` before deriving `BatchEntropy`, for
example from a BIP-85 RootKey outside this package.
`BatchEntropy.RecoverUserKey` does not check whether the supplied entropy
belongs to the code's embedded batch number. It combines the supplied
entropy with the batch number in the code and returns a well-formed
`UserKey`. Entropy from the wrong batch therefore silently produces the
wrong UserKey instead of an error.

`DecodeRecoveryCode(recoveryCode string) (RecoveryCodeInfo, error)` parses
and CRC-validates a Recovery Code exactly as `RecoverUserKey` does
internally. It returns `RecoveryCodeInfo` with two accessors:

- `BatchNumber() BatchNumber`
- `Extension() uint8`

It does not expose full envelope parsing or `RecoveryCodeData`.
`RecoverUserKey` already consumes that data internally, and no planned
caller needs more than `BatchNumber` and `Extension` outside that function.

Both functions return the same [sentinel errors](https://go.dev/blog/go1.13-errors) for equivalent rejections:
`ErrRecoveryCodeLength`, `ErrRecoveryCodeHyphen`, `ErrRecoveryCodeChar`,
`ErrRecoveryCodeCRC`, `ErrRecoveryCodeExtension`, and `ErrInvalidBatchNumber`.
The last applies to a CRC-valid code whose embedded batch number is out of
range. Callers can therefore check the same error identities with either
function.

## Key derivation

The derivations use distinct context labels for distinct purposes, a
technique called [domain separation](https://www.rfc-editor.org/info/rfc5869/#section-3.2).
They use a [hash-based message authentication code (HMAC)](https://www.rfc-editor.org/info/rfc2104/)
inside the [HMAC-based Extract-and-Expand Key Derivation Function
(HKDF)](https://www.rfc-editor.org/info/rfc5869/), with the
[256-bit Secure Hash Algorithm (SHA-256)](https://csrc.nist.gov/pubs/fips/180-4/upd1/final).
The key derived from the batch mnemonic is called the BatchKey. The Recovery
Code mnemonic, batch number, and entry index produce RecoveryCodeData, which is encoded in the Recovery Code.
The BatchKey and RecoveryCodeData then produce exactly one UserKey.

The following rules and fixed test vectors (input/output examples) define the derivation and
encodings byte for byte. They are intended to support independent
implementations.

### Exact HKDF parameters

Every derivation below reduces to HKDF-SHA-256 Extract+Expand over a
[salt and context information (`info`)](https://www.rfc-editor.org/info/rfc5869/#section-2)
pair built the same way. The salt is an additional input to Extract; `info`
binds Expand to its intended context. Text fields use
[American Standard Code for Information Interchange (ASCII)](https://www.rfc-editor.org/info/rfc20/).
The formulas use [input keying material (IKM) and pseudorandom key (PRK)](https://www.rfc-editor.org/info/rfc5869/#section-2.2)
as defined in [Request for Comments 5869 (RFC 5869)](https://www.rfc-editor.org/info/rfc5869/). The `enc` function prefixes a byte sequence with
its length; `ctx` combines the protocol's domain label, a role label, and
any additional fields. Integer fields use
[big-endian byte order](https://en.wikipedia.org/wiki/Endianness):

```
enc(b)          = uint32-BE(len(b)) ‖ b
ctx(role, f...) = enc(ascii(Domain)) ‖ enc(ascii(role)) ‖ enc(f[0]) ‖ enc(f[1]) ‖ ...
Domain          = "fortego:codebook-derivation:v1"
```

`entropy` is a mnemonic's already-validated 256-bit BIP-39 entropy (below);
`batchNumber` and `entryIndex` are always encoded `u16`/`u32`
big-endian regardless of their narrower domains.

```
BatchKey (32 bytes), from the batch mnemonic's entropy:
  salt = ctx("batch-key-salt")
  info = ctx("batch-key", u8(1), u16(batchNumber))
  PRK  = HKDF-Extract(SHA-256, salt, IKM = entropy)
  BatchKey = HKDF-Expand(SHA-256, PRK, info, 32)

RecoveryCodeData (16 bytes), from the recovery-code mnemonic's entropy:
  salt = ctx("recovery-code-data-salt")
  info = ctx("recovery-code-data", u8(1), u16(batchNumber), u32(entryIndex))
  PRK  = HKDF-Extract(SHA-256, salt, IKM = entropy)
  RecoveryCodeData = HKDF-Expand(SHA-256, PRK, info, 16)

UserKey (32 bytes), combining the two above:
  salt = ctx("user-key-salt")
  IKM  = BatchKey ‖ RecoveryCodeData          // 32 + 16 = 48 bytes
  info = ctx("user-key", u8(1), u16(batchNumber), u8(0))  // Extension fixed 0
  PRK  = HKDF-Extract(SHA-256, salt, IKM)
  UserKey = HKDF-Expand(SHA-256, PRK, info, 32)

CodeBookSeed (32 bytes), from a UserKey and a non-zero CodeBookIndex:
  info = ctx("codebook-seed", u64(index))
  CodeBookSeed = HKDF-Expand(SHA-256, PRK = UserKey (used directly), info, 32)
```

`CodeBookSeed` skips a fresh Extract and uses `UserKey` directly as the PRK —
safe because `UserKey` is already uniformly random 32-byte HKDF output.

### Mnemonic validation

Both mnemonic inputs must be valid 24-word English BIP-39 mnemonics and yield
256 bits of entropy. For byte-exact interoperability, each word is
ASCII-trimmed and ASCII-lowercased (any byte outside `a-z` afterward is
rejected), then looked up in the fixed 2048-word BIP-39 English list for its
11-bit index. The 24 indices concatenated MSB-first yield 264 bits. The first
256 are candidate entropy; the last 8 must equal the top 8 bits of
SHA-256(candidate entropy), or validation fails.

## Batch handoff and verification

A Batch packages the Recovery Codes and UserKeys produced together. It is an
operational handoff artefact, not an input to independent recovery. Its
contents are plaintext, so use the transport envelope whenever it must be
transferred confidentially.

### Canonical Batch encoding

A Batch uses a fixed-width binary layout, not
[JavaScript Object Notation (JSON)](https://www.rfc-editor.org/info/rfc8259/).
The compact binary form therefore prioritizes unambiguous representation over
readability. There is exactly one derivation suite and one wire format, both identified by version
`1`, so the header carries a single version byte rather than two independent
version-like fields:

```
header = version(1 byte, = 1) ‖ batchNumber(2 bytes, big-endian) ‖ entryCount(4 bytes, big-endian)   // 7 bytes
entry  = recoveryCode(30 bytes, canonical ungrouped Crockford ASCII) ‖ userKey(32 bytes)              // 62 bytes
encoded = header ‖ entry[0] ‖ entry[1] ‖ ... ‖ entry[entryCount-1]
```

`entryCount` must be in `1..100,000`. An entry index is not itself a wire
field — it is always the entry's 1-based position, so there is nothing for it
to desynchronize from. The encoded length in bytes must equal:

```text
encodedLength = 7 + entryCount × 62
```

Input above 6,200,007 bytes is rejected before trusting any header field. A fixed-width layout has no whitespace,
field-order, or duplicate-field ambiguity the way this module's earlier
canonical-JSON encoding did, so the only remaining "not canonical, but
otherwise well-formed" case is an entry's 30-byte RecoveryCode field using a
structurally valid but non-canonical Crockford character (an `O`/`I`/`L`
alias in place of its canonical `0`/`1`). Such input is rejected: every
stored Recovery Code must already be the exact canonical rendering.

### Fingerprint

A Fingerprint is a truncated, unkeyed SHA-256 digest of the entire encoded
form — header fields and every Recovery Code and UserKey included, not just a
self-declared subset:

```
input       = ascii("fortego:codebook-derivation:v1:fingerprint:") ‖ encoded
Fingerprint = first 100 bits of SHA-256(input), Crockford Base32, grouped 4×5
```

A decoder validates only this binary schema. Before deriving CodeBooks from a
received Batch, compare its fingerprint with an expected value obtained through
an independently trusted channel. A Fingerprint is **not a
[digital signature](https://csrc.nist.gov/glossary/term/digital_signature)**:
it is an unkeyed digest with no notion of who produced `encoded`, so an
attacker able to alter both bytes and expected fingerprint together defeats this check
entirely. For a fixed pinned fingerprint, forging such a match has 100-bit
[second-preimage resistance](https://csrc.nist.gov/glossary/term/second_preimage_resistance);
it is still a probabilistic cryptographic check, not literal proof of
byte-for-byte equality. A Batch carries no
verification key or signature field.

## Transport envelope

The transport envelope authenticates and encrypts arbitrary bytes. It has no
concept of a Batch, its entries, or its Fingerprint. Anyone holding the transport
key can create an authenticated envelope; authentication under that key does
not by itself establish a trusted sender.

It uses the 256-bit [Advanced Encryption Standard
(AES)](https://csrc.nist.gov/pubs/fips/197/final) in [Galois/Counter Mode
(GCM)](https://csrc.nist.gov/pubs/sp/800/38/d/final). The version byte is
authenticated as [additional authenticated data (AAD)](https://www.rfc-editor.org/info/rfc5116/#section-2.1).
Each envelope also includes a [nonce](https://csrc.nist.gov/glossary/term/nonce)
and an [authentication tag](https://csrc.nist.gov/glossary/term/authentication_tag),
which GCM uses to verify integrity:

```
envelope = envelopeVersion(1 byte, = 1) ‖ nonce(12 bytes) ‖ AES-256-GCM(plaintext) ‖ tag(16 bytes)
AAD      = envelopeVersion
```

For every envelope, draw a fresh 32-byte key and a fresh 12-byte nonce from a
[cryptographically secure random source](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final). The key travels separately and is
never embedded in the envelope. `Seal` accepts at most 64 [mebibytes (MiB)](https://physics.nist.gov/cuu/Units/binary.html) of plaintext.
`Open` rejects a zero-value key, envelopes outside the 29-byte to
67,108,893-byte range, and an unrecognized `envelopeVersion` before processing
the nonce, ciphertext, or tag.

## Test vectors

The checked-in JSON vectors provide fixed conformance examples for each
protocol component. Implementations must reproduce their expected values;
they must not regenerate them during testing. Parts without dedicated vectors
are exercised by the vector sets that depend on them.

### Vector provenance

Fortego's protocol uses public building blocks: HKDF-SHA-256, AES-256-GCM,
CRC-10/ATM, Crockford Base32, and BIP-39. The domain-separation strings,
wire formats, and pinned byte values are Fortego's own design. Almost every
vector file is therefore **project-normative**: frozen output from this
implementation, rather than an independently published reference. Each
file's `description` field states its provenance.

The table identifies the external BIP-39 reference values and CRC-10/ATM
catalog check value. The files `bip39.v1.json`, `batch-key.v1.json`,
`recovery-code-data.v1.json`, `batch.v1.json`, and `recover-user-key.v1.json`
also reuse fixed entropy from the external BIP-39 source as known inputs.
Every value derived from those inputs is this project's own.

BIP-39 mnemonic validation, encoding, and seed derivation live in the public
[`bip39`](bip39) package (`github.com/FortegoSwiss/codebook-derivation/bip39`),
which was previously internal. Its [package documentation](bip39/bip39.go)
describes the supported subset (English, 24 words, 256-bit entropy, fixed
empty passphrase) and non-goals.

### Vector coverage

| Part | Vectors | Provenance |
|---|---|---|
| HKDF context framing (`ctx`, `enc`, `u8`/`u16`/`u32`/`u64`) and Extract/Expand | exercised indirectly by every vector set below | project-normative |
| BIP-39 mnemonic validation and entropy encoding (`bip39.Mnemonic.Parse`/`FromEntropy`) | [`bip39.v1.json`](bip39/bip39.v1.json) | **external**: all four mnemonic/entropy pairs reproduce the [Trezor python-mnemonic reference vectors](https://github.com/trezor/python-mnemonic/blob/master/vectors.json) (256-bit-entropy English cases) |
| BIP-39 mnemonic-to-seed derivation (`bip39.Mnemonic.Seed`) | [`bip39-seed.v1.json`](bip39/bip39-seed.v1.json) | mixed, per vector: `trezorPassphraseSeedHex` is **external** (the same Trezor python-mnemonic reference vectors, passphrase `"TREZOR"`); `emptyPassphraseSeedHex` (what `Seed` itself is pinned against) is project-derived -- computed with the identical [Password-Based Key Derivation Function 2 (PBKDF2)](https://www.rfc-editor.org/info/rfc8018/#section-5.2) formula and cross-checked for correctness against the external value on the same mnemonic, not itself an independently published number -- see the file's own `description` |
| BatchKey / RecoveryCodeData / UserKey derivation | [`batch-key.v1.json`](internal/derive/batch-key.v1.json), [`recovery-code-data.v1.json`](internal/derive/recovery-code-data.v1.json), [`user-key.v1.json`](internal/derive/user-key.v1.json) | project-normative (first two reuse external BIP-39 entropy as input; derived values are this project's own) |
| Recovery Code wire packing and CRC-10/ATM | [`recovery-code.v1.json`](internal/recoverycode/recovery-code.v1.json), [`crc10.v1.json`](internal/recoverycode/crc10.v1.json) | project-normative, except `crc10.v1.json`'s `catalogCheckValue`, which is the **external** well-known CRC-10/ATM catalog check value |
| Crockford Base32 alphabet | exercised indirectly by every vector set below | external convention, project-normative fixture values |
| CodeBookSeed derivation | [`codebook-seed.v1.json`](codebook-seed.v1.json) | project-normative |
| Canonical Batch encoding, Fingerprint | [`batch.v1.json`](batch.v1.json) | project-normative (reuses external BIP-39 entropy as input) |
| Recovery from BatchEntropy and Recovery Code | [`recover-user-key.v1.json`](recover-user-key.v1.json) | project-normative (reuses external BIP-39 entropy as input) |
| Transport envelope (AES-256-GCM framing) | [`transport.v1.json`](transport/transport.v1.json) | project-normative |

## License

Apache License 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
