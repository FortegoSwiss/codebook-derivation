package derivation

import (
	"errors"
	"fmt"
	"io"

	"github.com/FortegoSwiss/codebook-derivation/internal/hkdf"
)

// MaxEntriesPerBatch is the maximum number of Entry values a single Batch
// may contain: BatchGenerator.Generate's size parameter domain, 1..MaxEntriesPerBatch.
// Named for Entry/BatchGenerator's v1 vocabulary — the prior draft's equivalent constant
// (MaxSlotsPerGeneration) no longer exists in this package; Git history is the archive for it.
const MaxEntriesPerBatch = 100_000

var (
	// ErrInvalidBatchNumber is returned when a BatchNumber value is 0 or
	// greater than 1023: BatchNumber's domain is fixed at 10 bits by
	// the RecoveryCode wire format's total bit budget (see README.md's
	// "The Recovery Code" section), not chosen freely here. BatchNumber
	// has no constructor of its own — a defined type over uint16, an
	// already-valid value can be written directly as BatchNumber(1) —
	// so this error surfaces when BatchGenerator.Generate first checks that
	// domain. It is also what DecodeRecoveryCode and RecoverUserKey return
	// for a CRC-valid Recovery Code whose embedded BatchNumber is out of
	// range (batch.go's translateRecoveryCodeParseError translates
	// internal/recoverycode's own, textually-identical-but-distinct error
	// value to this one), so errors.Is(err, ErrInvalidBatchNumber) succeeds
	// regardless of which of the three rejects a given BatchNumber.
	ErrInvalidBatchNumber = errors.New("derivation: BatchNumber must be in 1..1023")
)

// BatchNumber is the globally unique, monotonic, never-reused batch
// identifier assigned by the out-of-scope Company/root-to-batch
// allocation process and bound verbatim into every HKDF context that
// derives from it (see README.md's "Derivation" section). Its domain is fixed
// at 10 bits (1..1023) by the RecoveryCode wire format's total bit budget,
// not chosen freely here; this library never allocates, reserves or looks
// up a BatchNumber — a caller passing an unallocated or already-used
// BatchNumber is out of scope to detect.
//
// BatchNumber is a defined type over uint16: an already-valid constant may be
// written directly as BatchNumber(1).
type BatchNumber uint16

func (b BatchNumber) valid() bool {
	return b >= 1 && b <= 1023
}

// EntryIndex is the 1-based, contiguous, per-batch position of a single
// Entry within a Batch, assigned sequentially by BatchGenerator.Generate while
// constructing one Batch. It replaces the prior draft's SlotOrdinal:
// same uint32 type, same 1..MaxEntriesPerBatch domain, only the name
// changed to match Entry replacing Slot.
//
// EntryIndex is a defined type over uint32: an already-valid constant may
// be written directly as EntryIndex(1).
type EntryIndex uint32

func (i EntryIndex) valid() bool {
	return i >= 1 && i <= MaxEntriesPerBatch
}

// ErrInvalidCodeBookIndex is returned by NewCodeBookIndex when the value
// is 0.
var ErrInvalidCodeBookIndex = errors.New("derivation: CodeBookIndex must not be zero")

// CodeBookIndex is the 1-based, per-user sequence number of a derived
// CodeBook. Its domain is 1..2^64-1; 0 is reserved and invalid. It
// is not a secret type. It is not constrained by the RecoveryCode wire
// format; it is consumed only by the UserKey -> CodeBookSeed handoff
// (see README.md's "Derivation" section).
//
// CodeBookIndex is a defined type over uint64: an already-valid constant
// may be written directly as CodeBookIndex(1).
type CodeBookIndex uint64

// NewCodeBookIndex constructs a CodeBookIndex from v. Zero is rejected with
// ErrInvalidCodeBookIndex; NewCodeBookIndex never panics.
func NewCodeBookIndex(v uint64) (CodeBookIndex, error) {
	if v == 0 {
		return 0, ErrInvalidCodeBookIndex
	}
	return CodeBookIndex(v), nil
}

func (i CodeBookIndex) valid() bool {
	return i != 0
}

// secretSize is the exact, required length in bytes of every 256-bit secret
// type defined in this package.
const secretSize = 32

// ErrInvalidUserKeySize is returned by NewUserKey when the input is
// not exactly 32 bytes long.
var ErrInvalidUserKeySize = errors.New("derivation: UserKey must be exactly 32 bytes")

// ErrInvalidUserKey is returned when an operation receives a zero-value
// UserKey rather than one returned by NewUserKey, Batch generation, recovery,
// or Batch decoding.
var ErrInvalidUserKey = errors.New("derivation: UserKey is invalid or zero-value")

// UserKey is the 32-byte key combining a batch's BatchKey and an
// Entry's RecoveryCodeData (see README.md's "Derivation" section for the exact
// derivation). It is a secret type: no exported field, no implicit
// String/Text/JSON representation, and its bytes are obtainable only via the
// explicit, copying Bytes method. Its zero value is invalid; NewUserKey still
// accepts an explicit 32-byte all-zero key.
type UserKey struct {
	b           [secretSize]byte
	initialized bool
}

// NewUserKey constructs a UserKey from exactly 32 bytes. Any other
// length is rejected with ErrInvalidUserKeySize; NewUserKey never
// panics. b is not retained.
func NewUserKey(b []byte) (UserKey, error) {
	if len(b) != secretSize {
		return UserKey{}, ErrInvalidUserKeySize
	}
	var k UserKey
	copy(k.b[:], b)
	k.initialized = true
	return k, nil
}

// Bytes returns a defensive copy of the key's 32 bytes. Mutating the
// returned slice never changes k. It returns nil for a zero-value UserKey.
func (k UserKey) Bytes() []byte {
	if !k.initialized {
		return nil
	}
	out := make([]byte, secretSize)
	copy(out, k.b[:])
	return out
}

// Format implements fmt.Formatter so that no verb — %v, %+v, %s, %x, %#v or
// any other — ever renders k's key bytes, including when k is printed
// directly or wrapped in an error. UserKey deliberately does not
// implement fmt.Stringer: Format alone controls all fmt output.
func (k UserKey) Format(f fmt.State, verb rune) {
	redactedFormat(f, "UserKey")
}

// redactedFormat writes a fixed, content-free placeholder for typeName to f,
// regardless of verb or flags. It is the single implementation behind every
// secret type's Format method in this package.
func redactedFormat(f fmt.State, typeName string) {
	_, _ = io.WriteString(f, "derivation.")
	_, _ = io.WriteString(f, typeName)
	_, _ = io.WriteString(f, "{REDACTED}")
}

// ErrInvalidCodeBookSeedSize is returned by NewCodeBookSeed when the input is
// not exactly 32 bytes long.
var ErrInvalidCodeBookSeedSize = errors.New("derivation: CodeBookSeed must be exactly 32 bytes")

// CodeBookSeed is the 32-byte value HKDF-derived (see README.md's
// "Derivation" section) from a UserKey and a CodeBookIndex. It is a secret type: no
// exported fields and no implicit text or JSON representation. Its zero value
// is invalid; NewCodeBookSeed still accepts an explicit 32-byte all-zero seed.
//
// CodeBookSeed.Bytes() is the explicit, copying accessor a caller passes to
// github.com/FortegoSwiss/codebook-cipher's New or NewBIP39English constructors;
// codebook performs no further derivation on the bytes it receives.
type CodeBookSeed struct {
	b           [secretSize]byte
	initialized bool
}

// NewCodeBookSeed constructs a CodeBookSeed from exactly 32 bytes. Any other
// length is rejected with ErrInvalidCodeBookSeedSize; NewCodeBookSeed never
// panics. b is not retained.
func NewCodeBookSeed(b []byte) (CodeBookSeed, error) {
	if len(b) != secretSize {
		return CodeBookSeed{}, ErrInvalidCodeBookSeedSize
	}
	var s CodeBookSeed
	copy(s.b[:], b)
	s.initialized = true
	return s, nil
}

// Bytes returns a defensive copy of the seed's 32 bytes. It returns nil for
// a zero-value CodeBookSeed.
func (s CodeBookSeed) Bytes() []byte {
	if !s.initialized {
		return nil
	}
	out := make([]byte, secretSize)
	copy(out, s.b[:])
	return out
}

// Format implements fmt.Formatter and redacts every presentation of s.
func (s CodeBookSeed) Format(f fmt.State, verb rune) {
	redactedFormat(f, "CodeBookSeed")
}

// DeriveCodeBookSeed computes the CodeBookSeed HKDF-derived (see README.md's
// "Derivation" section) from key and index:
//
//	info = ctx("codebook-seed", u64(index))
//	CodeBookSeed = HKDF-Expand(SHA-256, PRK = key (used directly), info, 32)
//
// CodeBookSeed is derived by HKDF-Expand only (no fresh Extract), using
// UserKey directly as the PRK. This is safe because UserKey is a
// uniformly random 32-byte value produced by HKDF Extract+Expand.
// The info field uses this package's binary ctx()/u64 convention (internal/hkdf).
//
// DeriveCodeBookSeed rejects index == 0 with ErrInvalidCodeBookIndex.
// NewCodeBookIndex already enforces this at construction time, but a caller
// outside this package can still produce a zero CodeBookIndex via a direct
// type conversion (CodeBookIndex(0)), so this check is re-applied here
// defensively rather than trusted from the type alone. DeriveCodeBookSeed is
// pure and deterministic: the same key and index always produce the same
// CodeBookSeed, and no other input participates. It never panics.
func DeriveCodeBookSeed(key UserKey, index CodeBookIndex) (CodeBookSeed, error) {
	if !key.initialized {
		return CodeBookSeed{}, ErrInvalidUserKey
	}
	if !index.valid() {
		return CodeBookSeed{}, ErrInvalidCodeBookIndex
	}

	info := hkdf.Ctx("codebook-seed", hkdf.U64(uint64(index)))

	okm, err := hkdf.Expand(key.Bytes(), info, secretSize)
	if err != nil {
		return CodeBookSeed{}, err
	}
	return NewCodeBookSeed(okm)
}
