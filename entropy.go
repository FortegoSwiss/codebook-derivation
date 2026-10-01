package derivation

import (
	"errors"
	"fmt"

	"github.com/FortegoSwiss/codebook-derivation/bip39"
	"github.com/FortegoSwiss/codebook-derivation/internal/derive"
	"github.com/FortegoSwiss/codebook-derivation/internal/recoverycode"
)

// Mnemonic validation errors are shared by both entropy roles.
var (
	// ErrMnemonicWordCount is returned when words does not contain exactly 24
	// elements.
	ErrMnemonicWordCount = bip39.ErrWordCount
	// ErrMnemonicWordChar is returned when a mnemonic word contains a character
	// outside ASCII lowercase letters.
	ErrMnemonicWordChar = bip39.ErrWordChar
	// ErrMnemonicWordUnknown is returned when a word is not in the fixed BIP-39
	// English word list.
	ErrMnemonicWordUnknown = bip39.ErrWordUnknown
	// ErrMnemonicChecksum is returned when a mnemonic's checksum does not match
	// its entropy.
	ErrMnemonicChecksum = bip39.ErrChecksum
)

// batchEntropyRole deliberately makes BatchEntropy non-convertible
// to RecoveryCodeEntropy. The two values have distinct
// operational roles even though both contain BIP-39-decoded entropy.
type batchEntropyRole struct{}

// ErrInvalidBatchEntropy is returned when an operation receives the
// zero-value BatchEntropy rather than a value returned by
// DecodeBatchMnemonic.
var ErrInvalidBatchEntropy = errors.New("derivation: BatchEntropy is invalid or zero-value")

// BatchEntropy is the validated 256-bit entropy decoded from a
// batch mnemonic. It supplies a Batch's BatchKey (see
// README.md's "Derivation" section), and is an opaque secret value.
//
// Its zero value is invalid. initialized distinguishes that value from valid
// all-zero BIP-39 entropy, which must remain representable.
type BatchEntropy struct {
	role        batchEntropyRole
	entropy     [32]byte
	initialized bool
}

// DecodeBatchMnemonic validates words as one 24-word BIP-39 English
// mnemonic and returns the batch entropy decoded from it. words is one
// already-split word per element and is never retained.
func DecodeBatchMnemonic(words []string) (BatchEntropy, error) {
	m, err := bip39.Parse(words)
	if err != nil {
		return BatchEntropy{}, err
	}
	return BatchEntropy{entropy: m.Entropy(), initialized: true}, nil
}

// Format prevents every fmt verb from disclosing entropy.
func (e BatchEntropy) Format(f fmt.State, verb rune) {
	redactedFormat(f, "BatchEntropy")
}

func (e BatchEntropy) batchKey(number BatchNumber) ([32]byte, error) {
	// Keep the role marker semantically live: its distinct type is the
	// conversion barrier between BatchEntropy and RecoveryCodeEntropy.
	_ = e.role
	if !e.initialized {
		return [32]byte{}, ErrInvalidBatchEntropy
	}
	return derive.DeriveBatchKey(e.entropy, uint16(number))
}

// RecoverUserKey reconstructs the UserKey carried by recoveryCode,
// independently of any Batch.
func (e BatchEntropy) RecoverUserKey(recoveryCode string) (UserKey, error) {
	if !e.initialized {
		return UserKey{}, ErrInvalidBatchEntropy
	}
	code, err := recoverycode.Parse(recoveryCode)
	if err != nil {
		return UserKey{}, translateRecoveryCodeParseError(err)
	}
	key, err := e.batchKey(BatchNumber(code.BatchNumber()))
	if err != nil {
		return UserKey{}, err
	}
	userKey, err := derive.DeriveUserKey(key, code.BatchNumber(), code.Data())
	if err != nil {
		return UserKey{}, err
	}
	return NewUserKey(userKey[:])
}

// recoveryCodeEntropyRole deliberately makes RecoveryCodeEntropy
// non-convertible to BatchEntropy.
type recoveryCodeEntropyRole struct{}

// ErrInvalidRecoveryCodeEntropy is returned when an operation receives the
// zero-value RecoveryCodeEntropy rather than a value returned by
// DecodeRecoveryCodeMnemonic.
var ErrInvalidRecoveryCodeEntropy = errors.New("derivation: RecoveryCodeEntropy is invalid or zero-value")

// RecoveryCodeEntropy is the validated 256-bit entropy decoded from a
// recovery-code mnemonic. It supplies a Batch's per-entry recovery-code
// material and is an opaque secret value.
//
// Its zero value is invalid. initialized distinguishes that value from valid
// all-zero BIP-39 entropy, which must remain representable.
type RecoveryCodeEntropy struct {
	role        recoveryCodeEntropyRole
	entropy     [32]byte
	initialized bool
}

// DecodeRecoveryCodeMnemonic validates words as one 24-word BIP-39 English
// mnemonic and returns the recovery-code entropy decoded from it. words is one
// already-split word per element and is never retained.
func DecodeRecoveryCodeMnemonic(words []string) (RecoveryCodeEntropy, error) {
	m, err := bip39.Parse(words)
	if err != nil {
		return RecoveryCodeEntropy{}, err
	}
	return RecoveryCodeEntropy{entropy: m.Entropy(), initialized: true}, nil
}

// Format prevents every fmt verb from disclosing entropy.
func (e RecoveryCodeEntropy) Format(f fmt.State, verb rune) {
	redactedFormat(f, "RecoveryCodeEntropy")
}

func (e RecoveryCodeEntropy) recoveryCodeData(number BatchNumber, index EntryIndex) ([16]byte, error) {
	// Keep the role marker semantically live: its distinct type is the
	// conversion barrier between RecoveryCodeEntropy and BatchEntropy.
	_ = e.role
	if !e.initialized {
		return [16]byte{}, ErrInvalidRecoveryCodeEntropy
	}
	return derive.DeriveRecoveryCodeData(e.entropy, uint16(number), uint32(index))
}
