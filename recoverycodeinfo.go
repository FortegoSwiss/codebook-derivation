package derivation

import (
	"github.com/FortegoSwiss/codebook-derivation/internal/recoverycode"
)

// RecoveryCodeInfo is the structural information DecodeRecoveryCode exposes
// from a Recovery Code (see README.md's "The Recovery Code" section). It
// deliberately stops at BatchNumber and Extension: no planned caller needs
// raw RecoveryCodeData outside RecoverUserKey, which already consumes it
// internally, so RecoveryCodeInfo must not widen beyond the need that
// motivates it.
//
// RecoveryCodeInfo has no public constructor; the only way to obtain one is
// DecodeRecoveryCode.
type RecoveryCodeInfo struct {
	batchNumber BatchNumber
	extension   uint8
}

// BatchNumber returns i's BatchNumber field.
func (i RecoveryCodeInfo) BatchNumber() BatchNumber { return i.batchNumber }

// Extension returns i's Extension field: reserved, always 0 in v1.
func (i RecoveryCodeInfo) Extension() uint8 { return i.extension }

// DecodeRecoveryCode parses and CRC-validates recoveryCode's envelope
// exactly as RecoverUserKey does internally, and returns its structural
// fields. It does not expose RecoveryCodeData: no planned caller needs it
// outside RecoverUserKey, which already consumes it internally.
//
// This exists because RecoverUserKey does not cross-check that the
// BatchEntropy it is given actually corresponds to recoveryCode's own
// embedded BatchNumber -- it combines whatever BatchEntropy it receives with
// whatever BatchNumber the code claims, and returns a well-formed UserKey
// regardless, so a caller deriving BatchEntropy for the wrong batch gets a
// silently wrong UserKey back, not an error. A caller that must derive
// BatchEntropy itself (for example from a BIP-85 RootKey, entirely outside
// this package) should call DecodeRecoveryCode first, use the returned
// BatchNumber to derive the matching BatchEntropy, and only then call
// RecoverUserKey.
//
// DecodeRecoveryCode returns the same sentinel errors RecoverUserKey
// returns for the equivalent rejection -- ErrRecoveryCodeLength,
// ErrRecoveryCodeHyphen, ErrRecoveryCodeChar, ErrRecoveryCodeCRC,
// ErrRecoveryCodeExtension, and ErrInvalidBatchNumber (for a CRC-valid code
// whose embedded BatchNumber is out of range) -- so callers get identical
// error identity regardless of which function rejected the code.
// DecodeRecoveryCode never panics.
func DecodeRecoveryCode(recoveryCode string) (RecoveryCodeInfo, error) {
	code, err := recoverycode.Parse(recoveryCode)
	if err != nil {
		return RecoveryCodeInfo{}, translateRecoveryCodeParseError(err)
	}
	return RecoveryCodeInfo{
		batchNumber: BatchNumber(code.BatchNumber()),
		extension:   code.Extension(),
	}, nil
}
