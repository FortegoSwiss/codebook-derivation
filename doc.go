// Package derivation creates and verifies Fortego CodeBook batches.
//
// BatchGenerator.Generate derives RecoveryCode and UserKey entries from
// role-specific 24-word BIP-39 English mnemonic entropy. DecodeBatch
// validates an encoded Batch.
// BatchEntropy.RecoverUserKey derives a UserKey directly from
// a recovery code. Encoded Batch bytes can be encrypted for transport with
// the independent transport subpackage.
//
// This package validates mnemonic checksums and extracts 32-byte entropy. It
// does not generate mnemonics, allocate BatchNumber values, or implement storage,
// ceremony, or CLI operations. See README.md for usage and
// reference behaviour.
package derivation
