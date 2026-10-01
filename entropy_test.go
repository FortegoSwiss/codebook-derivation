package derivation

import (
	"fmt"
	"strings"
	"testing"
)

var batchMnemonicFixtureWords = strings.Fields(
	"abandon abandon abandon abandon abandon abandon abandon abandon abandon " +
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon " +
		"abandon abandon abandon abandon abandon art",
)

func batchEntropyFixture(t *testing.T) BatchEntropy {
	t.Helper()
	if len(batchMnemonicFixtureWords) != 24 {
		t.Fatalf("test setup: fixture has %d words, want 24", len(batchMnemonicFixtureWords))
	}
	e, err := DecodeBatchMnemonic(batchMnemonicFixtureWords)
	if err != nil {
		t.Fatalf("test setup: DecodeBatchMnemonic: %v", err)
	}
	return e
}

var recoveryCodeMnemonicFixtureWords = strings.Fields(
	"legal winner thank year wave sausage worth useful legal winner " +
		"thank year wave sausage worth useful legal winner thank year " +
		"wave sausage worth title",
)

func recoveryCodeEntropyFixture(t *testing.T) RecoveryCodeEntropy {
	t.Helper()
	if len(recoveryCodeMnemonicFixtureWords) != 24 {
		t.Fatalf("test setup: fixture has %d words, want 24", len(recoveryCodeMnemonicFixtureWords))
	}
	e, err := DecodeRecoveryCodeMnemonic(recoveryCodeMnemonicFixtureWords)
	if err != nil {
		t.Fatalf("test setup: DecodeRecoveryCodeMnemonic: %v", err)
	}
	return e
}

func TestMnemonicConstructorsPreserveRoleAndZeroValueInvariants(t *testing.T) {
	batch, err := DecodeBatchMnemonic(batchMnemonicFixtureWords)
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := DecodeRecoveryCodeMnemonic(recoveryCodeMnemonicFixtureWords)
	if err != nil {
		t.Fatal(err)
	}

	if !batch.initialized || !recovery.initialized {
		t.Fatal("successful constructors must initialize their capabilities")
	}
	if batch.entropy != ([32]byte{}) {
		t.Fatal("test setup: batch fixture must represent valid all-zero entropy")
	}
	if (BatchEntropy{}).initialized || (RecoveryCodeEntropy{}).initialized {
		t.Fatal("mnemonic zero values must remain invalid")
	}

	if _, err := createBatch(BatchEntropy{}, recovery, BatchNumber(1), 1); err != ErrInvalidBatchEntropy {
		t.Errorf("zero batch entropy error = %v, want ErrInvalidBatchEntropy", err)
	}
	if _, err := createBatch(batch, RecoveryCodeEntropy{}, BatchNumber(1), 1); err != ErrInvalidRecoveryCodeEntropy {
		t.Errorf("zero recovery entropy error = %v, want ErrInvalidRecoveryCodeEntropy", err)
	}
}

func TestMnemonicSecretsNeverFormat(t *testing.T) {
	batch := batchEntropyFixture(t)
	recovery := recoveryCodeEntropyFixture(t)
	for _, secret := range []any{batch, recovery} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%x"} {
			got := fmt.Sprintf(format, secret)
			if !strings.Contains(got, "{REDACTED}") {
				t.Errorf("Sprintf(%q) = %q, want redacted output", format, got)
			}
			if strings.Contains(got, "abandon") || strings.Contains(got, "legal") {
				t.Errorf("Sprintf(%q) disclosed mnemonic material: %q", format, got)
			}
		}
	}
}
