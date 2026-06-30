package verification

import (
	"errors"
	"testing"

	"github.com/GoCodeAlone/encrypted-spaces-go/operationlog"
)

func TestFakeVerifierReportsNonProduction(t *testing.T) {
	verifier := NewFakeVerifier()

	report, err := verifier.VerifyOperation(FakeProof{
		OperationID: "op-1",
		Digest:      "sha256:test",
		Proof:       []byte("fake-proof"),
	})
	if err != nil {
		t.Fatalf("VerifyOperation returned error: %v", err)
	}
	if report.ProductionReady {
		t.Fatal("fake verifier reported production ready")
	}
	if !report.Accepted {
		t.Fatal("fake verifier did not accept fake proof")
	}
	if report.OperationID != operationlog.OperationID("op-1") {
		t.Fatalf("OperationID = %q, want op-1", report.OperationID)
	}
}

func TestFakeVerifierRejectsMalformedProof(t *testing.T) {
	verifier := NewFakeVerifier()

	_, err := verifier.VerifyOperation(FakeProof{
		OperationID: "op-1",
		Digest:      "sha256:test",
		Proof:       []byte("not-a-fake-proof"),
	})
	if !errors.Is(err, ErrMalformedProof) {
		t.Fatalf("VerifyOperation malformed error = %v, want ErrMalformedProof", err)
	}
}
