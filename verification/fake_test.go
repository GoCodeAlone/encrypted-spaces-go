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

func TestProofCoverageReportMarksBackupAndSVRGaps(t *testing.T) {
	report := ProofCoverageReport()
	want := map[string]string{
		"zkgroup":        "vector-backed",
		"zkcredential":   "vector-backed",
		"poksho":         "vector-backed",
		"keytrans":       "vector-backed",
		"message-backup": "deferred",
		"svr-svrb":       "deferred",
	}
	for _, row := range report.Rows {
		status, ok := want[row.Domain]
		if !ok {
			continue
		}
		delete(want, row.Domain)
		if row.Status != status {
			t.Fatalf("%s status = %q, want %s", row.Domain, row.Status, status)
		}
		if row.Status == "vector-backed" && row.Vector == "" {
			t.Fatalf("%s missing vector", row.Domain)
		}
		if row.Status == "deferred" && row.Reason == "" {
			t.Fatalf("%s missing deferred reason", row.Domain)
		}
	}
	for domain := range want {
		t.Fatalf("missing coverage row %s", domain)
	}
	if report.ProductionEquivalent {
		t.Fatal("coverage report claimed production equivalence with deferred domains")
	}
}
