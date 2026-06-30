package poksho

import "testing"

func TestVerifyProofTranscriptVector(t *testing.T) {
	report, err := VerifyProofTranscript(ProofTranscript{
		TranscriptID: "transcript-1",
		StatementID:  "statement-1",
		WitnessHash:  "sha256:operation",
		ProofDigest:  "sha256:03362ba67e599e1ae3b3b34ef2734245fd784ba2948e6ee8835ba06d1019b3ff",
		UpstreamPath: "rust/poksho/src/proof.rs",
	})
	if err != nil {
		t.Fatalf("VerifyProofTranscript: %v", err)
	}
	if !report.Accepted || !report.ProductionReady {
		t.Fatalf("report = %#v, want accepted production-ready", report)
	}
}

func TestVerifyProofTranscriptRejectsMalformedStatement(t *testing.T) {
	_, err := VerifyProofTranscript(ProofTranscript{
		TranscriptID: "transcript-1",
		StatementID:  "statement-1",
		WitnessHash:  "sha256:operation",
		ProofDigest:  "sha256:bad",
	})
	if err == nil {
		t.Fatal("expected malformed proof rejection")
	}
}
