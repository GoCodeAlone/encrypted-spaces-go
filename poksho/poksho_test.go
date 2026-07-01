package poksho

import (
	"encoding/json"
	"os"
	"testing"
)

func TestVerifyProofTranscriptVector(t *testing.T) {
	vector := loadTranscriptVector(t)
	report, err := VerifyProofTranscript(ProofTranscript{
		TranscriptID: vector.Cases[0].TranscriptID,
		StatementID:  vector.Cases[0].StatementID,
		WitnessHash:  vector.Cases[0].WitnessHash,
		ProofDigest:  vector.Cases[0].ProofDigest,
		UpstreamPath: vector.Source,
	})
	if err != nil {
		t.Fatalf("VerifyProofTranscript: %v", err)
	}
	if !report.Accepted || !report.ProductionReady {
		t.Fatalf("report = %#v, want accepted production-ready", report)
	}
}

func loadTranscriptVector(t *testing.T) struct {
	Source string `json:"source"`
	Cases  []struct {
		TranscriptID string `json:"transcript_id"`
		StatementID  string `json:"statement_id"`
		WitnessHash  string `json:"witness_hash"`
		ProofDigest  string `json:"proof_digest"`
	} `json:"cases"`
} {
	t.Helper()
	raw, err := os.ReadFile("../testdata/upstream-vectors/poksho-transcript.json")
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var vector struct {
		Source string `json:"source"`
		Cases  []struct {
			TranscriptID string `json:"transcript_id"`
			StatementID  string `json:"statement_id"`
			WitnessHash  string `json:"witness_hash"`
			ProofDigest  string `json:"proof_digest"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatalf("decode vector: %v", err)
	}
	if len(vector.Cases) == 0 {
		t.Fatal("vector has no cases")
	}
	return vector
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
