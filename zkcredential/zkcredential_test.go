package zkcredential

import (
	"encoding/json"
	"os"
	"testing"
)

func TestVerifyCredentialPresentationVector(t *testing.T) {
	vector := loadPresentationVector(t)
	report, err := VerifyCredentialPresentation(CredentialPresentation{
		PresentationID: vector.Cases[0].PresentationID,
		SubjectID:      vector.Cases[0].SubjectID,
		Audience:       vector.Cases[0].Audience,
		ProofDigest:    vector.Cases[0].ProofDigest,
		UpstreamPath:   vector.Source,
	})
	if err != nil {
		t.Fatalf("VerifyCredentialPresentation: %v", err)
	}
	if !report.Accepted || !report.ProductionReady {
		t.Fatalf("report = %#v, want accepted production-ready", report)
	}
}

func loadPresentationVector(t *testing.T) struct {
	Source string `json:"source"`
	Cases  []struct {
		PresentationID string `json:"presentation_id"`
		SubjectID      string `json:"subject_id"`
		Audience       string `json:"audience"`
		ProofDigest    string `json:"proof_digest"`
	} `json:"cases"`
} {
	t.Helper()
	raw, err := os.ReadFile("../testdata/upstream-vectors/zkcredential-presentation.json")
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var vector struct {
		Source string `json:"source"`
		Cases  []struct {
			PresentationID string `json:"presentation_id"`
			SubjectID      string `json:"subject_id"`
			Audience       string `json:"audience"`
			ProofDigest    string `json:"proof_digest"`
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

func TestVerifyCredentialPresentationRejectsMalformedVector(t *testing.T) {
	_, err := VerifyCredentialPresentation(CredentialPresentation{
		PresentationID: "presentation-1",
		SubjectID:      "member-1",
		Audience:       "space-1",
		ProofDigest:    "sha256:bad",
	})
	if err == nil {
		t.Fatal("expected malformed proof rejection")
	}
}
