package zkgroup

import (
	"encoding/json"
	"os"
	"testing"
)

func TestVerifyMembershipCredentialVector(t *testing.T) {
	vector := loadMembershipVector(t)
	report, err := VerifyMembershipCredential(MembershipCredential{
		GroupID:      vector.Cases[0].GroupID,
		MemberID:     vector.Cases[0].MemberID,
		Issuer:       vector.Cases[0].Issuer,
		ExpiresAt:    vector.Cases[0].ExpiresAt,
		ProofDigest:  vector.Cases[0].ProofDigest,
		UpstreamPath: vector.Source,
	})
	if err != nil {
		t.Fatalf("VerifyMembershipCredential: %v", err)
	}
	if !report.Accepted || !report.ProductionReady {
		t.Fatalf("report = %#v, want accepted production-ready", report)
	}
}

func loadMembershipVector(t *testing.T) struct {
	Source string `json:"source"`
	Cases  []struct {
		GroupID     string `json:"group_id"`
		MemberID    string `json:"member_id"`
		Issuer      string `json:"issuer"`
		ExpiresAt   int64  `json:"expires_at"`
		ProofDigest string `json:"proof_digest"`
	} `json:"cases"`
} {
	t.Helper()
	raw, err := os.ReadFile("../testdata/upstream-vectors/zkgroup-membership.json")
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var vector struct {
		Source string `json:"source"`
		Cases  []struct {
			GroupID     string `json:"group_id"`
			MemberID    string `json:"member_id"`
			Issuer      string `json:"issuer"`
			ExpiresAt   int64  `json:"expires_at"`
			ProofDigest string `json:"proof_digest"`
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

func TestVerifyMembershipCredentialRejectsMalformedVector(t *testing.T) {
	_, err := VerifyMembershipCredential(MembershipCredential{
		GroupID:     "space-1",
		MemberID:    "member-1",
		Issuer:      "issuer-1",
		ExpiresAt:   1893456000,
		ProofDigest: "sha256:bad",
	})
	if err == nil {
		t.Fatal("expected malformed proof rejection")
	}
}
