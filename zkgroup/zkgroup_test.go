package zkgroup

import "testing"

func TestVerifyMembershipCredentialVector(t *testing.T) {
	report, err := VerifyMembershipCredential(MembershipCredential{
		GroupID:      "space-1",
		MemberID:     "member-1",
		Issuer:       "issuer-1",
		ExpiresAt:    1893456000,
		ProofDigest:  "sha256:2f99cb90ee710be078aaf1b8cb9a22942c10f5965e5e39c1607a930fd6df7874",
		UpstreamPath: "java/shared/java/org/signal/libsignal/zkgroup/groups",
	})
	if err != nil {
		t.Fatalf("VerifyMembershipCredential: %v", err)
	}
	if !report.Accepted || !report.ProductionReady {
		t.Fatalf("report = %#v, want accepted production-ready", report)
	}
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
