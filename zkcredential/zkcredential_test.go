package zkcredential

import "testing"

func TestVerifyCredentialPresentationVector(t *testing.T) {
	report, err := VerifyCredentialPresentation(CredentialPresentation{
		PresentationID: "presentation-1",
		SubjectID:      "member-1",
		Audience:       "space-1",
		ProofDigest:    "sha256:9b03b326186231ffebf8f1e5ba3e31afd7ba9b687e12b6fb2eb8ecfbe17295cf",
		UpstreamPath:   "java/shared/java/org/signal/libsignal/zkgroup/auth",
	})
	if err != nil {
		t.Fatalf("VerifyCredentialPresentation: %v", err)
	}
	if !report.Accepted || !report.ProductionReady {
		t.Fatalf("report = %#v, want accepted production-ready", report)
	}
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
