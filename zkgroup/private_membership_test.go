package zkgroup

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestPrivateMembershipCredentialLifecycle(t *testing.T) {
	credential, err := IssuePrivateMembershipCredential(PrivateMembershipIssueRequest{
		GroupID:         "space-1",
		MemberID:        "member-1",
		Issuer:          "issuer-1",
		IssuerSecret:    []byte("fixture-secret"),
		MembershipEpoch: 2,
		ExpiresAt:       1893456000,
		UpstreamPath:    "java/shared/java/org/signal/libsignal/zkgroup/groups",
	})
	if err != nil {
		t.Fatalf("IssuePrivateMembershipCredential: %v", err)
	}
	if credential.MemberCommitment == "" {
		t.Fatal("member commitment is empty")
	}
	if strings.Contains(mustJSON(t, credential), "member-1") {
		t.Fatal("credential JSON leaked plaintext member ID")
	}
	if strings.Contains(mustJSON(t, credential), "fixture-secret") {
		t.Fatal("credential JSON leaked issuer secret")
	}

	presentation, err := PresentPrivateMembershipCredential(credential, PrivateMembershipPresentationRequest{
		Audience:    "workflow-scenario-108",
		OperationID: "append-1",
	})
	if err != nil {
		t.Fatalf("PresentPrivateMembershipCredential: %v", err)
	}
	if strings.Contains(mustJSON(t, presentation), "member-1") {
		t.Fatal("presentation JSON leaked plaintext member ID")
	}

	report, err := VerifyPrivateMembershipPresentation(presentation, PrivateMembershipVerifyRequest{
		IssuerSecret:           []byte("fixture-secret"),
		Audience:               "workflow-scenario-108",
		OperationID:            "append-1",
		CurrentMembershipEpoch: 2,
		NowUnix:                1890000000,
	})
	if err != nil {
		t.Fatalf("VerifyPrivateMembershipPresentation: %v", err)
	}
	if !report.Accepted {
		t.Fatalf("report accepted = false, reason %q", report.Reason)
	}
	if report.OfficialZKEquivalent {
		t.Fatal("local private membership subset must not claim official zk equivalence")
	}
	if report.MemberCommitment != credential.MemberCommitment {
		t.Fatalf("report commitment = %q, want %q", report.MemberCommitment, credential.MemberCommitment)
	}
}

func TestPrivateMembershipRejectsInvalidPresentation(t *testing.T) {
	credential, err := IssuePrivateMembershipCredential(PrivateMembershipIssueRequest{
		GroupID:         "space-1",
		MemberID:        "member-1",
		Issuer:          "issuer-1",
		IssuerSecret:    []byte("fixture-secret"),
		MembershipEpoch: 2,
		ExpiresAt:       1893456000,
		UpstreamPath:    "java/shared/java/org/signal/libsignal/zkgroup/groups",
	})
	if err != nil {
		t.Fatalf("IssuePrivateMembershipCredential: %v", err)
	}
	presentation, err := PresentPrivateMembershipCredential(credential, PrivateMembershipPresentationRequest{
		Audience:    "workflow-scenario-108",
		OperationID: "append-1",
	})
	if err != nil {
		t.Fatalf("PresentPrivateMembershipCredential: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*PrivateMembershipPresentation, *PrivateMembershipVerifyRequest)
	}{
		{
			name: "wrong audience",
			mutate: func(_ *PrivateMembershipPresentation, req *PrivateMembershipVerifyRequest) {
				req.Audience = "other-audience"
			},
		},
		{
			name: "wrong operation",
			mutate: func(_ *PrivateMembershipPresentation, req *PrivateMembershipVerifyRequest) {
				req.OperationID = "append-2"
			},
		},
		{
			name: "expired",
			mutate: func(_ *PrivateMembershipPresentation, req *PrivateMembershipVerifyRequest) {
				req.NowUnix = 1893456001
			},
		},
		{
			name: "stale epoch",
			mutate: func(_ *PrivateMembershipPresentation, req *PrivateMembershipVerifyRequest) {
				req.CurrentMembershipEpoch = 3
			},
		},
		{
			name: "revoked commitment",
			mutate: func(p *PrivateMembershipPresentation, req *PrivateMembershipVerifyRequest) {
				req.RevokedMemberCommitments = []string{p.MemberCommitment}
			},
		},
		{
			name: "tampered proof",
			mutate: func(p *PrivateMembershipPresentation, _ *PrivateMembershipVerifyRequest) {
				p.ProofDigest = "sha256:bad"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := presentation
			req := PrivateMembershipVerifyRequest{
				IssuerSecret:           []byte("fixture-secret"),
				Audience:               "workflow-scenario-108",
				OperationID:            "append-1",
				CurrentMembershipEpoch: 2,
				NowUnix:                1890000000,
			}
			tt.mutate(&p, &req)
			report, err := VerifyPrivateMembershipPresentation(p, req)
			if !errors.Is(err, ErrVerificationFailed) {
				t.Fatalf("err = %v, want ErrVerificationFailed", err)
			}
			if report.Accepted {
				t.Fatalf("report accepted = true, reason %q", report.Reason)
			}
		})
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}
	return string(data)
}
