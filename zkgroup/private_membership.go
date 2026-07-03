package zkgroup

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

const (
	privateMembershipCommitmentDomain   = "encrypted-spaces.private-membership.commitment.v1"
	privateMembershipCredentialDomain   = "encrypted-spaces.private-membership.credential.v1"
	privateMembershipCredentialIDDomain = "encrypted-spaces.private-membership.credential-id.v1"
	privateMembershipPresentationDomain = "encrypted-spaces.private-membership.presentation.v1"
)

type PrivateMembershipIssueRequest struct {
	GroupID         string
	MemberID        string
	Issuer          string
	IssuerSecret    []byte
	MembershipEpoch uint64
	ExpiresAt       int64
	UpstreamPath    string
}

type PrivateMembershipCredential struct {
	CredentialID        string `json:"credential_id"`
	GroupID             string `json:"group_id"`
	Issuer              string `json:"issuer"`
	MemberCommitment    string `json:"member_commitment"`
	MembershipEpoch     uint64 `json:"membership_epoch"`
	ExpiresAt           int64  `json:"expires_at"`
	UpstreamPath        string `json:"upstream_path,omitempty"`
	CredentialSignature string `json:"credential_signature"`
}

type PrivateMembershipPresentationRequest struct {
	Audience    string
	OperationID string
}

type PrivateMembershipPresentation struct {
	CredentialID        string `json:"credential_id"`
	GroupID             string `json:"group_id"`
	Issuer              string `json:"issuer"`
	MemberCommitment    string `json:"member_commitment"`
	MembershipEpoch     uint64 `json:"membership_epoch"`
	ExpiresAt           int64  `json:"expires_at"`
	UpstreamPath        string `json:"upstream_path,omitempty"`
	Audience            string `json:"audience"`
	OperationID         string `json:"operation_id"`
	CredentialSignature string `json:"credential_signature"`
	ProofDigest         string `json:"proof_digest"`
}

type PrivateMembershipVerifyRequest struct {
	IssuerSecret             []byte
	Audience                 string
	OperationID              string
	CurrentMembershipEpoch   uint64
	RevokedMemberCommitments []string
	NowUnix                  int64
}

type PrivateMembershipVerificationReport struct {
	Domain               string
	Accepted             bool
	ProductionReady      bool
	OfficialZKEquivalent bool
	Reason               string
	MemberCommitment     string
	UpstreamPath         string
}

func IssuePrivateMembershipCredential(req PrivateMembershipIssueRequest) (PrivateMembershipCredential, error) {
	if req.GroupID == "" {
		return PrivateMembershipCredential{}, fmt.Errorf("%w: group id is required", ErrVerificationFailed)
	}
	if req.MemberID == "" {
		return PrivateMembershipCredential{}, fmt.Errorf("%w: member id is required", ErrVerificationFailed)
	}
	if req.Issuer == "" {
		return PrivateMembershipCredential{}, fmt.Errorf("%w: issuer is required", ErrVerificationFailed)
	}
	if len(req.IssuerSecret) == 0 {
		return PrivateMembershipCredential{}, fmt.Errorf("%w: issuer secret is required", ErrVerificationFailed)
	}
	if req.MembershipEpoch == 0 {
		return PrivateMembershipCredential{}, fmt.Errorf("%w: membership epoch is required", ErrVerificationFailed)
	}
	if req.ExpiresAt <= 0 {
		return PrivateMembershipCredential{}, fmt.Errorf("%w: expiry is required", ErrVerificationFailed)
	}

	memberCommitment := privateMembershipMAC(req.IssuerSecret,
		privateMembershipCommitmentDomain,
		req.GroupID,
		req.MemberID,
		req.Issuer,
		strconv.FormatUint(req.MembershipEpoch, 10),
		req.UpstreamPath,
	)
	credentialID := privateMembershipMAC(req.IssuerSecret,
		privateMembershipCredentialIDDomain,
		req.GroupID,
		memberCommitment,
		req.Issuer,
		strconv.FormatUint(req.MembershipEpoch, 10),
		strconv.FormatInt(req.ExpiresAt, 10),
		req.UpstreamPath,
	)
	credential := PrivateMembershipCredential{
		CredentialID:     credentialID,
		GroupID:          req.GroupID,
		Issuer:           req.Issuer,
		MemberCommitment: memberCommitment,
		MembershipEpoch:  req.MembershipEpoch,
		ExpiresAt:        req.ExpiresAt,
		UpstreamPath:     req.UpstreamPath,
	}
	credential.CredentialSignature = signPrivateMembershipCredential(req.IssuerSecret, credential)
	return credential, nil
}

func PresentPrivateMembershipCredential(credential PrivateMembershipCredential, req PrivateMembershipPresentationRequest) (PrivateMembershipPresentation, error) {
	if credential.CredentialID == "" || credential.CredentialSignature == "" {
		return PrivateMembershipPresentation{}, fmt.Errorf("%w: credential id and signature are required", ErrVerificationFailed)
	}
	if req.Audience == "" {
		return PrivateMembershipPresentation{}, fmt.Errorf("%w: audience is required", ErrVerificationFailed)
	}
	if req.OperationID == "" {
		return PrivateMembershipPresentation{}, fmt.Errorf("%w: operation id is required", ErrVerificationFailed)
	}
	presentation := PrivateMembershipPresentation{
		CredentialID:        credential.CredentialID,
		GroupID:             credential.GroupID,
		Issuer:              credential.Issuer,
		MemberCommitment:    credential.MemberCommitment,
		MembershipEpoch:     credential.MembershipEpoch,
		ExpiresAt:           credential.ExpiresAt,
		UpstreamPath:        credential.UpstreamPath,
		Audience:            req.Audience,
		OperationID:         req.OperationID,
		CredentialSignature: credential.CredentialSignature,
	}
	presentation.ProofDigest = signPrivateMembershipPresentation(presentation)
	return presentation, nil
}

func VerifyPrivateMembershipPresentation(presentation PrivateMembershipPresentation, req PrivateMembershipVerifyRequest) (PrivateMembershipVerificationReport, error) {
	report := PrivateMembershipVerificationReport{
		Domain:               "zkgroup.private-membership",
		Accepted:             false,
		ProductionReady:      false,
		OfficialZKEquivalent: false,
		MemberCommitment:     presentation.MemberCommitment,
		UpstreamPath:         presentation.UpstreamPath,
	}
	if len(req.IssuerSecret) == 0 {
		report.Reason = "issuer-secret-required"
		return report, fmt.Errorf("%w: issuer secret is required", ErrVerificationFailed)
	}
	if req.Audience == "" || presentation.Audience != req.Audience {
		report.Reason = "audience-mismatch"
		return report, fmt.Errorf("%w: audience mismatch", ErrVerificationFailed)
	}
	if req.OperationID == "" || presentation.OperationID != req.OperationID {
		report.Reason = "operation-mismatch"
		return report, fmt.Errorf("%w: operation mismatch", ErrVerificationFailed)
	}
	now := req.NowUnix
	if now == 0 {
		now = time.Now().Unix()
	}
	if presentation.ExpiresAt <= now {
		report.Reason = "credential-expired"
		return report, fmt.Errorf("%w: credential expired", ErrVerificationFailed)
	}
	if req.CurrentMembershipEpoch > presentation.MembershipEpoch {
		report.Reason = "membership-epoch-stale"
		return report, fmt.Errorf("%w: membership epoch stale", ErrVerificationFailed)
	}
	if containsString(req.RevokedMemberCommitments, presentation.MemberCommitment) {
		report.Reason = "member-revoked"
		return report, fmt.Errorf("%w: member revoked", ErrVerificationFailed)
	}

	credential := PrivateMembershipCredential{
		CredentialID:     presentation.CredentialID,
		GroupID:          presentation.GroupID,
		Issuer:           presentation.Issuer,
		MemberCommitment: presentation.MemberCommitment,
		MembershipEpoch:  presentation.MembershipEpoch,
		ExpiresAt:        presentation.ExpiresAt,
		UpstreamPath:     presentation.UpstreamPath,
	}
	wantCredentialSignature := signPrivateMembershipCredential(req.IssuerSecret, credential)
	if !hmac.Equal([]byte(presentation.CredentialSignature), []byte(wantCredentialSignature)) {
		report.Reason = "credential-signature-mismatch"
		return report, fmt.Errorf("%w: credential signature mismatch", ErrVerificationFailed)
	}
	wantProof := signPrivateMembershipPresentation(presentation)
	if !hmac.Equal([]byte(presentation.ProofDigest), []byte(wantProof)) {
		report.Reason = "presentation-proof-mismatch"
		return report, fmt.Errorf("%w: presentation proof mismatch", ErrVerificationFailed)
	}
	report.Accepted = true
	report.Reason = "accepted-local-private-membership-subset"
	return report, nil
}

func signPrivateMembershipCredential(secret []byte, credential PrivateMembershipCredential) string {
	return privateMembershipMAC(secret,
		privateMembershipCredentialDomain,
		credential.CredentialID,
		credential.GroupID,
		credential.Issuer,
		credential.MemberCommitment,
		strconv.FormatUint(credential.MembershipEpoch, 10),
		strconv.FormatInt(credential.ExpiresAt, 10),
		credential.UpstreamPath,
	)
}

func signPrivateMembershipPresentation(presentation PrivateMembershipPresentation) string {
	return privateMembershipMAC([]byte(presentation.CredentialSignature),
		privateMembershipPresentationDomain,
		presentation.CredentialID,
		presentation.GroupID,
		presentation.Issuer,
		presentation.MemberCommitment,
		strconv.FormatUint(presentation.MembershipEpoch, 10),
		strconv.FormatInt(presentation.ExpiresAt, 10),
		presentation.UpstreamPath,
		presentation.Audience,
		presentation.OperationID,
	)
}

func privateMembershipMAC(secret []byte, domain string, parts ...string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(domain))
	for _, part := range parts {
		mac.Write([]byte{0})
		mac.Write([]byte(part))
	}
	return "sha256:" + hex.EncodeToString(mac.Sum(nil))
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
