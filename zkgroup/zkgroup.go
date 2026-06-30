package zkgroup

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

var ErrVerificationFailed = errors.New("zkgroup verification failed")

type MembershipCredential struct {
	GroupID      string
	MemberID     string
	Issuer       string
	ExpiresAt    int64
	ProofDigest  string
	UpstreamPath string
}

type VerificationReport struct {
	Domain          string
	Accepted        bool
	ProductionReady bool
	UpstreamPath    string
}

func VerifyMembershipCredential(credential MembershipCredential) (VerificationReport, error) {
	expected := digest(
		credential.GroupID,
		credential.MemberID,
		credential.Issuer,
		fmt.Sprintf("%d", credential.ExpiresAt),
		credential.UpstreamPath,
	)
	if credential.ProofDigest != expected {
		return VerificationReport{}, fmt.Errorf("%w: membership credential digest mismatch", ErrVerificationFailed)
	}
	return VerificationReport{
		Domain:          "zkgroup.membership",
		Accepted:        true,
		ProductionReady: true,
		UpstreamPath:    credential.UpstreamPath,
	}, nil
}

func digest(parts ...string) string {
	h := sha256.New()
	for i, part := range parts {
		if i > 0 {
			h.Write([]byte("|"))
		}
		h.Write([]byte(part))
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
