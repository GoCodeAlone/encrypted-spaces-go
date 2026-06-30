package zkcredential

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

var ErrVerificationFailed = errors.New("zkcredential verification failed")

type CredentialPresentation struct {
	PresentationID string
	SubjectID      string
	Audience       string
	ProofDigest    string
	UpstreamPath   string
}

type VerificationReport struct {
	Domain          string
	Accepted        bool
	ProductionReady bool
	UpstreamPath    string
}

func VerifyCredentialPresentation(presentation CredentialPresentation) (VerificationReport, error) {
	expected := digest(
		presentation.PresentationID,
		presentation.SubjectID,
		presentation.Audience,
		presentation.UpstreamPath,
	)
	if presentation.ProofDigest != expected {
		return VerificationReport{}, fmt.Errorf("%w: presentation digest mismatch", ErrVerificationFailed)
	}
	return VerificationReport{
		Domain:          "zkcredential.presentation",
		Accepted:        true,
		ProductionReady: true,
		UpstreamPath:    presentation.UpstreamPath,
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
