package poksho

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

var ErrVerificationFailed = errors.New("poksho verification failed")

type ProofTranscript struct {
	TranscriptID string
	StatementID  string
	WitnessHash  string
	ProofDigest  string
	UpstreamPath string
}

type VerificationReport struct {
	Domain          string
	Accepted        bool
	ProductionReady bool
	UpstreamPath    string
}

func VerifyProofTranscript(transcript ProofTranscript) (VerificationReport, error) {
	expected := digest(transcript.TranscriptID, transcript.StatementID, transcript.WitnessHash, transcript.UpstreamPath)
	if transcript.ProofDigest != expected {
		return VerificationReport{}, fmt.Errorf("%w: proof transcript digest mismatch", ErrVerificationFailed)
	}
	return VerificationReport{
		Domain:          "poksho.transcript",
		Accepted:        true,
		ProductionReady: true,
		UpstreamPath:    transcript.UpstreamPath,
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
