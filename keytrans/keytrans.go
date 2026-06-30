package keytrans

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

var ErrVerificationFailed = errors.New("keytrans verification failed")

type Checkpoint struct {
	CheckpointID string
	TreeHead     string
	TreeSize     uint64
	ProofDigest  string
	UpstreamPath string
}

type VerificationReport struct {
	Domain          string
	Accepted        bool
	ProductionReady bool
	UpstreamPath    string
}

func VerifyCheckpoint(checkpoint Checkpoint) (VerificationReport, error) {
	expected := digest(checkpoint.CheckpointID, checkpoint.TreeHead, fmt.Sprintf("%d", checkpoint.TreeSize), checkpoint.UpstreamPath)
	if checkpoint.ProofDigest != expected {
		return VerificationReport{}, fmt.Errorf("%w: checkpoint digest mismatch", ErrVerificationFailed)
	}
	return VerificationReport{
		Domain:          "keytrans.checkpoint",
		Accepted:        true,
		ProductionReady: true,
		UpstreamPath:    checkpoint.UpstreamPath,
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
