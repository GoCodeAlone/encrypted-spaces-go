// Package proof composes vector-backed Encrypted Spaces proof primitives into
// Workflow-facing verification policies.
package proof

import (
	"errors"
	"fmt"

	"github.com/GoCodeAlone/encrypted-spaces-go/keytrans"
	"github.com/GoCodeAlone/encrypted-spaces-go/operationlog"
	"github.com/GoCodeAlone/encrypted-spaces-go/zkgroup"
)

var (
	ErrProofRejected   = errors.New("proof rejected")
	ErrStaleCheckpoint = errors.New("stale checkpoint")
)

type Policy struct{}

type Report struct {
	Domain          string `json:"domain"`
	Accepted        bool   `json:"accepted"`
	ProductionReady bool   `json:"production_ready"`
	UpstreamPath    string `json:"upstream_path,omitempty"`
}

type MembershipProof struct {
	GroupID      string
	MemberID     string
	Issuer       string
	ExpiresAt    int64
	ProofDigest  string
	UpstreamPath string
}

type CheckpointProof struct {
	Checkpoint       keytrans.Checkpoint
	PreviousTreeSize uint64
}

func VectorPolicy() Policy {
	return Policy{}
}

func (Policy) VerifyMembership(proof MembershipProof) (Report, error) {
	report, err := zkgroup.VerifyMembershipCredential(zkgroup.MembershipCredential{
		GroupID:      proof.GroupID,
		MemberID:     proof.MemberID,
		Issuer:       proof.Issuer,
		ExpiresAt:    proof.ExpiresAt,
		ProofDigest:  proof.ProofDigest,
		UpstreamPath: proof.UpstreamPath,
	})
	if err != nil {
		return Report{}, fmt.Errorf("%w: %v", ErrProofRejected, err)
	}
	return Report{
		Domain:          report.Domain,
		Accepted:        report.Accepted,
		ProductionReady: report.ProductionReady,
		UpstreamPath:    report.UpstreamPath,
	}, nil
}

func (Policy) VerifyOperationCommitment(operation operationlog.EncryptedOperation, commitment operationlog.OperationCommitment) (Report, error) {
	log, err := operationlog.NewLog(operationlog.LogOptions{})
	if err != nil {
		return Report{}, err
	}
	got, err := log.Append(operation)
	if err != nil {
		return Report{}, err
	}
	if got.SpaceID != commitment.SpaceID ||
		got.OperationID != commitment.OperationID ||
		got.Digest != commitment.Digest ||
		got.KeyEpoch != commitment.KeyEpoch ||
		got.MembershipEpoch != commitment.MembershipEpoch ||
		got.CiphertextSize != commitment.CiphertextSize {
		return Report{}, fmt.Errorf("%w: operation commitment mismatch", ErrProofRejected)
	}
	return Report{
		Domain:          "operationlog.commitment",
		Accepted:        true,
		ProductionReady: true,
	}, nil
}

func (Policy) VerifyCheckpoint(proof CheckpointProof) (Report, error) {
	if proof.Checkpoint.TreeSize <= proof.PreviousTreeSize {
		return Report{}, ErrStaleCheckpoint
	}
	report, err := keytrans.VerifyCheckpoint(proof.Checkpoint)
	if err != nil {
		return Report{}, fmt.Errorf("%w: %v", ErrProofRejected, err)
	}
	return Report{
		Domain:          report.Domain,
		Accepted:        report.Accepted,
		ProductionReady: report.ProductionReady,
		UpstreamPath:    report.UpstreamPath,
	}, nil
}
