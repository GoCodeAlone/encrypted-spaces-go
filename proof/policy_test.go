package proof

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/GoCodeAlone/encrypted-spaces-go/keytrans"
	"github.com/GoCodeAlone/encrypted-spaces-go/operationlog"
)

func TestMembershipProofAcceptsVectorBackedCredential(t *testing.T) {
	vector := loadMembershipVector(t)
	policy := VectorPolicy()

	report, err := policy.VerifyMembership(MembershipProof{
		GroupID:      vector.Cases[0].GroupID,
		MemberID:     vector.Cases[0].MemberID,
		Issuer:       vector.Cases[0].Issuer,
		ExpiresAt:    vector.Cases[0].ExpiresAt,
		ProofDigest:  vector.Cases[0].ProofDigest,
		UpstreamPath: vector.Source,
	})
	if err != nil {
		t.Fatalf("VerifyMembership: %v", err)
	}
	if !report.Accepted || !report.ProductionReady || report.Domain != "zkgroup.membership" {
		t.Fatalf("report = %#v, want accepted vector-backed membership", report)
	}
}

func TestMembershipProofRejectsMalformedProof(t *testing.T) {
	vector := loadMembershipVector(t)
	policy := VectorPolicy()

	_, err := policy.VerifyMembership(MembershipProof{
		GroupID:      vector.Cases[0].GroupID,
		MemberID:     vector.Cases[0].MemberID,
		Issuer:       vector.Cases[0].Issuer,
		ExpiresAt:    vector.Cases[0].ExpiresAt,
		ProofDigest:  "sha256:bad",
		UpstreamPath: vector.Source,
	})
	if !errors.Is(err, ErrProofRejected) {
		t.Fatalf("VerifyMembership malformed error = %v, want ErrProofRejected", err)
	}
}

func TestOperationCommitmentRejectsTamperedOperation(t *testing.T) {
	policy := VectorPolicy()
	log, err := operationlog.NewLog(operationlog.LogOptions{})
	if err != nil {
		t.Fatalf("NewLog: %v", err)
	}
	operation := encryptedOperation("ciphertext-v1")
	commitment, err := log.Append(operation)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	tampered := operation
	tampered.Ciphertext = []byte("ciphertext-v2")
	_, err = policy.VerifyOperationCommitment(tampered, commitment)
	if !errors.Is(err, ErrProofRejected) {
		t.Fatalf("VerifyOperationCommitment tampered error = %v, want ErrProofRejected", err)
	}
}

func TestCheckpointProofRejectsStaleCheckpoint(t *testing.T) {
	vector := loadCheckpointVector(t)
	policy := VectorPolicy()

	_, err := policy.VerifyCheckpoint(CheckpointProof{
		Checkpoint: keytrans.Checkpoint{
			CheckpointID: vector.Cases[0].CheckpointID,
			TreeHead:     vector.Cases[0].TreeHead,
			TreeSize:     vector.Cases[0].TreeSize,
			ProofDigest:  vector.Cases[0].ProofDigest,
			UpstreamPath: vector.Source,
		},
		PreviousTreeSize: vector.Cases[0].TreeSize,
	})
	if !errors.Is(err, ErrStaleCheckpoint) {
		t.Fatalf("VerifyCheckpoint stale error = %v, want ErrStaleCheckpoint", err)
	}
}

func encryptedOperation(ciphertext string) operationlog.EncryptedOperation {
	return operationlog.EncryptedOperation{
		SpaceID:         "space-1",
		MemberID:        "member-1",
		DeviceID:        "device-1",
		OperationID:     "operation-1",
		KeyEpoch:        3,
		MembershipEpoch: 5,
		Ciphertext:      []byte(ciphertext),
		Nonce:           []byte("nonce-1"),
		AssociatedData:  []byte("associated-data"),
		CreatedAt:       time.Unix(1_700_000_000, 0),
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
		t.Fatalf("read membership vector: %v", err)
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
		t.Fatalf("decode membership vector: %v", err)
	}
	if len(vector.Cases) == 0 {
		t.Fatal("membership vector has no cases")
	}
	return vector
}

func loadCheckpointVector(t *testing.T) struct {
	Source string `json:"source"`
	Cases  []struct {
		CheckpointID string `json:"checkpoint_id"`
		TreeHead     string `json:"tree_head"`
		TreeSize     uint64 `json:"tree_size"`
		ProofDigest  string `json:"proof_digest"`
	} `json:"cases"`
} {
	t.Helper()
	raw, err := os.ReadFile("../testdata/upstream-vectors/keytrans-checkpoint.json")
	if err != nil {
		t.Fatalf("read checkpoint vector: %v", err)
	}
	var vector struct {
		Source string `json:"source"`
		Cases  []struct {
			CheckpointID string `json:"checkpoint_id"`
			TreeHead     string `json:"tree_head"`
			TreeSize     uint64 `json:"tree_size"`
			ProofDigest  string `json:"proof_digest"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatalf("decode checkpoint vector: %v", err)
	}
	if len(vector.Cases) == 0 {
		t.Fatal("checkpoint vector has no cases")
	}
	return vector
}
