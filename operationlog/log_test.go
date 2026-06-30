package operationlog

import (
	"errors"
	"testing"
	"time"
)

func TestAppendProducesDeterministicCommitment(t *testing.T) {
	log, err := NewLog(LogOptions{
		Retention: RetentionPolicy{MaxOperations: 10},
	})
	if err != nil {
		t.Fatalf("NewLog returned error: %v", err)
	}

	op := testOperation("op-1")
	first, err := log.Append(op)
	if err != nil {
		t.Fatalf("first append returned error: %v", err)
	}
	second, err := log.Append(op)
	if err != nil {
		t.Fatalf("idempotent append returned error: %v", err)
	}

	if first != second {
		t.Fatalf("commitment changed across replay:\nfirst:  %#v\nsecond: %#v", first, second)
	}
	if first.Sequence != 1 {
		t.Fatalf("Sequence = %d, want 1", first.Sequence)
	}
	if first.CiphertextSize != len(op.Ciphertext) {
		t.Fatalf("CiphertextSize = %d, want %d", first.CiphertextSize, len(op.Ciphertext))
	}
	if first.Digest == "" {
		t.Fatal("Digest is empty")
	}
}

func TestAppendRejectsConflictingReplay(t *testing.T) {
	log, err := NewLog(LogOptions{Retention: RetentionPolicy{MaxOperations: 10}})
	if err != nil {
		t.Fatalf("NewLog returned error: %v", err)
	}

	op := testOperation("op-1")
	if _, err := log.Append(op); err != nil {
		t.Fatalf("append returned error: %v", err)
	}
	conflict := op
	conflict.Ciphertext = []byte("different-ciphertext")

	_, err = log.Append(conflict)
	if !errors.Is(err, ErrOperationConflict) {
		t.Fatalf("Append conflict error = %v, want ErrOperationConflict", err)
	}
	var report *ConflictReport
	if !errors.As(err, &report) {
		t.Fatalf("Append conflict error = %T, want ConflictReport", err)
	}
	if report.OperationID != op.OperationID {
		t.Fatalf("Conflict OperationID = %q, want %q", report.OperationID, op.OperationID)
	}
	if report.ExistingDigest == report.IncomingDigest {
		t.Fatal("conflict digests unexpectedly match")
	}
}

func TestRetentionBoundaryValidation(t *testing.T) {
	if _, err := NewLog(LogOptions{Retention: RetentionPolicy{MaxOperations: -1}}); !errors.Is(err, ErrInvalidRetentionPolicy) {
		t.Fatalf("NewLog with negative MaxOperations error = %v, want ErrInvalidRetentionPolicy", err)
	}

	log, err := NewLog(LogOptions{Retention: RetentionPolicy{
		MaxOperations:      2,
		MinKeyEpoch:        2,
		MinMembershipEpoch: 3,
	}})
	if err != nil {
		t.Fatalf("NewLog returned error: %v", err)
	}

	oldKey := testOperation("old-key")
	oldKey.KeyEpoch = 1
	if _, err := log.Append(oldKey); !errors.Is(err, ErrOperationOutsideRetention) {
		t.Fatalf("old key epoch error = %v, want ErrOperationOutsideRetention", err)
	}

	oldMember := testOperation("old-member")
	oldMember.KeyEpoch = 2
	oldMember.MembershipEpoch = 2
	if _, err := log.Append(oldMember); !errors.Is(err, ErrOperationOutsideRetention) {
		t.Fatalf("old membership epoch error = %v, want ErrOperationOutsideRetention", err)
	}

	first, err := log.Append(testOperation("op-1"))
	if err != nil {
		t.Fatalf("append op-1 returned error: %v", err)
	}
	second, err := log.Append(testOperation("op-2"))
	if err != nil {
		t.Fatalf("append op-2 returned error: %v", err)
	}
	third, err := log.Append(testOperation("op-3"))
	if err != nil {
		t.Fatalf("append op-3 returned error: %v", err)
	}

	if got := log.Commitments(); len(got) != 2 {
		t.Fatalf("retained commitments = %d, want 2", len(got))
	}
	if got := log.Commitments()[0]; got.OperationID != second.OperationID {
		t.Fatalf("first retained operation = %q, want %q", got.OperationID, second.OperationID)
	}
	if third.Sequence != first.Sequence+2 {
		t.Fatalf("third sequence = %d, want %d", third.Sequence, first.Sequence+2)
	}
}

func testOperation(id string) EncryptedOperation {
	return EncryptedOperation{
		SpaceID:         "space-1",
		MemberID:        "member-1",
		DeviceID:        "device-1",
		OperationID:     OperationID(id),
		KeyEpoch:        2,
		MembershipEpoch: 3,
		Ciphertext:      []byte("ciphertext-" + id),
		Nonce:           []byte("nonce-" + id),
		AssociatedData:  []byte("aad-" + id),
		CreatedAt:       time.Date(2026, 6, 30, 20, 0, 0, 0, time.UTC),
	}
}
