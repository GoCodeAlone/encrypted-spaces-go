package operationlog

import (
	"errors"
	"fmt"
	"time"
)

type SpaceID string
type MemberID string
type DeviceID string
type OperationID string
type KeyEpoch uint64
type MembershipEpoch uint64

var (
	ErrInvalidRetentionPolicy    = errors.New("invalid retention policy")
	ErrOperationOutsideRetention = errors.New("operation outside retention boundary")
	ErrOperationConflict         = errors.New("operation replay conflict")
	ErrStaleCheckpoint           = errors.New("stale checkpoint")
	ErrCheckpointMismatch        = errors.New("checkpoint mismatch")
)

type RetentionPolicy struct {
	MaxOperations      int
	MinKeyEpoch        KeyEpoch
	MinMembershipEpoch MembershipEpoch
}

type EncryptedOperation struct {
	SpaceID         SpaceID
	MemberID        MemberID
	DeviceID        DeviceID
	OperationID     OperationID
	KeyEpoch        KeyEpoch
	MembershipEpoch MembershipEpoch
	Ciphertext      []byte
	Nonce           []byte
	AssociatedData  []byte
	CreatedAt       time.Time
}

type OperationCommitment struct {
	SpaceID         SpaceID
	OperationID     OperationID
	Sequence        uint64
	Digest          string
	KeyEpoch        KeyEpoch
	MembershipEpoch MembershipEpoch
	CiphertextSize  int
}

type FastForwardCheckpoint struct {
	SpaceID         SpaceID
	ThroughSequence uint64
	OperationID     OperationID
	Digest          string
	KeyEpoch        KeyEpoch
	MembershipEpoch MembershipEpoch
}

type ConflictReport struct {
	OperationID    OperationID
	ExistingDigest string
	IncomingDigest string
}

func (r *ConflictReport) Error() string {
	return fmt.Sprintf("%s: operation %s existing=%s incoming=%s", ErrOperationConflict, r.OperationID, r.ExistingDigest, r.IncomingDigest)
}

func (r *ConflictReport) Unwrap() error {
	return ErrOperationConflict
}
