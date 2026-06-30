package operationlog

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
)

type LogOptions struct {
	Retention RetentionPolicy
}

type Log struct {
	mu          sync.Mutex
	retention   RetentionPolicy
	nextSeq     uint64
	ledger      map[OperationID]OperationCommitment
	commitments []OperationCommitment
	checkpoint  FastForwardCheckpoint
}

func NewLog(options LogOptions) (*Log, error) {
	if options.Retention.MaxOperations < 0 {
		return nil, ErrInvalidRetentionPolicy
	}
	return &Log{
		retention: options.Retention,
		nextSeq:   1,
		ledger:    make(map[OperationID]OperationCommitment),
	}, nil
}

func (l *Log) Append(operation EncryptedOperation) (OperationCommitment, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if operation.KeyEpoch < l.retention.MinKeyEpoch || operation.MembershipEpoch < l.retention.MinMembershipEpoch {
		return OperationCommitment{}, ErrOperationOutsideRetention
	}

	digest, err := operationDigest(operation)
	if err != nil {
		return OperationCommitment{}, err
	}
	if existing, ok := l.ledger[operation.OperationID]; ok {
		if existing.Digest == digest {
			return existing, nil
		}
		return OperationCommitment{}, &ConflictReport{
			OperationID:    operation.OperationID,
			ExistingDigest: existing.Digest,
			IncomingDigest: digest,
		}
	}

	commitment := OperationCommitment{
		SpaceID:         operation.SpaceID,
		OperationID:     operation.OperationID,
		Sequence:        l.nextSeq,
		Digest:          digest,
		KeyEpoch:        operation.KeyEpoch,
		MembershipEpoch: operation.MembershipEpoch,
		CiphertextSize:  len(operation.Ciphertext),
	}
	l.nextSeq++
	l.ledger[operation.OperationID] = commitment
	l.commitments = append(l.commitments, commitment)
	l.pruneRetainedCommitments()
	return commitment, nil
}

func (l *Log) Commitments() []OperationCommitment {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]OperationCommitment(nil), l.commitments...)
}

func (l *Log) Checkpoint() FastForwardCheckpoint {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.checkpoint
}

func (l *Log) pruneRetainedCommitments() {
	if l.retention.MaxOperations == 0 || len(l.commitments) <= l.retention.MaxOperations {
		return
	}
	l.commitments = append([]OperationCommitment(nil), l.commitments[len(l.commitments)-l.retention.MaxOperations:]...)
}

func operationDigest(operation EncryptedOperation) (string, error) {
	payload := struct {
		SpaceID         SpaceID
		MemberID        MemberID
		DeviceID        DeviceID
		OperationID     OperationID
		KeyEpoch        KeyEpoch
		MembershipEpoch MembershipEpoch
		Ciphertext      []byte
		Nonce           []byte
		AssociatedData  []byte
		CreatedAtUnixNS int64
	}{
		SpaceID:         operation.SpaceID,
		MemberID:        operation.MemberID,
		DeviceID:        operation.DeviceID,
		OperationID:     operation.OperationID,
		KeyEpoch:        operation.KeyEpoch,
		MembershipEpoch: operation.MembershipEpoch,
		Ciphertext:      bytes.Clone(operation.Ciphertext),
		Nonce:           bytes.Clone(operation.Nonce),
		AssociatedData:  bytes.Clone(operation.AssociatedData),
		CreatedAtUnixNS: operation.CreatedAt.UTC().UnixNano(),
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
