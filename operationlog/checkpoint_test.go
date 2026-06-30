package operationlog

import (
	"errors"
	"testing"
)

func TestFastForwardCheckpointVerification(t *testing.T) {
	log, err := NewLog(LogOptions{Retention: RetentionPolicy{MaxOperations: 10}})
	if err != nil {
		t.Fatalf("NewLog returned error: %v", err)
	}
	first, err := log.Append(testOperation("op-1"))
	if err != nil {
		t.Fatalf("append op-1 returned error: %v", err)
	}

	checkpoint := FastForwardCheckpoint{
		SpaceID:         "space-1",
		ThroughSequence: first.Sequence,
		OperationID:     first.OperationID,
		Digest:          first.Digest,
		KeyEpoch:        first.KeyEpoch,
		MembershipEpoch: first.MembershipEpoch,
	}
	if err := log.FastForward(checkpoint); err != nil {
		t.Fatalf("FastForward returned error: %v", err)
	}
	if got := log.Checkpoint(); got != checkpoint {
		t.Fatalf("Checkpoint = %#v, want %#v", got, checkpoint)
	}

	stale := checkpoint
	stale.ThroughSequence = 0
	if err := log.FastForward(stale); !errors.Is(err, ErrStaleCheckpoint) {
		t.Fatalf("stale checkpoint error = %v, want ErrStaleCheckpoint", err)
	}

	wrongDigest := checkpoint
	wrongDigest.ThroughSequence = 2
	wrongDigest.Digest = "sha256:not-the-commitment"
	if err := log.FastForward(wrongDigest); !errors.Is(err, ErrCheckpointMismatch) {
		t.Fatalf("wrong digest checkpoint error = %v, want ErrCheckpointMismatch", err)
	}
}
