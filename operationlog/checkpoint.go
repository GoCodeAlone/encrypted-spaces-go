package operationlog

func (l *Log) FastForward(checkpoint FastForwardCheckpoint) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if checkpoint.ThroughSequence <= l.checkpoint.ThroughSequence {
		return ErrStaleCheckpoint
	}
	for _, commitment := range l.commitments {
		if commitment.Sequence != checkpoint.ThroughSequence {
			continue
		}
		if commitment.SpaceID != checkpoint.SpaceID ||
			commitment.OperationID != checkpoint.OperationID ||
			commitment.Digest != checkpoint.Digest ||
			commitment.KeyEpoch != checkpoint.KeyEpoch ||
			commitment.MembershipEpoch != checkpoint.MembershipEpoch {
			return ErrCheckpointMismatch
		}
		l.checkpoint = checkpoint
		return nil
	}
	return ErrCheckpointMismatch
}
