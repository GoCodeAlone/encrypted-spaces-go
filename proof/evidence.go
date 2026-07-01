package proof

import "github.com/GoCodeAlone/encrypted-spaces-go/operationlog"

type OperationEvidence struct {
	SpaceID         operationlog.SpaceID         `json:"space_id"`
	OperationID     operationlog.OperationID     `json:"operation_id"`
	Sequence        uint64                       `json:"sequence"`
	Digest          string                       `json:"digest"`
	KeyEpoch        operationlog.KeyEpoch        `json:"key_epoch"`
	MembershipEpoch operationlog.MembershipEpoch `json:"membership_epoch"`
	CiphertextSize  int                          `json:"ciphertext_size"`
	Reports         []Report                     `json:"reports"`
}

func NewOperationEvidence(commitment operationlog.OperationCommitment, reports []Report) OperationEvidence {
	return OperationEvidence{
		SpaceID:         commitment.SpaceID,
		OperationID:     commitment.OperationID,
		Sequence:        commitment.Sequence,
		Digest:          commitment.Digest,
		KeyEpoch:        commitment.KeyEpoch,
		MembershipEpoch: commitment.MembershipEpoch,
		CiphertextSize:  commitment.CiphertextSize,
		Reports:         append([]Report(nil), reports...),
	}
}
