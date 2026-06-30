package verification

import (
	"errors"

	"github.com/GoCodeAlone/encrypted-spaces-go/operationlog"
)

var ErrMalformedProof = errors.New("malformed proof")

type FakeProof struct {
	OperationID operationlog.OperationID
	Digest      string
	Proof       []byte
}

type Report struct {
	OperationID     operationlog.OperationID
	Digest          string
	Accepted        bool
	ProductionReady bool
	Mode            string
}

type FakeVerifier struct{}

func NewFakeVerifier() FakeVerifier {
	return FakeVerifier{}
}

func (FakeVerifier) VerifyOperation(proof FakeProof) (Report, error) {
	if string(proof.Proof) != "fake-proof" {
		return Report{}, ErrMalformedProof
	}
	return Report{
		OperationID:     proof.OperationID,
		Digest:          proof.Digest,
		Accepted:        true,
		ProductionReady: false,
		Mode:            "fake",
	}, nil
}
