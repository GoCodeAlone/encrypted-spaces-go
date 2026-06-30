package epochs

import (
	"errors"
	"sync"

	"github.com/GoCodeAlone/encrypted-spaces-go/operationlog"
)

type MemberAction string

const (
	MemberActionAdd    MemberAction = "add"
	MemberActionRemove MemberAction = "remove"
)

var (
	ErrMemberAlreadyExists = errors.New("member already exists")
	ErrMemberNotFound      = errors.New("member not found")
	ErrMemberRemoved       = errors.New("member removed")
	ErrUnknownMemberAction = errors.New("unknown member action")
	ErrSpaceMismatch       = errors.New("space mismatch")
)

type MemberUpdate struct {
	MemberID operationlog.MemberID
	Action   MemberAction
	Reason   string
}

type SpaceState struct {
	mu              sync.Mutex
	spaceID         operationlog.SpaceID
	keyEpoch        operationlog.KeyEpoch
	membershipEpoch operationlog.MembershipEpoch
	members         map[operationlog.MemberID]bool
	removed         map[operationlog.MemberID]bool
}

func NewSpaceState(spaceID operationlog.SpaceID, members []operationlog.MemberID) *SpaceState {
	state := &SpaceState{
		spaceID:         spaceID,
		keyEpoch:        1,
		membershipEpoch: 1,
		members:         make(map[operationlog.MemberID]bool, len(members)),
		removed:         make(map[operationlog.MemberID]bool),
	}
	for _, member := range members {
		state.members[member] = true
	}
	return state
}

func (s *SpaceState) RotateKeyEpoch(reason string) operationlog.KeyEpoch {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keyEpoch++
	return s.keyEpoch
}

func (s *SpaceState) ApplyMemberUpdate(update MemberUpdate) (operationlog.MembershipEpoch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch update.Action {
	case MemberActionAdd:
		if s.members[update.MemberID] {
			return 0, ErrMemberAlreadyExists
		}
		s.members[update.MemberID] = true
		delete(s.removed, update.MemberID)
	case MemberActionRemove:
		if !s.members[update.MemberID] {
			return 0, ErrMemberNotFound
		}
		delete(s.members, update.MemberID)
		s.removed[update.MemberID] = true
	default:
		return 0, ErrUnknownMemberAction
	}

	s.membershipEpoch++
	return s.membershipEpoch, nil
}

func (s *SpaceState) AllowsMember(memberID operationlog.MemberID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.members[memberID]
}

func (s *SpaceState) ValidateOperation(operation operationlog.EncryptedOperation) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if operation.SpaceID != s.spaceID {
		return ErrSpaceMismatch
	}
	if s.removed[operation.MemberID] {
		return ErrMemberRemoved
	}
	if !s.members[operation.MemberID] {
		return ErrMemberNotFound
	}
	return nil
}

func (s *SpaceState) KeyEpoch() operationlog.KeyEpoch {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keyEpoch
}

func (s *SpaceState) MembershipEpoch() operationlog.MembershipEpoch {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.membershipEpoch
}
