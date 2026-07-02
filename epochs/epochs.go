package epochs

import (
	"errors"
	"fmt"
	"slices"
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
	ErrInvalidSnapshot     = errors.New("invalid space snapshot")
)

type MemberUpdate struct {
	MemberID operationlog.MemberID
	Action   MemberAction
	Reason   string
}

type SpaceSnapshot struct {
	SpaceID         operationlog.SpaceID
	KeyEpoch        operationlog.KeyEpoch
	MembershipEpoch operationlog.MembershipEpoch
	Members         []operationlog.MemberID
	RemovedMembers  []operationlog.MemberID
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

func NewSpaceStateFromSnapshot(snapshot SpaceSnapshot) (*SpaceState, error) {
	if snapshot.SpaceID == "" {
		return nil, fmt.Errorf("%w: space id is required", ErrInvalidSnapshot)
	}
	if snapshot.KeyEpoch < 1 {
		return nil, fmt.Errorf("%w: key epoch must be at least 1", ErrInvalidSnapshot)
	}
	if snapshot.MembershipEpoch < 1 {
		return nil, fmt.Errorf("%w: membership epoch must be at least 1", ErrInvalidSnapshot)
	}
	state := &SpaceState{
		spaceID:         snapshot.SpaceID,
		keyEpoch:        snapshot.KeyEpoch,
		membershipEpoch: snapshot.MembershipEpoch,
		members:         make(map[operationlog.MemberID]bool, len(snapshot.Members)),
		removed:         make(map[operationlog.MemberID]bool, len(snapshot.RemovedMembers)),
	}
	for _, member := range snapshot.Members {
		if member == "" {
			return nil, fmt.Errorf("%w: active member id is required", ErrInvalidSnapshot)
		}
		if state.members[member] {
			return nil, fmt.Errorf("%w: duplicate active member %q", ErrInvalidSnapshot, member)
		}
		state.members[member] = true
	}
	for _, member := range snapshot.RemovedMembers {
		if member == "" {
			return nil, fmt.Errorf("%w: removed member id is required", ErrInvalidSnapshot)
		}
		if state.members[member] {
			return nil, fmt.Errorf("%w: member %q is both active and removed", ErrInvalidSnapshot, member)
		}
		if state.removed[member] {
			return nil, fmt.Errorf("%w: duplicate removed member %q", ErrInvalidSnapshot, member)
		}
		state.removed[member] = true
	}
	return state, nil
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

func (s *SpaceState) Snapshot() SpaceSnapshot {
	s.mu.Lock()
	snapshot := SpaceSnapshot{
		SpaceID:         s.spaceID,
		KeyEpoch:        s.keyEpoch,
		MembershipEpoch: s.membershipEpoch,
		Members:         make([]operationlog.MemberID, 0, len(s.members)),
		RemovedMembers:  make([]operationlog.MemberID, 0, len(s.removed)),
	}
	for member := range s.members {
		snapshot.Members = append(snapshot.Members, member)
	}
	for member := range s.removed {
		snapshot.RemovedMembers = append(snapshot.RemovedMembers, member)
	}
	s.mu.Unlock()

	slices.Sort(snapshot.Members)
	slices.Sort(snapshot.RemovedMembers)
	return snapshot
}
