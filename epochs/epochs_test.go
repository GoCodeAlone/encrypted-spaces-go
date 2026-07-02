package epochs

import (
	"errors"
	"slices"
	"testing"

	"github.com/GoCodeAlone/encrypted-spaces-go/operationlog"
)

func TestEpochRotation(t *testing.T) {
	state := NewSpaceState("space-1", []operationlog.MemberID{"member-1", "member-2"})

	keyEpoch := state.RotateKeyEpoch("scheduled rotation")
	if keyEpoch != 2 {
		t.Fatalf("RotateKeyEpoch = %d, want 2", keyEpoch)
	}

	membershipEpoch, err := state.ApplyMemberUpdate(MemberUpdate{
		MemberID: "member-3",
		Action:   MemberActionAdd,
		Reason:   "invite",
	})
	if err != nil {
		t.Fatalf("ApplyMemberUpdate add returned error: %v", err)
	}
	if membershipEpoch != 2 {
		t.Fatalf("membership epoch after add = %d, want 2", membershipEpoch)
	}
	if !state.AllowsMember("member-3") {
		t.Fatal("new member is not allowed")
	}
}

func TestRemovedMemberRejected(t *testing.T) {
	state := NewSpaceState("space-1", []operationlog.MemberID{"member-1", "member-2"})

	if _, err := state.ApplyMemberUpdate(MemberUpdate{
		MemberID: "member-2",
		Action:   MemberActionRemove,
		Reason:   "access revoked",
	}); err != nil {
		t.Fatalf("ApplyMemberUpdate remove returned error: %v", err)
	}

	if state.AllowsMember("member-2") {
		t.Fatal("removed member is still allowed")
	}

	op := operationlog.EncryptedOperation{
		SpaceID:         "space-1",
		MemberID:        "member-2",
		OperationID:     "op-removed",
		KeyEpoch:        state.KeyEpoch(),
		MembershipEpoch: state.MembershipEpoch(),
	}
	if err := state.ValidateOperation(op); !errors.Is(err, ErrMemberRemoved) {
		t.Fatalf("ValidateOperation removed member error = %v, want ErrMemberRemoved", err)
	}
}

func TestMemberUpdateValidation(t *testing.T) {
	state := NewSpaceState("space-1", []operationlog.MemberID{"member-1"})

	if _, err := state.ApplyMemberUpdate(MemberUpdate{MemberID: "member-1", Action: MemberActionAdd}); !errors.Is(err, ErrMemberAlreadyExists) {
		t.Fatalf("duplicate add error = %v, want ErrMemberAlreadyExists", err)
	}
	if _, err := state.ApplyMemberUpdate(MemberUpdate{MemberID: "missing", Action: MemberActionRemove}); !errors.Is(err, ErrMemberNotFound) {
		t.Fatalf("missing remove error = %v, want ErrMemberNotFound", err)
	}
}

func TestSpaceStateSnapshotIsSortedAndImmutable(t *testing.T) {
	state := NewSpaceState("space-1", []operationlog.MemberID{"member-3", "member-1", "member-2"})
	state.RotateKeyEpoch("scheduled")
	if _, err := state.ApplyMemberUpdate(MemberUpdate{MemberID: "member-2", Action: MemberActionRemove}); err != nil {
		t.Fatalf("remove member-2: %v", err)
	}

	snapshot := state.Snapshot()
	if snapshot.SpaceID != "space-1" {
		t.Fatalf("space id = %q, want space-1", snapshot.SpaceID)
	}
	if snapshot.KeyEpoch != 2 {
		t.Fatalf("key epoch = %d, want 2", snapshot.KeyEpoch)
	}
	if snapshot.MembershipEpoch != 2 {
		t.Fatalf("membership epoch = %d, want 2", snapshot.MembershipEpoch)
	}
	if !slices.Equal(snapshot.Members, []operationlog.MemberID{"member-1", "member-3"}) {
		t.Fatalf("members = %v, want sorted active members", snapshot.Members)
	}
	if !slices.Equal(snapshot.RemovedMembers, []operationlog.MemberID{"member-2"}) {
		t.Fatalf("removed members = %v, want member-2", snapshot.RemovedMembers)
	}

	snapshot.Members[0] = "mutated"
	if state.AllowsMember("mutated") {
		t.Fatal("snapshot mutation changed live state")
	}
}

func TestNewSpaceStateFromSnapshotPreservesEpochsAndMembership(t *testing.T) {
	state, err := NewSpaceStateFromSnapshot(SpaceSnapshot{
		SpaceID:         "space-1",
		KeyEpoch:        4,
		MembershipEpoch: 7,
		Members:         []operationlog.MemberID{"member-2", "member-1"},
		RemovedMembers:  []operationlog.MemberID{"member-3"},
	})
	if err != nil {
		t.Fatalf("NewSpaceStateFromSnapshot: %v", err)
	}
	if state.KeyEpoch() != 4 {
		t.Fatalf("key epoch = %d, want 4", state.KeyEpoch())
	}
	if state.MembershipEpoch() != 7 {
		t.Fatalf("membership epoch = %d, want 7", state.MembershipEpoch())
	}
	if !state.AllowsMember("member-1") {
		t.Fatal("member-1 not allowed after hydrate")
	}
	op := operationlog.EncryptedOperation{SpaceID: "space-1", MemberID: "member-3"}
	if err := state.ValidateOperation(op); !errors.Is(err, ErrMemberRemoved) {
		t.Fatalf("removed member validation error = %v, want ErrMemberRemoved", err)
	}

	epoch, err := state.ApplyMemberUpdate(MemberUpdate{MemberID: "member-4", Action: MemberActionAdd})
	if err != nil {
		t.Fatalf("add member-4 after hydrate: %v", err)
	}
	if epoch != 8 {
		t.Fatalf("membership epoch after hydrate add = %d, want 8", epoch)
	}
}

func TestNewSpaceStateFromSnapshotRejectsInvalidSnapshots(t *testing.T) {
	tests := []struct {
		name     string
		snapshot SpaceSnapshot
	}{
		{
			name: "empty space id",
			snapshot: SpaceSnapshot{
				KeyEpoch:        1,
				MembershipEpoch: 1,
			},
		},
		{
			name: "zero key epoch",
			snapshot: SpaceSnapshot{
				SpaceID:         "space-1",
				MembershipEpoch: 1,
			},
		},
		{
			name: "zero membership epoch",
			snapshot: SpaceSnapshot{
				SpaceID:  "space-1",
				KeyEpoch: 1,
			},
		},
		{
			name: "duplicate active member",
			snapshot: SpaceSnapshot{
				SpaceID:         "space-1",
				KeyEpoch:        1,
				MembershipEpoch: 1,
				Members:         []operationlog.MemberID{"member-1", "member-1"},
			},
		},
		{
			name: "empty active member",
			snapshot: SpaceSnapshot{
				SpaceID:         "space-1",
				KeyEpoch:        1,
				MembershipEpoch: 1,
				Members:         []operationlog.MemberID{""},
			},
		},
		{
			name: "active and removed overlap",
			snapshot: SpaceSnapshot{
				SpaceID:         "space-1",
				KeyEpoch:        1,
				MembershipEpoch: 1,
				Members:         []operationlog.MemberID{"member-1"},
				RemovedMembers:  []operationlog.MemberID{"member-1"},
			},
		},
		{
			name: "duplicate removed member",
			snapshot: SpaceSnapshot{
				SpaceID:         "space-1",
				KeyEpoch:        1,
				MembershipEpoch: 1,
				RemovedMembers:  []operationlog.MemberID{"member-1", "member-1"},
			},
		},
		{
			name: "empty removed member",
			snapshot: SpaceSnapshot{
				SpaceID:         "space-1",
				KeyEpoch:        1,
				MembershipEpoch: 1,
				RemovedMembers:  []operationlog.MemberID{""},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewSpaceStateFromSnapshot(tt.snapshot); !errors.Is(err, ErrInvalidSnapshot) {
				t.Fatalf("NewSpaceStateFromSnapshot error = %v, want ErrInvalidSnapshot", err)
			}
		})
	}
}
