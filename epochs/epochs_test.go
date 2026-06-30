package epochs

import (
	"errors"
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
