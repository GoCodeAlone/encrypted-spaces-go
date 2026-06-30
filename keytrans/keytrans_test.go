package keytrans

import "testing"

func TestVerifyCheckpointVector(t *testing.T) {
	report, err := VerifyCheckpoint(Checkpoint{
		CheckpointID: "checkpoint-1",
		TreeHead:     "tree-head-1",
		TreeSize:     42,
		ProofDigest:  "sha256:479338417f33b12df048fbe2180f58638636b2618d90ac6f807ed436ff881d8c",
		UpstreamPath: "rust/keytrans/src/verify.rs",
	})
	if err != nil {
		t.Fatalf("VerifyCheckpoint: %v", err)
	}
	if !report.Accepted || !report.ProductionReady {
		t.Fatalf("report = %#v, want accepted production-ready", report)
	}
}

func TestVerifyCheckpointRejectsMalformedVector(t *testing.T) {
	_, err := VerifyCheckpoint(Checkpoint{
		CheckpointID: "checkpoint-1",
		TreeHead:     "tree-head-1",
		TreeSize:     42,
		ProofDigest:  "sha256:bad",
	})
	if err == nil {
		t.Fatal("expected malformed checkpoint rejection")
	}
}
