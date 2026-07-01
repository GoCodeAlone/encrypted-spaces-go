package keytrans

import (
	"encoding/json"
	"os"
	"testing"
)

func TestVerifyCheckpointVector(t *testing.T) {
	vector := loadCheckpointVector(t)
	report, err := VerifyCheckpoint(Checkpoint{
		CheckpointID: vector.Cases[0].CheckpointID,
		TreeHead:     vector.Cases[0].TreeHead,
		TreeSize:     vector.Cases[0].TreeSize,
		ProofDigest:  vector.Cases[0].ProofDigest,
		UpstreamPath: vector.Source,
	})
	if err != nil {
		t.Fatalf("VerifyCheckpoint: %v", err)
	}
	if !report.Accepted || !report.ProductionReady {
		t.Fatalf("report = %#v, want accepted production-ready", report)
	}
}

func loadCheckpointVector(t *testing.T) struct {
	Source string `json:"source"`
	Cases  []struct {
		CheckpointID string `json:"checkpoint_id"`
		TreeHead     string `json:"tree_head"`
		TreeSize     uint64 `json:"tree_size"`
		ProofDigest  string `json:"proof_digest"`
	} `json:"cases"`
} {
	t.Helper()
	raw, err := os.ReadFile("../testdata/upstream-vectors/keytrans-checkpoint.json")
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var vector struct {
		Source string `json:"source"`
		Cases  []struct {
			CheckpointID string `json:"checkpoint_id"`
			TreeHead     string `json:"tree_head"`
			TreeSize     uint64 `json:"tree_size"`
			ProofDigest  string `json:"proof_digest"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatalf("decode vector: %v", err)
	}
	if len(vector.Cases) == 0 {
		t.Fatal("vector has no cases")
	}
	return vector
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
