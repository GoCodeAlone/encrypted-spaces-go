package proof

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/GoCodeAlone/encrypted-spaces-go/operationlog"
)

func TestProofEvidenceSerializationRedactsOperationBodyAndKeyMaterial(t *testing.T) {
	log, err := operationlog.NewLog(operationlog.LogOptions{})
	if err != nil {
		t.Fatalf("NewLog: %v", err)
	}
	operation := encryptedOperation("plaintext operation body and key material")
	operation.Nonce = []byte("secret nonce key material")
	operation.AssociatedData = []byte("associated key material")
	commitment, err := log.Append(operation)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	evidence := NewOperationEvidence(commitment, []Report{{
		Domain:          "zkgroup.membership",
		Accepted:        true,
		ProductionReady: true,
		UpstreamPath:    "java/shared/java/org/signal/libsignal/zkgroup/groups",
	}})
	raw, err := json.Marshal(evidence)
	if err != nil {
		t.Fatalf("Marshal evidence: %v", err)
	}
	encoded := string(raw)
	for _, forbidden := range []string{
		"plaintext operation body",
		"secret nonce",
		"associated key material",
		"key material",
	} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("evidence JSON leaked %q: %s", forbidden, encoded)
		}
	}
	for _, required := range []string{
		string(commitment.OperationID),
		commitment.Digest,
		"zkgroup.membership",
	} {
		if !strings.Contains(encoded, required) {
			t.Fatalf("evidence JSON missing %q: %s", required, encoded)
		}
	}
}
