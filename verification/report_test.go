package verification

import "testing"

func TestProofCoverageReportDeferredRowsRequireNextInput(t *testing.T) {
	report := ProofCoverageReport()
	seen := map[string]bool{
		"message-backup": false,
		"svr-svrb":       false,
	}
	for _, row := range report.Rows {
		if _, ok := seen[row.Domain]; !ok {
			continue
		}
		seen[row.Domain] = true
		if row.Status != "deferred" {
			t.Fatalf("%s status = %q, want deferred", row.Domain, row.Status)
		}
		if row.Reason == "" || row.NextUpstreamInput == "" {
			t.Fatalf("%s reason=%q next=%q, want both set", row.Domain, row.Reason, row.NextUpstreamInput)
		}
	}
	for domain, ok := range seen {
		if !ok {
			t.Fatalf("missing deferred row %s", domain)
		}
	}
}
