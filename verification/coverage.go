package verification

import "github.com/GoCodeAlone/encrypted-spaces-go/internal/upstream"

type ProofCoverage struct {
	UpstreamTag          string
	ProductionEquivalent bool
	Rows                 []ProofCoverageRow
}

type ProofCoverageRow struct {
	Domain            string
	Status            string
	Vector            string
	Reason            string
	NextUpstreamInput string
	Notes             string
}

func ProofCoverageReport() ProofCoverage {
	manifest := upstream.CurrentManifest()
	report := ProofCoverage{
		UpstreamTag:          manifest.SourceTag,
		ProductionEquivalent: true,
		Rows:                 make([]ProofCoverageRow, 0, len(manifest.Domains)),
	}
	for _, domain := range manifest.Domains {
		row := ProofCoverageRow{
			Domain:            domain.Name,
			Status:            domain.Status,
			Vector:            domain.Vector,
			Reason:            domain.Reason,
			NextUpstreamInput: domain.NextUpstreamInput,
			Notes:             domain.Notes,
		}
		if domain.Status != "vector-backed" {
			report.ProductionEquivalent = false
		}
		report.Rows = append(report.Rows, row)
	}
	return report
}
