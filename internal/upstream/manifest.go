package upstream

// Manifest records the upstream libsignal release used as the compatibility
// source for Encrypted Spaces wire and proof domains.
type Manifest struct {
	SourceRepo    string
	SourceTag     string
	PublishedAt   string
	Compatibility string
	Domains       []Domain
}

// Domain records one upstream proof or wire-compatibility area and its local
// implementation status.
type Domain struct {
	Name              string
	Status            string
	Vector            string
	Reason            string
	NextUpstreamInput string
	Notes             string
}

// CurrentManifest returns the pinned upstream source for this module.
func CurrentManifest() Manifest {
	return Manifest{
		SourceRepo:    "signalapp/libsignal",
		SourceTag:     "v0.96.4",
		PublishedAt:   "2026-06-25T21:34:59Z",
		Compatibility: "wire-compatible-source",
		Domains: []Domain{
			{
				Name:   "operationlog",
				Status: "planned",
				Notes:  "Encrypted operation log foundation for Workflow spaces primitives.",
			},
			{
				Name:   "zkgroup",
				Status: "vector-backed",
				Vector: "testdata/upstream-vectors/zkgroup-membership.json",
				Notes:  "Membership credential verification API covered by deterministic compatibility vectors.",
			},
			{
				Name:   "zkcredential",
				Status: "vector-backed",
				Vector: "testdata/upstream-vectors/zkcredential-presentation.json",
				Notes:  "Credential presentation verification API covered by deterministic compatibility vectors.",
			},
			{
				Name:   "poksho",
				Status: "vector-backed",
				Vector: "testdata/upstream-vectors/poksho-transcript.json",
				Notes:  "Proof transcript verification API covered by deterministic compatibility vectors.",
			},
			{
				Name:   "keytrans",
				Status: "vector-backed",
				Vector: "testdata/upstream-vectors/keytrans-checkpoint.json",
				Notes:  "Key transparency checkpoint verification API covered by deterministic compatibility vectors.",
			},
			{
				Name:              "message-backup",
				Status:            "deferred",
				Reason:            "Message-backup proof vectors require the backup/SVR proof boundary planned for the next phase.",
				NextUpstreamInput: "Stable upstream message-backup proof vectors and backup manifest schemas.",
				Notes:             "No production-equivalence claim is made for message-backup proofs in this release.",
			},
			{
				Name:              "svr-svrb",
				Status:            "deferred",
				Reason:            "SVR/SVRB proof vectors require upstream proof-system fixtures not yet carried in this module.",
				NextUpstreamInput: "Stable upstream SVR/SVRB proof fixtures and service transcript inputs.",
				Notes:             "Coverage is reported as deferred instead of vector-backed.",
			},
		},
	}
}
