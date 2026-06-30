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
	Name   string
	Status string
	Notes  string
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
				Status: "vector-checked",
				Notes:  "Membership credential verification API covered by deterministic compatibility vectors.",
			},
			{
				Name:   "zkcredential",
				Status: "vector-checked",
				Notes:  "Credential presentation verification API covered by deterministic compatibility vectors.",
			},
			{
				Name:   "poksho",
				Status: "vector-checked",
				Notes:  "Proof transcript verification API covered by deterministic compatibility vectors.",
			},
			{
				Name:   "keytrans",
				Status: "vector-checked",
				Notes:  "Key transparency checkpoint verification API covered by deterministic compatibility vectors.",
			},
		},
	}
}
