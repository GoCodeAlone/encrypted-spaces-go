package upstream

import (
	"strings"
	"testing"
	"time"
)

func TestManifestPinsLibsignalRelease(t *testing.T) {
	manifest := CurrentManifest()

	if manifest.SourceRepo != "signalapp/libsignal" {
		t.Fatalf("SourceRepo = %q, want signalapp/libsignal", manifest.SourceRepo)
	}
	if !strings.HasPrefix(manifest.SourceTag, "v") {
		t.Fatalf("SourceTag = %q, want v-prefixed release tag", manifest.SourceTag)
	}
	if _, err := time.Parse(time.RFC3339, manifest.PublishedAt); err != nil {
		t.Fatalf("PublishedAt = %q, want RFC3339 timestamp: %v", manifest.PublishedAt, err)
	}
	if manifest.Compatibility != "wire-compatible-source" {
		t.Fatalf("Compatibility = %q, want wire-compatible-source", manifest.Compatibility)
	}
	if len(manifest.Domains) == 0 {
		t.Fatal("Domains is empty")
	}
}

func TestManifestDeclaresDeferredProofDomains(t *testing.T) {
	manifest := CurrentManifest()
	want := map[string]string{
		"zkgroup":      "vector-checked",
		"zkcredential": "vector-checked",
		"poksho":       "deferred",
		"keytrans":     "deferred",
	}

	for _, domain := range manifest.Domains {
		if status, ok := want[domain.Name]; ok {
			delete(want, domain.Name)
			if domain.Status != status {
				t.Fatalf("%s status = %q, want %s", domain.Name, domain.Status, status)
			}
		}
	}
	for name := range want {
		t.Fatalf("missing proof domain %s", name)
	}
}
