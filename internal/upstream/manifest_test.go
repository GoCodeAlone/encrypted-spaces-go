package upstream

import "testing"

func TestManifestPinsLibsignalRelease(t *testing.T) {
	manifest := CurrentManifest()

	if manifest.SourceRepo != "signalapp/libsignal" {
		t.Fatalf("SourceRepo = %q, want signalapp/libsignal", manifest.SourceRepo)
	}
	if manifest.SourceTag != "v0.96.4" {
		t.Fatalf("SourceTag = %q, want v0.96.4", manifest.SourceTag)
	}
	if manifest.PublishedAt != "2026-06-25T21:34:59Z" {
		t.Fatalf("PublishedAt = %q, want upstream release timestamp", manifest.PublishedAt)
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
	want := map[string]bool{
		"zkgroup":      false,
		"zkcredential": false,
		"poksho":       false,
		"keytrans":     false,
	}

	for _, domain := range manifest.Domains {
		if _, ok := want[domain.Name]; ok {
			want[domain.Name] = true
			if domain.Status != "deferred" {
				t.Fatalf("%s status = %q, want deferred", domain.Name, domain.Status)
			}
		}
	}
	for name, seen := range want {
		if !seen {
			t.Fatalf("missing proof domain %s", name)
		}
	}
}
