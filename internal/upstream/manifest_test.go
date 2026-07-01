package upstream

import (
	"os"
	"path/filepath"
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
		"zkgroup":      "vector-backed",
		"zkcredential": "vector-backed",
		"poksho":       "vector-backed",
		"keytrans":     "vector-backed",
	}

	for _, domain := range manifest.Domains {
		if status, ok := want[domain.Name]; ok {
			delete(want, domain.Name)
			if domain.Status != status {
				t.Fatalf("%s status = %q, want %s", domain.Name, domain.Status, status)
			}
			if domain.Vector == "" {
				t.Fatalf("%s missing vector path", domain.Name)
			}
			if _, err := os.Stat(filepath.Join("..", "..", domain.Vector)); err != nil {
				t.Fatalf("%s vector %q is not readable: %v", domain.Name, domain.Vector, err)
			}
		}
	}
	for name := range want {
		t.Fatalf("missing proof domain %s", name)
	}
}

func TestManifestRecordsDeferredProofGaps(t *testing.T) {
	manifest := CurrentManifest()
	want := map[string]bool{
		"message-backup": false,
		"svr-svrb":       false,
	}
	for _, domain := range manifest.Domains {
		if _, ok := want[domain.Name]; !ok {
			continue
		}
		want[domain.Name] = true
		if domain.Status != "deferred" {
			t.Fatalf("%s status = %q, want deferred", domain.Name, domain.Status)
		}
		if domain.Reason == "" {
			t.Fatalf("%s missing deferred reason", domain.Name)
		}
	}
	for name, seen := range want {
		if !seen {
			t.Fatalf("missing deferred domain %s", name)
		}
	}
}
