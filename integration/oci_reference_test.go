package integration_test

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

func TestRegistryImageReferenceScan(t *testing.T) {
	imageDir := ociTestLayout(t)
	manifest := ociTestImage(t, imageDir, "linux", runtime.GOARCH, []ociTestLayer{{gzip: true, entries: []ociTestEntry{{name: "var/lib/dpkg/status", data: ociTestStatus(t, "dpkg-basic")}}}})
	ociTestIndex(t, imageDir, manifest)
	imageLayout, err := layout.FromPath(imageDir)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := v1.NewHash(manifest.Digest)
	if err != nil {
		t.Fatal(err)
	}
	img, err := imageLayout.Image(hash)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(registry.New())
	defer server.Close()
	reference := strings.TrimPrefix(server.URL, "http://") + "/ravel/sample:tag"
	ref, err := name.ParseReference(reference, name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(ref, img); err != nil {
		t.Fatal(err)
	}
	doc, output, code := ociTestScan(t, reference, "--platform", "linux/"+runtime.GOARCH)
	if code != 0 || doc.Coverage.Packages != 4 || doc.Coverage.Manager != "oci" {
		t.Fatalf("registry scan failed: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
	expectedSource := ref.Context().Name() + "@" + manifest.Digest
	if doc.Source != expectedSource || len(doc.Sources) != 1 || doc.Sources[0] != expectedSource {
		t.Fatalf("registry source should contain the selected immutable digest: %#v", doc.Sources)
	}
	if byDigest, output, code := ociTestScan(t, expectedSource); code != 0 || byDigest.Source != expectedSource || byDigest.Coverage.Packages != doc.Coverage.Packages {
		t.Fatalf("digest reference scan failed: code=%d output=%s source=%s", code, output, byDigest.Source)
	}
	if _, output, code := ociTestScan(t, reference, "--network", "deny"); code != 2 || !strings.Contains(output, "require network access") {
		t.Fatalf("explicit network deny was accepted: code=%d output=%s", code, output)
	}
}

func TestLocalDockerImageReferenceScan(t *testing.T) {
	archive := dockerTestArchive(t, "sample.docker.tar", dockerTestEntries(t, []ociTestLayer{{entries: []ociTestEntry{{name: "var/lib/dpkg/status", data: ociTestStatus(t, "dpkg-basic")}}}}))
	binDir := t.TempDir()
	script := "#!/bin/sh\nif [ \"$1\" != image ] || [ \"$2\" != save ]; then exit 2; fi\nexec cat \"$RAVEL_TEST_DOCKER_ARCHIVE\"\n"
	if err := os.WriteFile(filepath.Join(binDir, "docker"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RAVEL_TEST_DOCKER_ARCHIVE", archive)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	doc, output, code := ociTestScan(t, "sample:tag", "--image-source", "docker")
	if code != 0 || doc.Coverage.Packages != 4 || doc.Source != "docker:sample:tag" || len(doc.Sources) != 1 || doc.Sources[0] != doc.Source {
		t.Fatalf("local Docker scan failed: code=%d output=%s source=%s coverage=%#v", code, output, doc.Source, doc.Coverage)
	}
}

func TestRegistryMultiPlatformImageSelectsRequestedManifest(t *testing.T) {
	otherArch := "arm64"
	if runtime.GOARCH == "arm64" {
		otherArch = "amd64"
	}
	imageDir := ociTestLayout(t)
	first := ociTestImage(t, imageDir, "linux", runtime.GOARCH, []ociTestLayer{{entries: []ociTestEntry{{name: "var/lib/dpkg/status", data: ociTestStatus(t, "dpkg-basic")}}}})
	second := ociTestImage(t, imageDir, "linux", otherArch, []ociTestLayer{{entries: []ociTestEntry{{name: "var/lib/dpkg/status", data: ociTestStatus(t, "dpkg-versioned-provide")}}}})
	ociTestIndex(t, imageDir, first, second)
	imageLayout, err := layout.FromPath(imageDir)
	if err != nil {
		t.Fatal(err)
	}
	load := func(descriptor ociTestDescriptor) v1.Image {
		t.Helper()
		hash, err := v1.NewHash(descriptor.Digest)
		if err != nil {
			t.Fatal(err)
		}
		img, err := imageLayout.Image(hash)
		if err != nil {
			t.Fatal(err)
		}
		return img
	}
	index := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: load(first), Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: runtime.GOARCH}}},
		mutate.IndexAddendum{Add: load(second), Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: otherArch}}},
	)
	server := httptest.NewServer(registry.New())
	defer server.Close()
	reference := strings.TrimPrefix(server.URL, "http://") + "/ravel/multi:tag"
	ref, err := name.ParseReference(reference, name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.WriteIndex(ref, index); err != nil {
		t.Fatal(err)
	}
	defaultDoc, output, code := ociTestScan(t, reference)
	if code != 0 || defaultDoc.Coverage.Packages != 4 || defaultDoc.Source != ref.Context().Name()+"@"+first.Digest {
		t.Fatalf("default platform selection failed: code=%d output=%s source=%s coverage=%#v", code, output, defaultDoc.Source, defaultDoc.Coverage)
	}
	selectedDoc, output, code := ociTestScan(t, reference, "--platform", "linux/"+otherArch)
	if code != 0 || selectedDoc.Coverage.Packages != 2 || selectedDoc.Source != ref.Context().Name()+"@"+second.Digest {
		t.Fatalf("requested platform selection failed: code=%d output=%s source=%s coverage=%#v", code, output, selectedDoc.Source, selectedDoc.Coverage)
	}
}
