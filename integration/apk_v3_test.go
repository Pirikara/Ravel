package integration_test

import (
	"bytes"
	"compress/flate"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Pirikara/Ravel/internal/model"
)

func TestAPKConvertedV3DatabaseAndEvidence(t *testing.T) {
	fixture := apkFixture(t, "apk-v3-converted")
	installed := filepath.Join(fixture, "lib", "apk", "db", "installed.adb")
	doc, output, code := scanAPK(t, installed)
	if code != 0 || doc.Coverage.Packages != 16 || doc.Coverage.Edges != 40 || doc.Coverage.GraphState != "complete_for_scope" {
		t.Fatalf("APK v3 scan failed: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
	expected := map[string]string{"apk-tools": "3.0.8-r0", "busybox": "1.37.0-r30", "musl": "1.2.5-r24", "libcrypto3": "3.5.9-r0"}
	for _, component := range doc.Components {
		if want, found := expected[component.Name]; found && component.Version != want {
			t.Fatalf("APK v3 package %s version %s, want %s", component.Name, component.Version, want)
		}
		if component.Platform != "aarch64" || component.PURL != "" || component.Evidence[0].Collector != "apk-installed-adb" || component.Evidence[0].Line != 0 || !strings.HasSuffix(component.Evidence[0].InputPath, "installed.adb") {
			t.Fatalf("APK v3 identity or evidence overstated: %#v", component)
		}
	}
	if dirDoc, output, code := scanAPK(t, fixture); code != 0 || dirDoc.Coverage.Packages != 16 {
		t.Fatalf("APK v3 rootfs scan failed: code=%d output=%s", code, output)
	}
	reference, err := os.ReadFile(filepath.Join(fixture, "reference", "installed-v2"))
	if err != nil {
		t.Fatal(err)
	}
	v2Path := filepath.Join(t.TempDir(), "lib", "apk", "db", "installed")
	if err := os.MkdirAll(filepath.Dir(v2Path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(v2Path, reference, 0o644); err != nil {
		t.Fatal(err)
	}
	v2Doc, output, code := scanAPK(t, v2Path)
	if code != 0 {
		t.Fatalf("APK v2 reference scan failed: code=%d output=%s", code, output)
	}
	canonical := func(document model.Document) (map[string]bool, map[string]bool) {
		packages := map[string]bool{}
		ids := map[string]string{"root": "root"}
		for _, component := range document.Components {
			key := component.Name + "@" + component.Version + ":" + component.Platform
			packages[key] = true
			ids[component.ID] = key
		}
		edges := map[string]bool{}
		for _, edge := range document.Edges {
			edges[ids[edge.From]+"->"+ids[edge.To]+":"+edge.Kind+":"+edge.Condition] = true
		}
		return packages, edges
	}
	v2Packages, v2Edges := canonical(v2Doc)
	v3Packages, v3Edges := canonical(doc)
	if !maps.Equal(v2Packages, v3Packages) || !maps.Equal(v2Edges, v3Edges) {
		t.Fatal("converted APK v3 database differs from its original v2 package graph")
	}

	data, err := os.ReadFile(installed)
	if err != nil {
		t.Fatal(err)
	}
	reader := flate.NewReader(bytes.NewReader(data[4:]))
	plain, err := io.ReadAll(reader)
	reader.Close()
	if err != nil {
		t.Fatal(err)
	}
	uncompressed := filepath.Join(t.TempDir(), "lib", "apk", "db", "installed.adb")
	if err := os.MkdirAll(filepath.Dir(uncompressed), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(uncompressed, plain, 0o644); err != nil {
		t.Fatal(err)
	}
	if plainDoc, output, code := scanAPK(t, uncompressed); code != 0 || plainDoc.Coverage.Packages != 16 || plainDoc.Coverage.Edges != 40 {
		t.Fatalf("uncompressed APK v3 scan failed: code=%d output=%s", code, output)
	}
	for _, name := range []string{"installed-none.adb", "installed-deflate6.adb", "installed-zstd.adb"} {
		t.Run(name, func(t *testing.T) {
			variant, err := os.ReadFile(filepath.Join(fixture, "reference", name))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(uncompressed, variant, 0o644); err != nil {
				t.Fatal(err)
			}
			variantDoc, output, code := scanAPK(t, uncompressed)
			if code != 0 || variantDoc.Coverage.Packages != 16 || variantDoc.Coverage.Edges != 40 {
				t.Fatalf("APK v3 %s scan failed: code=%d output=%s coverage=%#v", name, code, output, variantDoc.Coverage)
			}
			packages, edges := canonical(variantDoc)
			if !maps.Equal(v2Packages, packages) || !maps.Equal(v2Edges, edges) {
				t.Fatalf("APK v3 %s differs from the original v2 package graph", name)
			}
		})
	}
	wrappedNone := append([]byte("ADBc\x00\x01"), plain...)
	if err := os.WriteFile(uncompressed, wrappedNone, 0o644); err != nil {
		t.Fatal(err)
	}
	if noneDoc, output, code := scanAPK(t, uncompressed); code != 0 || noneDoc.Coverage.Packages != 16 || noneDoc.Coverage.Edges != 40 {
		t.Fatalf("custom uncompressed APK v3 scan failed: code=%d output=%s", code, output)
	}

	for _, corrupted := range [][]byte{
		[]byte("ADBc"),
		[]byte("ADBc\x03\x00"),
		[]byte("ADBc\x01\x06"),
		[]byte("ADBc\x02\x03"),
		data[:len(data)/2],
		append([]byte(nil), []byte("ADB.unknown")...),
	} {
		if err := os.WriteFile(uncompressed, corrupted, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, output, code := scanAPK(t, uncompressed); code == 0 || !strings.Contains(output, "APK v3") {
			t.Fatalf("malformed APK v3 accepted: code=%d output=%s", code, output)
		}
	}

	if err := os.WriteFile(uncompressed, plain, 0o644); err != nil {
		t.Fatal(err)
	}
	textPath := filepath.Join(filepath.Dir(uncompressed), "installed")
	if err := os.WriteFile(textPath, ociTestAPKInstalled(t, "apk-basic"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, output, code := scanAPK(t, filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(uncompressed))))); code == 0 || !strings.Contains(output, "multiple APK installed databases") {
		t.Fatalf("ambiguous APK databases accepted: code=%d output=%s", code, output)
	}
}

func TestOCIAPKConvertedV3Overlay(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(apkFixture(t, "apk-v3-converted"), "lib", "apk", "db", "installed.adb"))
	if err != nil {
		t.Fatal(err)
	}
	layout := ociTestLayout(t)
	manifest := ociTestImage(t, layout, "linux", "arm64", []ociTestLayer{
		{entries: []ociTestEntry{{name: "lib/apk/db/installed.adb", data: data}}},
	})
	ociTestIndex(t, layout, manifest)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || doc.Coverage.Packages != 16 || doc.Coverage.Edges != 40 {
		t.Fatalf("OCI APK v3 scan failed: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
	for _, component := range doc.Components {
		if component.Evidence[0].Collector != "apk-installed-adb" || !strings.Contains(component.Evidence[0].InputPath, "!/lib/apk/db/installed.adb") {
			t.Fatalf("OCI APK v3 layer evidence wrong: %#v", component)
		}
	}
	zstdData, err := os.ReadFile(filepath.Join(apkFixture(t, "apk-v3-converted"), "reference", "installed-zstd.adb"))
	if err != nil {
		t.Fatal(err)
	}
	zstdLayout := ociTestLayout(t)
	zstdManifest := ociTestImage(t, zstdLayout, "linux", "arm64", []ociTestLayer{
		{entries: []ociTestEntry{{name: "lib/apk/db/installed.adb", data: zstdData}}},
	})
	ociTestIndex(t, zstdLayout, zstdManifest)
	zstdDoc, output, code := ociTestScan(t, zstdLayout)
	if code != 0 || zstdDoc.Coverage.Packages != 16 || zstdDoc.Coverage.Edges != 40 {
		t.Fatalf("OCI APK v3 zstd scan failed: code=%d output=%s coverage=%#v", code, output, zstdDoc.Coverage)
	}

	replaced := ociTestLayout(t)
	manifest = ociTestImage(t, replaced, "linux", "arm64", []ociTestLayer{
		{entries: []ociTestEntry{{name: "lib/apk/db/installed.adb", data: data}}},
		{entries: []ociTestEntry{{name: "lib/apk/db/.wh.installed.adb"}, {name: "lib/apk/db/installed", data: ociTestAPKInstalled(t, "apk-basic")}}},
	})
	ociTestIndex(t, replaced, manifest)
	doc, output, code = ociTestScan(t, replaced)
	if code != 0 || doc.Coverage.Packages != 3 || doc.Coverage.Edges != 5 {
		t.Fatalf("OCI APK v3 whiteout failed: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
}
