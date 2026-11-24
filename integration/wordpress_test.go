package integration_test

import (
	"archive/tar"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Pirikara/Ravel/internal/model"
)

func TestWordPressRepositoryInventory(t *testing.T) {
	fixture := filepath.Join("..", "testdata", "wordpress-installed")
	output := filepath.Join(t.TempDir(), "scan.json")
	cmd := exec.Command(executable, "scan", fixture, "--all", "--recursive", "--format", "ravel-json", "--output", output)
	if data, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("WordPress repository scan: %v: %s", err, data)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"Create Block Theme": "2.10.2", "Secure Custom Fields": "6.9.8", "Hello Dolly": "1.7.2", "Site Loader": ""}
	if len(doc.Components) != len(want) || len(doc.Edges) != len(want) {
		t.Fatalf("nested implementation or documentation was counted: %#v", doc.Components)
	}
	for _, component := range doc.Components {
		version, exists := want[component.Name]
		if !exists || version != component.Version || component.PURL != "" || !strings.Contains(component.Context, "ecosystem=wordpress-plugin;") {
			t.Fatalf("plugin identity: %#v", component)
		}
		for _, evidence := range component.Evidence {
			if evidence.Collector != "wordpress-plugin-header" || evidence.Method != "header-prefix-analysis" || !strings.HasPrefix(evidence.Pointer, "bytes/0:") || evidence.Line == 0 {
				t.Fatalf("plugin header evidence: %#v", evidence)
			}
		}
	}
	if len(doc.Origins) != 0 || doc.Coverage.GraphState != "partial" || doc.Coverage.OriginState != "partial" {
		t.Fatalf("unverified activation or distribution origin was asserted: %#v", doc)
	}
}

func TestWordPressExplicitInputAndOverwriteProtection(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "custom.php")
	const header = "<?php /* Plugin Name: Custom Plugin\nVersion: 1.0-beta */\nthrow new Exception('do not run');"
	if err := os.WriteFile(file, []byte(header), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{file, dir} {
		output := filepath.Join(t.TempDir(), "scan.json")
		cmd := exec.Command(executable, "scan", input, "--manager", "wordpress", "--format", "ravel-json", "--output", output)
		if data, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("explicit WordPress input: %v: %s", err, data)
		}
	}
	for _, flags := range [][]string{nil, {"--all", "--recursive"}} {
		args := append([]string{"scan", dir}, flags...)
		args = append(args, "--output", file)
		if err := exec.Command(executable, args...).Run(); err == nil {
			t.Fatal("plugin header could be overwritten")
		}
	}
	data, err := os.ReadFile(file)
	if err != nil || string(data) != header {
		t.Fatal("plugin input was modified")
	}
}

func TestOCIWordPressPluginsFinalLayers(t *testing.T) {
	const base = "var/www/html/wp-content/"
	a := base + "plugins/a/a.php"
	b := base + "plugins/b/b.php"
	header := func(name, version string) []byte {
		return []byte("<?php\n/*\nPlugin Name: " + name + "\nVersion: " + version + "\n*/")
	}
	for _, tc := range []struct {
		name  string
		upper []ociTestEntry
		want  map[string]string
	}{
		{"base", nil, map[string]string{"A": "1.0", "B": "2-beta.1", "Loose": "3", "MU": "4"}},
		{"replacement", []ociTestEntry{{name: b, data: header("B", "5")}}, map[string]string{"A": "1.0", "B": "5", "Loose": "3", "MU": "4"}},
		{"whiteout", []ociTestEntry{{name: base + "plugins/b/.wh.b.php"}}, map[string]string{"A": "1.0", "Loose": "3", "MU": "4"}},
		{"opaque", []ociTestEntry{{name: base + "plugins/.wh..wh..opq"}}, map[string]string{"MU": "4"}},
		{"parent_symlink", []ociTestEntry{{name: base + "plugins", typeflag: tar.TypeSymlink, linkname: "/elsewhere"}}, map[string]string{"MU": "4"}},
		{"file_symlink", []ociTestEntry{{name: b, typeflag: tar.TypeSymlink, linkname: "/elsewhere/b.php"}}, map[string]string{"A": "1.0", "Loose": "3", "MU": "4"}},
		{"non_plugin_replacement", []ociTestEntry{{name: b, data: []byte("<?php // ordinary code")}}, map[string]string{"A": "1.0", "Loose": "3", "MU": "4"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			layout := ociTestLayout(t)
			layers := []ociTestLayer{{entries: []ociTestEntry{
				{name: a, data: header("A", "1.0")}, {name: b, data: header("B", "2-beta.1")},
				{name: base + "plugins/loose.php", data: header("Loose", "3")},
				{name: base + "mu-plugins/loader.php", data: header("MU", "4")},
				{name: base + "plugins/a/includes/test.php", data: header("Nested", "99")},
				{name: base + "mu-plugins/nested/test.php", data: header("Unloaded MU", "99")},
			}}}
			if tc.upper != nil {
				layers = append(layers, ociTestLayer{entries: tc.upper})
			}
			image := ociTestImage(t, layout, "linux", "arm64", layers)
			ociTestIndex(t, layout, image)
			doc, output, code := ociTestScan(t, layout)
			if code != 0 || len(doc.Components) != len(tc.want) {
				t.Fatalf("OCI plugin scan: code=%d output=%s components=%#v", code, output, doc.Components)
			}
			for _, component := range doc.Components {
				version, found := tc.want[component.Name]
				if !found || component.Version != version || component.PURL != "" || !strings.HasPrefix(component.Evidence[0].InputPath, "oci:sha256:") {
					t.Fatalf("final plugin identity/evidence: %#v", component)
				}
			}
		})
	}
}
