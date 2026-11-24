package wordpress

import (
	"strings"
	"testing"

	"github.com/Pirikara/Ravel/internal/collectors/common"
)

func TestHeaderMatchesWordPressFieldsAndBounds(t *testing.T) {
	for _, tc := range []struct {
		name, header, version string
		found                 bool
		line                  int
	}{
		{"release_suffix", "<?php\n/*\n * Plugin Name: Example\n * Version: 1.2.3-beta.2\n */", "1.2.3-beta.2", true, 3},
		{"case_and_crlf", "<?php\r\n/*\r\nPLUGIN NAME: Example\r\nVERSION: 2.0 */\r\n", "2.0", true, 3},
		{"cr_only", "<?php\r/*\rPlugin Name: Example\rVersion: 3\r*/", "3", true, 3},
		{"version_missing", "/* Plugin Name: Example */", "", true, 1},
		{"first_field_wins", "Plugin Name: Example\nVersion: 1\nVersion: 2", "1", true, 1},
		{"not_a_header", "<?php $s = 'Plugin Name: fake';", "", false, 0},
		{"outside_header", strings.Repeat(" ", HeaderBytes) + "\nPlugin Name: Example\nVersion: 1", "", false, 0},
		{"after_four_kib", strings.Repeat(" ", 6000) + "\nPlugin Name: Example\nVersion: 4", "4", true, 2},
		{"inline_php_tag", "<?php /* Plugin Name: Example\nVersion: 5 */", "5", true, 1},
		{"inline_short_tag", "<? /* Plugin Name: Example\nVersion: 6 */", "6", true, 1},
		{"header_label_spacing", "Plugin Name : Example\nVersion: 7", "", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record, found, err := Parse([]byte(tc.header), "example.php", "example.php")
			if err != nil || found != tc.found {
				t.Fatalf("parse: found=%v err=%v", found, err)
			}
			if found && (record.Component.Name != "Example" || record.Component.Version != tc.version || record.Component.Evidence[0].Line != tc.line || record.Component.PURL != "") {
				t.Fatalf("identity or evidence: %#v", record)
			}
		})
	}
}

func TestInstalledPluginLayouts(t *testing.T) {
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"var/www/html/wp-content/plugins/a/main.php", true},
		{"wp-content/plugins/hello.php", true},
		{"wp-content/mu-plugins/loader.php", true},
		{"wp-content/plugins/a/includes/fake.php", false},
		{"wp-content/plugins/.hidden/main.php", false},
		{"wp-content/mu-plugins/nested/main.php", false},
		{"wp-content/themes/theme/functions.php", false},
	} {
		if _, _, _, ok := InstalledPath(tc.path); ok != tc.want {
			t.Errorf("candidate %s = %v", tc.path, ok)
		}
	}
}

func TestPluginDependencyDeclarationsStayScopedAndConditional(t *testing.T) {
	doc := common.NewDocument("fixture", "fixture", "wordpress", nil)
	var records []Record
	for _, spec := range []struct{ file, header string }{
		{"site/wp-content/plugins/a/main.php", "Plugin Name: A\nVersion: 1\nRequires Plugins: b, missing, b"},
		{"site/wp-content/plugins/b/main.php", "Plugin Name: B\nVersion: 2"},
		{"other/wp-content/plugins/missing/main.php", "Plugin Name: Other site\nVersion: 3"},
		{"site/wp-content/mu-plugins/missing.php", "Plugin Name: MU\nVersion: 4"},
	} {
		record, _, err := Parse([]byte(spec.header), spec.file, spec.file)
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	Append(&doc, records)
	common.Finalize(&doc)
	if len(doc.Components) != 4 || len(doc.Edges) != 5 || doc.Coverage.GraphState != "partial" || doc.Coverage.OriginState != "partial" {
		t.Fatalf("graph=%#v coverage=%#v", doc.Edges, doc.Coverage)
	}
	edge := doc.Edges[4]
	if edge.From != records[0].Component.ID || edge.To != records[1].Component.ID || edge.Condition != "activation=unverified" || edge.Evidence.Line != 3 {
		t.Fatalf("dependency declaration: %#v", edge)
	}
	for _, component := range doc.Components {
		if component.PURL != "" {
			t.Fatal("plugin installation was relabeled as a public registry package")
		}
	}
}

func TestAmbiguousPluginSlugDoesNotEstablishDependency(t *testing.T) {
	doc := common.NewDocument("fixture", "fixture", "wordpress", nil)
	var records []Record
	for _, file := range []string{"wp-content/plugins/a/main.php", "wp-content/plugins/b/first.php", "wp-content/plugins/b/second.php"} {
		record, _, err := Parse([]byte("Plugin Name: Example\nVersion: 1\nRequires Plugins: b"), file, file)
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	Append(&doc, records)
	if len(doc.Edges) != 3 {
		t.Fatalf("ambiguous plugin dependency was linked: %#v", doc.Edges)
	}
	for _, edge := range doc.Edges {
		if edge.Kind != "observed" {
			t.Fatalf("presence was promoted to an active dependency: %#v", edge)
		}
	}
}
