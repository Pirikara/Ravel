package integration_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"

	"ravel/internal/model"
)

func TestJavaArchiveCLI(t *testing.T) {
	compiler := jsonschema.NewCompiler()
	for _, name := range []string{"bom-1.7.schema.json", "jsf-0.82.schema.json", "cryptography-defs.schema.json", "spdx.schema.json"} {
		data, err := os.ReadFile(filepath.Join("..", "testdata", "schema", name))
		if err != nil {
			t.Fatal(err)
		}
		var raw any
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Fatal(err)
		}
		if err := compiler.AddResource("http://cyclonedx.org/schema/"+name, raw); err != nil {
			t.Fatal(err)
		}
	}
	cdxSchema, err := compiler.Compile("http://cyclonedx.org/schema/bom-1.7.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	spdxBytes, err := os.ReadFile(filepath.Join("..", "testdata", "schema", "spdx-2.3.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var spdxRaw any
	if err := json.Unmarshal(spdxBytes, &spdxRaw); err != nil {
		t.Fatal(err)
	}
	spdxCompiler := jsonschema.NewCompiler()
	if err := spdxCompiler.AddResource("http://spdx.org/rdf/terms/2.3", spdxRaw); err != nil {
		t.Fatal(err)
	}
	spdxSchema, err := spdxCompiler.Compile("http://spdx.org/rdf/terms/2.3")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		fixture, file   string
		packages, edges int
	}{
		{"java-jar-basic", "sample.jar", 1, 1},
		{"java-jar-connection", "connection.jar", 1, 1},
		{"java-pom-invalid", "bad-pom.jar", 1, 1},
		{"java-pom-unsafe", "unsafe-pom.jar", 1, 1},
		{"java-boot", "boot.jar", 3, 3},
		{"java-war", "app.war", 3, 3},
		{"java-ambiguous", "shaded.jar", 1, 1},
		{"java-duplicate-lib", "duplicate.jar", 1, 1},
		{"java-duplicate-pom", "duplicate.jar", 1, 1},
		{"java-duplicate-properties", "duplicate.jar", 1, 1},
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			archive := filepath.Join("..", "testdata", "fixtures", tc.fixture, tc.file)
			for _, format := range []string{"cyclonedx-json", "spdx-json", "ravel-json"} {
				out := filepath.Join(t.TempDir(), format+".json")
				cmd := exec.Command(executable, "scan", archive, "--format", format, "--output", out)
				cmd.Env = append(os.Environ(), "SOURCE_DATE_EPOCH=1700000000")
				if output, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("%s scan failed: %v: %s", format, err, output)
				}
				data, err := os.ReadFile(out)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(data), "hidden") || strings.Contains(string(data), "token=secret") || strings.Contains(string(data), "token-secret") {
					t.Fatalf("POM credential leaked into %s", format)
				}
				var raw any
				if err := json.Unmarshal(data, &raw); err != nil {
					t.Fatal(err)
				}
				switch format {
				case "cyclonedx-json":
					if err := cdxSchema.Validate(raw); err != nil {
						t.Fatalf("CycloneDX schema: %v", err)
					}
					if tc.fixture == "java-war" {
						var bom struct {
							Dependencies []struct {
								DependsOn []string `json:"dependsOn"`
							} `json:"dependencies"`
						}
						if err := json.Unmarshal(data, &bom); err != nil {
							t.Fatal(err)
						}
						links := 0
						for _, dep := range bom.Dependencies {
							links += len(dep.DependsOn)
						}
						if links != 2 {
							t.Fatalf("provided WAR JAR became unconditional: %d links", links)
						}
					}
				case "spdx-json":
					if err := spdxSchema.Validate(raw); err != nil {
						t.Fatalf("SPDX schema: %v", err)
					}
					if tc.fixture == "java-war" {
						var sbom struct {
							Relationships []any `json:"relationships"`
						}
						if err := json.Unmarshal(data, &sbom); err != nil {
							t.Fatal(err)
						}
						if len(sbom.Relationships) != 2 {
							t.Fatalf("provided WAR JAR became unconditional in SPDX: %d links", len(sbom.Relationships))
						}
					}
				case "ravel-json":
					var doc model.Document
					if err := json.Unmarshal(data, &doc); err != nil {
						t.Fatal(err)
					}
					if doc.Coverage.Manager != "java-archive" || doc.Coverage.Packages != tc.packages || doc.Coverage.Edges != tc.edges || doc.Coverage.GraphState != "partial" || doc.Coverage.OriginState != "partial" {
						t.Fatalf("unexpected archive coverage: %#v", doc.Coverage)
					}
					for _, component := range doc.Components {
						if len(component.Hashes) != 1 || component.Hashes[0].Alg != "SHA-256" || len(component.Hashes[0].Content) != 64 {
							t.Fatalf("archive hash missing: %#v", component)
						}
						if component.PURL != "" {
							t.Fatalf("archive without observed repository was assigned Maven Central PURL: %s", component.PURL)
						}
					}
					if tc.fixture == "java-boot" {
						if len(doc.Development) != 2 {
							t.Fatalf("embedded POM development repositories missing: %#v", doc.Development)
						}
						var foundRepository bool
						for _, source := range doc.Development {
							if source.SafeURL == "https://github.com/example/lib-a" {
								foundRepository = true
							}
						}
						if !foundRepository {
							t.Fatal("nested JAR development repository not sanitized")
						}
						var nestedIdentity bool
						for _, component := range doc.Components {
							if component.Name == "org.example:lib-a" && component.Version == "2.0.0" {
								nestedIdentity = true
							}
						}
						if !nestedIdentity {
							t.Fatal("nested JAR Maven coordinates missing")
						}
					}
					if tc.fixture == "java-war" {
						var provided bool
						for _, edge := range doc.Edges {
							if edge.Condition == "runtime=embedded" {
								provided = true
							}
						}
						if !provided {
							t.Fatal("WAR provided library was made unconditional")
						}
					}
					if tc.fixture == "java-ambiguous" && doc.Components[0].PURL != "" {
						t.Fatal("ambiguous shaded JAR was assigned Maven identity")
					}
					if tc.fixture == "java-ambiguous" && len(doc.Development) != 0 {
						t.Fatal("ambiguous shaded JAR was assigned development repository")
					}
					if tc.fixture == "java-jar-connection" && (len(doc.Development) != 1 || doc.Development[0].SafeURL != "https://github.com/example/connection-only.git") {
						t.Fatal("Maven SCM connection was not read")
					}
					if tc.fixture == "java-pom-invalid" {
						if len(doc.Development) != 0 {
							t.Fatal("malformed POM supplied a development repository")
						}
						var issue bool
						for _, item := range doc.Coverage.Issues {
							if item.Code == "development_metadata_invalid" {
								issue = true
							}
						}
						if !issue {
							t.Fatal("malformed POM was not reported")
						}
					}
					if tc.fixture == "java-pom-unsafe" {
						if len(doc.Development) != 0 {
							t.Fatal("unsafe POM URL supplied a development repository")
						}
						var issue bool
						for _, item := range doc.Coverage.Issues {
							if item.Code == "unsafe_or_invalid_development_source" {
								issue = true
							}
						}
						if !issue {
							t.Fatal("unsafe POM URL was not reported")
						}
					}
					if tc.fixture == "java-duplicate-lib" {
						found := false
						for _, issue := range doc.Coverage.Issues {
							found = found || issue.Code == "duplicate_archive_entry"
						}
						if !found || len(doc.Components) != 1 {
							t.Fatalf("duplicate nested JAR was counted: %#v", doc)
						}
					}
					if tc.fixture == "java-duplicate-pom" {
						found := false
						for _, issue := range doc.Coverage.Issues {
							found = found || issue.Code == "development_metadata_ambiguous"
						}
						if !found || len(doc.Development) != 0 {
							t.Fatalf("ambiguous POM selected a development URL: %#v", doc)
						}
					}
					if tc.fixture == "java-duplicate-properties" {
						if doc.Components[0].PURL != "" || !hasArchiveIssue(doc, "ambiguous_archive_metadata") {
							t.Fatalf("duplicate Maven identity was selected: %#v", doc)
						}
					}
				}
			}
		})
	}
	for _, tc := range []struct{ fixture, message string }{
		{"java-invalid", "invalid"},
		{"java-nested-invalid", "invalid"},
		{"java-path-unsafe", "unsafe"},
		{"java-oversized", "oversized"},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			archive := filepath.Join("..", "testdata", "fixtures", tc.fixture, "broken.jar")
			if output, err := exec.Command(executable, "scan", archive, "--format", "ravel-json").CombinedOutput(); err == nil || !strings.Contains(string(output), tc.message) {
				t.Fatalf("invalid Java archive accepted: %v: %s", err, output)
			}
		})
	}
}

func TestJavaDevelopmentExplainAndDiff(t *testing.T) {
	archive := filepath.Join("..", "testdata", "fixtures", "java-boot", "boot.jar")
	before := filepath.Join(t.TempDir(), "before.json")
	if out, err := exec.Command(executable, "scan", archive, "--format", "ravel-json", "--output", before).CombinedOutput(); err != nil {
		t.Fatalf("scan failed: %v: %s", err, out)
	}
	data, err := os.ReadFile(before)
	if err != nil {
		t.Fatal(err)
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	var nestedRef string
	for _, component := range doc.Components {
		if component.Name == "org.example:lib-a" {
			nestedRef = component.ID
		}
	}
	if nestedRef == "" {
		t.Fatal("nested library missing")
	}
	output, err := exec.Command(executable, "explain", nestedRef, "--input", before, "--format", "json").CombinedOutput()
	if err != nil {
		t.Fatalf("explain failed: %v: %s", err, output)
	}
	var explanation struct {
		Development []model.Development `json:"development"`
	}
	if err := json.Unmarshal(output, &explanation); err != nil {
		t.Fatal(err)
	}
	if len(explanation.Development) != 1 || explanation.Development[0].SafeURL != "https://github.com/example/lib-a" {
		t.Fatalf("development repository missing from explain: %#v", explanation.Development)
	}
	for i := range doc.Development {
		if doc.Development[i].Occurrence == nestedRef {
			doc.Development[i].SafeURL = "https://github.com/example/lib-a-fork"
		}
	}
	after := filepath.Join(t.TempDir(), "after.json")
	modified, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(after, modified, 0o600); err != nil {
		t.Fatal(err)
	}
	output, err = exec.Command(executable, "diff", before, after, "--format", "json").CombinedOutput()
	if err != nil {
		t.Fatalf("diff failed: %v: %s", err, output)
	}
	var difference struct {
		AddedDevelopment   []model.Development `json:"addedDevelopment"`
		RemovedDevelopment []model.Development `json:"removedDevelopment"`
	}
	if err := json.Unmarshal(output, &difference); err != nil {
		t.Fatal(err)
	}
	if len(difference.AddedDevelopment) != 1 || len(difference.RemovedDevelopment) != 1 || difference.AddedDevelopment[0].SafeURL != "https://github.com/example/lib-a-fork" {
		t.Fatalf("development repository change missing from diff: %#v", difference)
	}
}
