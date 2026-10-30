package integration_test

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	packageurl "github.com/package-url/packageurl-go"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"

	"ravel/internal/model"
	"ravel/internal/report"
)

var executable string

func TestMain(m *testing.M) {
	root, err := filepath.Abs("..")
	if err != nil {
		panic(err)
	}
	dir, err := os.MkdirTemp("", "ravel-integration-")
	if err != nil {
		panic(err)
	}
	executable = filepath.Join(dir, "ravel")
	cmd := exec.Command("go", "build", "-o", executable, "./cmd/ravel")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		panic(string(out) + err.Error())
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

type expected struct {
	name       string
	manager    string
	packages   int
	edges      int
	graph      string
	origin     string
	wantNames  []string
	absentName string
	secret     string
}

func TestCLIAndCycloneDXSchema(t *testing.T) {
	compiler := jsonschema.NewCompiler()
	const schemaID = "http://cyclonedx.org/schema/bom-1.7.schema.json"
	for _, name := range []string{"bom-1.7.schema.json", "jsf-0.82.schema.json", "cryptography-defs.schema.json", "spdx.schema.json"} {
		schemaData, err := os.ReadFile(filepath.Join("..", "testdata", "schema", name))
		if err != nil {
			t.Fatal(err)
		}
		var schemaDoc any
		if err := json.Unmarshal(schemaData, &schemaDoc); err != nil {
			t.Fatal(err)
		}
		if err := compiler.AddResource("http://cyclonedx.org/schema/"+name, schemaDoc); err != nil {
			t.Fatal(err)
		}
	}
	schema, err := compiler.Compile(schemaID)
	if err != nil {
		t.Fatal(err)
	}
	cases := []expected{
		{"bundler-basic", "bundler", 2, 2, "complete_for_scope", "complete_for_scope", []string{"alpha", "beta"}, "", "secret"},
		{"bundler-generated-4", "bundler", 2, 3, "complete_for_scope", "complete_for_scope", []string{"ravel_alpha", "ravel_beta"}, "", ""},
		{"bundler-git-scp", "bundler", 1, 1, "complete_for_scope", "complete_for_scope", []string{"gitgem"}, "", ""},
		{"bundler-ambiguous", "bundler", 3, 1, "partial", "complete_for_scope", []string{"parent", "foo"}, "", ""},
		{"npm-v2", "npm", 1, 1, "complete_for_scope", "complete_for_scope", []string{"one"}, "", ""},
		{"npm-v1", "npm", 1, 0, "partial", "partial", []string{"alpha"}, "", ""},
		{"npm-v1-generated-12", "npm", 3, 3, "complete_for_scope", "complete_for_scope", []string{"is-odd", "is-number"}, "", ""},
		{"npm-v1-optional", "npm", 2, 3, "partial", "complete_for_scope", []string{"core", "native"}, "", "hidden"},
		{"npm-v1-sources", "npm", 2, 2, "partial", "complete_for_scope", []string{"gitpkg", "archive"}, "", "hidden"},
		{"npm-v1-incomplete", "npm", 2, 1, "partial", "complete_for_scope", []string{"parent", "child"}, "", ""},
		{"npm-v1-stale", "npm", 2, 1, "partial", "complete_for_scope", []string{"parent", "child"}, "", ""},
		{"npm-v1-scoped", "npm", 2, 2, "complete_for_scope", "complete_for_scope", []string{"@scope/core", "@scope/util"}, "", ""},
		{"npm-v1-orphan", "npm", 2, 1, "partial", "complete_for_scope", []string{"used", "orphan"}, "", ""},
		{"npm-v3", "npm", 4, 4, "complete_for_scope", "complete_for_scope", []string{"alpha", "beta", "@scope/tool"}, "", "secret"},
		{"npm-generated-12", "npm", 1, 1, "complete_for_scope", "complete_for_scope", []string{"is-number"}, "", ""},
		{"npm-optional", "npm", 3, 3, "partial", "partial", []string{"alpha", "native-addon", "peer-lib"}, "", ""},
		{"bun-basic", "bun", 2, 2, "complete_for_scope", "partial", []string{"alpha", "beta"}, "", ""},
		{"bun-git", "bun", 2, 2, "complete_for_scope", "complete_for_scope", []string{"gitpkg", "webpkg"}, "", "hidden"},
		{"bun-platform", "bun", 3, 3, "partial", "partial", []string{"sharp", "@img/darwin", "@img/linux"}, "", ""},
		{"bun-generated-1_3", "bun", 1, 1, "complete_for_scope", "partial", []string{"is-number"}, "", ""},
		{"bun-enrich", "bun", 1, 1, "complete_for_scope", "complete_for_scope", []string{"is-number"}, "", ""},
		{"deno-v4", "deno", 2, 2, "partial", "complete_for_scope", []string{"@std/path", "https://cdn.example.test/lib/mod.ts"}, "", ""},
		{"deno-v5", "deno", 3, 3, "partial", "partial", []string{"@std/encoding", "@std/bytes", "chalk"}, "stale", ""},
		{"deno-generated-2_9", "deno", 1, 1, "partial", "partial", []string{"is-number"}, "", ""},
		{"deno-peer", "deno", 2, 2, "partial", "partial", []string{"typedoc", "typescript"}, "", ""},
		{"deno-source-only", "deno", 5, 5, "partial", "partial", []string{"@std/path", "@std/bytes", "chalk", "is-number", "https://cdn.example.test/mod.ts"}, "", "hidden"},
		{"deno-source-mapped", "deno", 3, 3, "partial", "partial", []string{"@std/path", "is-number"}, "", ""},
		{"deno-source-importmap", "deno", 1, 1, "partial", "partial", []string{"chalk"}, "", ""},
		{"deno-source-nested", "deno", 1, 1, "partial", "partial", []string{"alpha"}, "beta", ""},
		{"deno-source-mismatch", "deno", 0, 0, "partial", "complete_for_scope", nil, "chalk", ""},
		{"swift-v1", "swiftpm", 1, 0, "unknown", "complete_for_scope", []string{"swift-collections"}, "", ""},
		{"swift-v2", "swiftpm", 2, 0, "unknown", "complete_for_scope", []string{"swift-algorithms", "swift-atomics"}, "", "secret"},
		{"swift-v3", "swiftpm", 2, 0, "unknown", "partial", []string{"swift-mmio", "registry-package"}, "", ""},
		{"nuget-single", "nuget", 2, 2, "complete_for_scope", "partial", []string{"Example.Core", "Example.Abstractions"}, "", ""},
		{"nuget-generated-10", "nuget", 1, 1, "complete_for_scope", "partial", []string{"Ravel.Beta"}, "", ""},
		{"nuget-assets-generated-10", "nuget", 1, 1, "complete_for_scope", "partial", []string{"Ravel.Beta"}, "", ""},
		{"nuget-multi", "nuget", 2, 2, "partial", "partial", []string{"Example.Core"}, "", ""},
		{"uv-basic", "uv", 2, 2, "complete_for_scope", "complete_for_scope", []string{"Requests", "idna"}, "", "secret"},
		{"uv-generated-0_11", "uv", 2, 2, "complete_for_scope", "complete_for_scope", []string{"alpha", "beta"}, "", ""},
		{"uv-pypi-enrich", "uv", 1, 1, "complete_for_scope", "complete_for_scope", []string{"idna"}, "", ""},
		{"uv-forked", "uv", 4, 4, "partial", "complete_for_scope", []string{"pandas", "numpy"}, "", ""},
		{"uv-sources", "uv", 3, 3, "complete_for_scope", "complete_for_scope", []string{"git-lib", "archive-lib", "local-lib"}, "", "secret"},
		{"pylock-basic", "pylock", 2, 2, "complete_for_scope", "complete_for_scope", []string{"click", "colorama"}, "", "secret"},
		{"pylock-pypi-enrich", "pylock", 1, 1, "complete_for_scope", "complete_for_scope", []string{"idna"}, "", ""},
		{"pylock-marker", "pylock", 3, 1, "partial", "complete_for_scope", []string{"spam", "ham"}, "", ""},
		{"pylock-multiwheel", "pylock", 1, 1, "complete_for_scope", "partial", []string{"platform-lib"}, "", ""},
		{"bun-workspace", "bun", 2, 1, "partial", "partial", []string{"alpha", "beta"}, "", ""},
		{"uv-extras", "uv", 3, 3, "partial", "complete_for_scope", []string{"base", "pillow", "pytest"}, "", ""},
		{"pylock-vcs", "pylock", 1, 1, "complete_for_scope", "complete_for_scope", []string{"git-package"}, "", "secret"},
		{"pylock-named", "pylock", 1, 0, "partial", "complete_for_scope", []string{"standalone"}, "", ""},
		{"requirements-basic", "requirements", 2, 2, "partial", "partial", []string{"requests", "idna"}, "", "hidden"},
		{"requirements-conditional", "requirements", 2, 2, "partial", "partial", []string{"widget", "helper"}, "", ""},
		{"requirements-url", "requirements", 1, 1, "partial", "complete_for_scope", []string{"direct-lib"}, "", "hidden"},
		{"requirements-constraint", "requirements", 1, 1, "partial", "partial", []string{"widget"}, "", ""},
		{"requirements-multihash", "requirements", 1, 1, "partial", "partial", []string{"multi"}, "", ""},
		{"nuget-assets-v3", "nuget", 2, 2, "complete_for_scope", "partial", []string{"Example.Core", "Example.Abstractions"}, "", ""},
		{"nuget-assets-v4", "nuget", 2, 2, "partial", "partial", []string{"Example.Core"}, "", ""},
		{"pnpm-basic", "pnpm", 2, 2, "complete_for_scope", "complete_for_scope", []string{"alpha", "beta"}, "", "secret"},
		{"pnpm-v6-generated-8", "pnpm", 2, 2, "complete_for_scope", "partial", []string{"is-odd", "is-number"}, "", ""},
		{"pnpm-v6-workspace-8", "pnpm", 1, 1, "partial", "partial", []string{"is-number"}, "", ""},
		{"pnpm-v6-peer", "pnpm", 6, 8, "complete_for_scope", "complete_for_scope", []string{"wrapper-a", "wrapper-b", "widget", "react"}, "", ""},
		{"pnpm-generated-10", "pnpm", 1, 1, "complete_for_scope", "partial", []string{"is-number"}, "", ""},
		{"pnpm-enrich", "pnpm", 1, 1, "complete_for_scope", "complete_for_scope", []string{"is-number"}, "", ""},
		{"pnpm-peer", "pnpm", 6, 6, "complete_for_scope", "partial", []string{"wrapper-a", "wrapper-b", "widget", "react"}, "", ""},
		{"pnpm-workspace", "pnpm", 2, 2, "partial", "partial", []string{"alpha", "beta"}, "", ""},
		{"pnpm-two-doc", "pnpm", 2, 2, "partial", "partial", []string{"pnpm", "app"}, "", ""},
		{"pnpm-optional", "pnpm", 2, 3, "partial", "partial", []string{"main", "native"}, "", ""},
		{"pnpm-link", "pnpm", 0, 0, "partial", "complete_for_scope", nil, "", ""},
		{"poetry-basic", "poetry", 2, 2, "partial", "complete_for_scope", []string{"Requests", "idna"}, "", "secret"},
		{"poetry-groups", "poetry", 2, 3, "partial", "partial", []string{"click", "colorama"}, "", ""},
		{"poetry-no-project", "poetry", 1, 0, "partial", "complete_for_scope", []string{"git-lib"}, "", "secret"},
		{"poetry-ambiguous", "poetry", 3, 1, "partial", "complete_for_scope", []string{"parent", "foo"}, "", ""},
		{"yarn-classic-basic", "yarn", 2, 2, "complete_for_scope", "complete_for_scope", []string{"alpha", "beta"}, "stale", "secret"},
		{"yarn-classic-enrich", "yarn", 1, 1, "complete_for_scope", "complete_for_scope", []string{"is-number"}, "", ""},
		{"yarn-classic-optional", "yarn", 2, 2, "partial", "partial", []string{"main", "native"}, "", ""},
		{"yarn-classic-no-manifest", "yarn", 1, 0, "partial", "complete_for_scope", []string{"standalone"}, "", ""},
		{"yarn-classic-ambiguous", "yarn", 0, 0, "partial", "complete_for_scope", nil, "", ""},
		{"yarn-berry-basic", "yarn", 2, 2, "complete_for_scope", "partial", []string{"alpha", "beta"}, "stale", ""},
		{"yarn-berry-enrich", "yarn", 1, 1, "complete_for_scope", "complete_for_scope", []string{"is-number"}, "", ""},
		{"yarn-berry-optional", "yarn", 2, 2, "partial", "partial", []string{"main", "native"}, "", ""},
		{"yarn-berry-remote", "yarn", 1, 1, "complete_for_scope", "complete_for_scope", []string{"foo"}, "", "secret"},
		{"yarn-berry-workspace", "yarn", 2, 2, "complete_for_scope", "partial", []string{"web", "alpha"}, "", ""},
		{"yarn-generated-4", "yarn", 2, 2, "complete_for_scope", "complete_for_scope", []string{"@ravel/alpha", "@ravel/beta"}, "", ""},
		{"poetry-shared-extra", "poetry", 1, 3, "partial", "complete_for_scope", []string{"shared"}, "", ""},
		{"cargo-basic", "cargo", 2, 2, "partial", "complete_for_scope", []string{"alpha", "beta"}, "", "secret"},
		{"cargo-git", "cargo", 1, 1, "partial", "complete_for_scope", []string{"git-lib"}, "", "secret"},
		{"cargo-sparse-default", "cargo", 1, 1, "partial", "complete_for_scope", []string{"serde"}, "", ""},
		{"cargo-workspace", "cargo", 2, 2, "partial", "complete_for_scope", []string{"web", "alpha"}, "", ""},
		{"cargo-ambiguous", "cargo", 2, 0, "partial", "complete_for_scope", []string{"foo"}, "", ""},
		{"cargo-no-manifest", "cargo", 1, 0, "partial", "complete_for_scope", []string{"standalone"}, "", ""},
		{"composer-basic", "composer", 2, 2, "partial", "complete_for_scope", []string{"monolog/monolog", "psr/log"}, "", "secret"},
		{"composer-dev", "composer", 2, 3, "partial", "complete_for_scope", []string{"symfony/console", "phpunit/phpunit"}, "", ""},
		{"composer-path", "composer", 1, 1, "partial", "complete_for_scope", []string{"team/local"}, "", ""},
		{"composer-generated-2", "composer", 2, 2, "partial", "complete_for_scope", []string{"acme/alpha", "acme/beta"}, "", ""},
		{"composer-no-manifest", "composer", 1, 0, "partial", "complete_for_scope", []string{"team/standalone"}, "", ""},
		{"composer-ambiguous", "composer", 2, 0, "partial", "complete_for_scope", []string{"team/foo"}, "", ""},
		{"cocoapods-basic", "cocoapods", 2, 2, "partial", "complete_for_scope", []string{"Alpha", "Beta"}, "", ""},
		{"cocoapods-subspec", "cocoapods", 3, 3, "partial", "complete_for_scope", []string{"Firebase/CoreOnly", "FirebaseCore", "GoogleUtilities/Environment"}, "", ""},
		{"cocoapods-git", "cocoapods", 2, 2, "partial", "complete_for_scope", []string{"SecretKit", "BaseKit"}, "", "hidden"},
		{"cocoapods-path", "cocoapods", 1, 1, "partial", "complete_for_scope", []string{"LocalKit"}, "", ""},
		{"cocoapods-ambiguous", "cocoapods", 2, 0, "partial", "complete_for_scope", []string{"Foo"}, "", ""},
		{"cocoapods-no-deps", "cocoapods", 1, 0, "partial", "complete_for_scope", []string{"Standalone"}, "", ""},
		{"cocoapods-custom-repo", "cocoapods", 1, 1, "partial", "complete_for_scope", []string{"EdgeKit"}, "", "hidden"},
		{"cocoapods-remote", "cocoapods", 2, 2, "partial", "complete_for_scope", []string{"RemoteKit", "PodspecKit"}, "", "hidden"},
		{"cocoapods-ambiguous-repo", "cocoapods", 1, 1, "partial", "partial", []string{"SharedKit"}, "", ""},
		{"pipenv-basic", "pipenv", 2, 1, "partial", "complete_for_scope", []string{"Requests", "idna"}, "", ""},
		{"pipenv-groups", "pipenv", 3, 3, "partial", "complete_for_scope", []string{"click", "pytest", "sphinx"}, "", ""},
		{"pipenv-sources", "pipenv", 3, 3, "partial", "complete_for_scope", []string{"git-lib", "archive-lib", "local-lib"}, "", "hidden"},
		{"pipenv-multisource", "pipenv", 2, 2, "partial", "partial", []string{"alpha", "beta"}, "", "hidden"},
		{"pipenv-no-manifest", "pipenv", 1, 0, "partial", "complete_for_scope", []string{"standalone"}, "", ""},
		{"pdm-basic", "pdm", 2, 2, "partial", "partial", []string{"alpha", "beta"}, "", ""},
		{"pdm-groups", "pdm", 3, 3, "partial", "partial", []string{"alpha", "beta", "pytest"}, "", "hidden"},
		{"pdm-extras", "pdm", 4, 4, "partial", "complete_for_scope", []string{"app", "plugin", "speedlib"}, "", ""},
		{"pdm-sources", "pdm", 3, 3, "partial", "complete_for_scope", []string{"git-lib", "archive-lib", "local-lib"}, "", "hidden"},
		{"pdm-no-manifest", "pdm", 1, 0, "partial", "partial", []string{"standalone"}, "", ""},
		{"go-vendor-basic", "go", 2, 1, "partial", "partial", []string{"github.com/acme/alpha", "golang.org/x/text"}, "", "stale-version-should-not-be-included"},
		{"go-vendor-local", "go", 1, 1, "partial", "complete_for_scope", []string{"github.com/acme/alpha"}, "", ""},
		{"go-vendor-replacement", "go", 1, 1, "partial", "partial", []string{"github.com/acme/alpha"}, "", ""},
		{"go-vendor-stale", "go", 1, 0, "partial", "partial", []string{"github.com/acme/alpha"}, "", ""},
		{"go-vendor-missing", "go", 0, 0, "partial", "complete_for_scope", nil, "", ""},
		{"go-vendor-no-mod", "go", 1, 0, "partial", "partial", []string{"github.com/acme/alpha"}, "", ""},
		{"go-vendor-workspace", "go", 1, 0, "partial", "partial", []string{"github.com/acme/alpha"}, "", ""},
		{"pub-basic", "pub", 2, 1, "partial", "complete_for_scope", []string{"collection", "meta"}, "", ""},
		{"pub-git", "pub", 2, 1, "partial", "complete_for_scope", []string{"git_package", "helper"}, "", "hidden"},
		{"pub-dev", "pub", 3, 3, "partial", "complete_for_scope", []string{"app_core", "test", "flutter"}, "", ""},
		{"pub-path", "pub", 2, 1, "partial", "complete_for_scope", []string{"local_plugin", "transitive_pkg"}, "", ""},
		{"pub-old-hosted", "pub", 1, 1, "partial", "partial", []string{"old_package"}, "", ""},
		{"pub-empty", "pub", 0, 0, "partial", "complete_for_scope", nil, "", ""},
		{"pub-custom", "pub", 1, 1, "partial", "complete_for_scope", []string{"private_widget"}, "", "hidden"},
		{"gradle-basic", "gradle", 3, 0, "partial", "partial", []string{"com.google.guava:guava", "com.google.guava:failureaccess", "org.slf4j:slf4j-api"}, "", ""},
		{"gradle-versions", "gradle", 2, 0, "partial", "partial", []string{"org.example:widget"}, "", ""},
		{"gradle-buildscript", "gradle", 1, 0, "partial", "partial", []string{"org.example:build-plugin"}, "", ""},
		{"gradle-empty", "gradle", 0, 0, "partial", "complete_for_scope", nil, "", ""},
		{"maven-basic", "maven", 2, 2, "partial", "partial", []string{"org.slf4j:slf4j-api", "org.example:api"}, "", ""},
		{"maven-scopes", "maven", 3, 3, "partial", "partial", []string{"org.junit.jupiter:junit-jupiter", "org.apiguardian:apiguardian-api", "org.slf4j:slf4j-api"}, "", ""},
		{"maven-classifier", "maven", 2, 2, "partial", "partial", []string{"org.example:asset"}, "", ""},
		{"maven-repeated", "maven", 3, 4, "partial", "partial", []string{"org.example:main", "org.example:tests", "org.example:shared"}, "", ""},
		{"maven-pom-basic", "maven", 3, 3, "partial", "partial", []string{"org.slf4j:slf4j-api", "org.junit.jupiter:junit-jupiter", "org.example:property-resolved"}, "org.example:profile-only", ""},
		{"maven-pom-module", "maven", 0, 0, "partial", "complete_for_scope", nil, "", ""},
		{"maven-pom-empty", "maven", 0, 0, "partial", "complete_for_scope", nil, "", ""},
		{"maven-pom-duplicate", "maven", 0, 0, "partial", "complete_for_scope", nil, "org.example:lib", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := filepath.Join("..", "testdata", "fixtures", tc.name)
			outFile := filepath.Join(t.TempDir(), "sbom.json")
			ravelFile := filepath.Join(t.TempDir(), "ravel.json")
			reportFile := filepath.Join(t.TempDir(), "coverage.json")
			cmd := exec.Command(executable, "scan", fixture, "--output", outFile, "--report", reportFile)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("scan failed: %v: %s", err, output)
			}
			coverageData, err := os.ReadFile(reportFile)
			if err != nil {
				t.Fatal(err)
			}
			var coverage model.Coverage
			if err := json.Unmarshal(coverageData, &coverage); err != nil {
				t.Fatal(err)
			}
			if coverage.Manager != tc.manager || coverage.Packages != tc.packages || coverage.Edges != tc.edges || coverage.GraphState != tc.graph || coverage.OriginState != tc.origin {
				t.Fatalf("unexpected coverage: %#v", coverage)
			}
			bomData, err := os.ReadFile(outFile)
			if err != nil {
				t.Fatal(err)
			}
			var bom any
			if err := json.Unmarshal(bomData, &bom); err != nil {
				t.Fatal(err)
			}
			if err := schema.Validate(bom); err != nil {
				t.Fatalf("CycloneDX schema failed: %v", err)
			}
			var details struct {
				Components []struct {
					Name string `json:"name"`
				} `json:"components"`
			}
			if err := json.Unmarshal(bomData, &details); err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, c := range details.Components {
				names = append(names, c.Name)
			}
			for _, want := range tc.wantNames {
				if !slices.Contains(names, want) {
					t.Fatalf("missing component %s: %v", want, names)
				}
			}
			if tc.absentName != "" && slices.Contains(names, tc.absentName) {
				t.Fatalf("stale component included: %s", tc.absentName)
			}
			if tc.secret != "" && strings.Contains(string(bomData)+string(coverageData), tc.secret) {
				t.Fatalf("secret leaked from lockfile")
			}
			cmd = exec.Command(executable, "scan", fixture, "--format", "ravel-json", "--output", ravelFile)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("ravel-json scan failed: %v: %s", err, output)
			}
			ravelData, err := os.ReadFile(ravelFile)
			if err != nil {
				t.Fatal(err)
			}
			if tc.secret != "" && strings.Contains(string(ravelData), tc.secret) {
				t.Fatalf("secret leaked into Ravel JSON")
			}
			var doc model.Document
			if err := json.Unmarshal(ravelData, &doc); err != nil {
				t.Fatal(err)
			}
			for _, component := range doc.Components {
				if (tc.manager == "nuget" || tc.manager == "maven" || tc.manager == "gradle") && component.PURL != "" {
					t.Fatalf("%s package without observed repository assigned default-repository PURL: %s", tc.manager, component.PURL)
				}
				if component.PURL == "" {
					continue
				}
				parsed, err := packageurl.FromString(component.PURL)
				if err != nil {
					t.Fatalf("invalid PURL %q: %v", component.PURL, err)
				}
				if parsed.ToString() != component.PURL {
					t.Fatalf("non-canonical PURL %q; canonical %q", component.PURL, parsed.ToString())
				}
			}
			verifySemantics(t, tc.name, doc, bomData)
		})
	}
}

func verifySemantics(t *testing.T, fixture string, doc model.Document, bomData []byte) {
	t.Helper()
	find := func(name, version string) string {
		for _, c := range doc.Components {
			if c.Name == name && c.Version == version {
				return c.ID
			}
		}
		t.Fatalf("missing %s@%s", name, version)
		return ""
	}
	connected := func(from, to string) bool {
		for _, edge := range doc.Edges {
			if edge.From == from && edge.To == to {
				return true
			}
		}
		return false
	}
	switch fixture {
	case "bundler-generated-4":
		alpha, beta := find("ravel_alpha", "1.0.0"), find("ravel_beta", "2.1.0")
		if !connected("root", alpha) || !connected("root", beta) || !connected(alpha, beta) {
			t.Fatal("Bundler 4 path graph missing")
		}
		for _, component := range doc.Components {
			if component.PURL != "" {
				t.Fatal("Bundler path package was identified as RubyGems")
			}
		}
		for _, origin := range doc.Origins {
			if origin.Kind != "local" {
				t.Fatal("Bundler path package did not retain local origin")
			}
		}
	case "bundler-git-scp":
		if len(doc.Components) != 1 || doc.Components[0].PURL != "" || len(doc.Origins) != 1 || doc.Origins[0].Kind != "vcs" || doc.Origins[0].SafeURL != "ssh://github.com/ravel/gitgem.git" || len(doc.Development) != 1 || doc.Development[0].SafeURL != "ssh://github.com/ravel/gitgem.git" {
			t.Fatalf("scp-style Bundler Git source lost or assigned RubyGems identity: %#v", doc)
		}
	case "nuget-generated-10", "nuget-assets-generated-10":
		if len(doc.Components) != 1 || doc.Components[0].PURL != "" || len(doc.Components[0].Hashes) != 1 || doc.Components[0].Hashes[0].Alg != "SHA-512" || !connected("root", find("Ravel.Beta", "1.2.3")) {
			t.Fatal("locally generated NuGet package was assigned NuGet.org identity or lost content hash")
		}
	case "npm-generated-12", "pnpm-generated-10":
		if !connected("root", find("is-number", "7.0.0")) || len(doc.Components[0].Hashes) != 1 || doc.Components[0].Hashes[0].Alg != "SHA-512" {
			t.Fatal("generated npm/pnpm lock lost dependency or integrity")
		}
		if fixture == "npm-generated-12" && doc.Components[0].PURL != "pkg:npm/is-number@7.0.0" {
			t.Fatal("default npm registry PURL missing")
		}
		if fixture == "pnpm-generated-10" && doc.Components[0].PURL != "" {
			t.Fatal("pnpm lock without tarball URL assumed default npm registry")
		}
	case "npm-v1-generated-12":
		odd := find("is-odd", "3.0.1")
		number6, number7 := find("is-number", "6.0.0"), find("is-number", "7.0.0")
		if !connected("root", odd) || !connected("root", number7) || !connected(odd, number6) || connected(odd, number7) {
			t.Fatal("npm v1 nested dependency resolved to the wrong installed version")
		}
		for _, component := range doc.Components {
			if component.PURL != "pkg:npm/"+component.Name+"@"+component.Version || len(component.Hashes) != 1 || component.Hashes[0].Alg != "SHA-512" {
				t.Fatalf("npm v1 registry identity or integrity lost: %+v", component)
			}
		}
	case "npm-v1-optional":
		core, native := find("core", "1.0.0"), find("native", "1.0.0")
		if !connected("root", core) || !connected("root", native) || !connected(core, native) {
			t.Fatal("npm v1 optional graph lost")
		}
		for _, edge := range doc.Edges {
			if edge.To == native && (edge.Kind != "optional" || edge.Condition != "optional") {
				t.Fatalf("npm v1 optional edge exported unconditionally: %+v", edge)
			}
		}
		for _, c := range doc.Components {
			if c.Name == "core" && c.PURL != "pkg:npm/core@1.0.0" || c.Name == "native" && c.PURL != "" {
				t.Fatalf("npm v1 private package assigned registry identity: %+v", c)
			}
		}
		if len(doc.Origins) != 2 {
			t.Fatal("npm v1 optional origin missing")
		}
		var bom struct {
			Dependencies []struct {
				DependsOn []string `json:"dependsOn"`
			} `json:"dependencies"`
		}
		if err := json.Unmarshal(bomData, &bom); err != nil {
			t.Fatal(err)
		}
		for _, dependency := range bom.Dependencies {
			if slices.Contains(dependency.DependsOn, native) {
				t.Fatal("npm v1 optional dependency exported as unconditional CycloneDX edge")
			}
		}
	case "npm-v1-sources":
		if strings.Contains(string(bomData), "secret") || strings.Contains(string(bomData), "hidden") {
			t.Fatal("npm v1 source credentials leaked into CycloneDX")
		}
		if !connected("root", find("gitpkg", "")) || !connected("root", find("archive", "")) {
			t.Fatal("npm v1 URL dependencies missing")
		}
		for _, c := range doc.Components {
			if c.PURL != "" || c.Version != "" {
				t.Fatalf("npm v1 URL source mistaken for package version: %+v", c)
			}
		}
		origins := map[string]model.Origin{}
		for _, o := range doc.Origins {
			origins[o.Kind] = o
		}
		if origins["vcs"].SafeURL != "https://github.com/team/gitpkg.git" || origins["vcs"].Revision != "0123456789abcdef0123456789abcdef01234567" || origins["download_url"].SafeURL != "https://packages.example.test/archive.tgz" {
			t.Fatalf("npm v1 URL origins missing or unsafe: %+v", doc.Origins)
		}
	case "npm-v1-incomplete":
		parent, child := find("parent", "1.0.0"), find("child", "1.0.0")
		if !connected("root", parent) || connected(parent, child) || !slices.ContainsFunc(doc.Coverage.Issues, func(issue model.Issue) bool { return issue.Code == "transitive_graph_unavailable" }) {
			t.Fatal("npm v1 inferred a transitive edge absent from requires")
		}
	case "npm-v1-stale":
		parent, child := find("parent", "1.0.0"), find("child", "1.0.0")
		if !connected("root", parent) || connected("root", child) || connected(parent, child) || !slices.ContainsFunc(doc.Coverage.Issues, func(issue model.Issue) bool { return issue.Code == "unresolved_dependency" && issue.Name == "child" }) {
			t.Fatal("npm v1 connected a package to a version outside its declared range")
		}
	case "npm-v1-scoped":
		core, util := find("@scope/core", "1.0.0"), find("@scope/util", "2.1.0")
		if !connected("root", core) || !connected(core, util) || connected("root", util) {
			t.Fatal("npm v1 scoped package graph missing")
		}
		for _, component := range doc.Components {
			if component.PURL != "pkg:npm/%40scope/"+strings.TrimPrefix(component.Name, "@scope/")+"@"+component.Version {
				t.Fatalf("npm v1 scoped package identity missing: %+v", component)
			}
		}
	case "npm-v1-orphan":
		if !connected("root", find("used", "1.0.0")) || connected("root", find("orphan", "2.0.0")) || !slices.ContainsFunc(doc.Coverage.Issues, func(issue model.Issue) bool { return issue.Code == "unreachable_graph" && issue.Name == "orphan" }) {
			t.Fatal("npm v1 orphan package was presented as part of a complete graph")
		}
	case "npm-v1":
		if len(doc.Edges) != 0 || doc.Components[0].PURL != "" {
			t.Fatal("npm v1 missing manifest or source was guessed")
		}
	case "requirements-basic":
		if !connected("root", find("requests", "2.32.3")) || !connected("root", find("idna", "3.7")) || len(doc.Sources) != 1 {
			t.Fatal("included requirements or direct edges missing")
		}
		for _, c := range doc.Components {
			if len(c.Hashes) != 1 || c.Hashes[0].Alg != "SHA-256" || c.PURL != "" {
				t.Fatal("pinned requirement hash missing or index origin inferred")
			}
		}
	case "requirements-conditional":
		var conditional bool
		for _, edge := range doc.Edges {
			if edge.To == find("widget", "1.2.0") && edge.Condition == `python_version >= "3.11"` {
				conditional = true
			}
		}
		if !conditional || find("helper", "") == "" {
			t.Fatal("requirement marker or unresolved version missing")
		}
		var bom struct {
			Dependencies []struct {
				Ref       string   `json:"ref"`
				DependsOn []string `json:"dependsOn"`
			} `json:"dependencies"`
		}
		if err := json.Unmarshal(bomData, &bom); err != nil {
			t.Fatal(err)
		}
		for _, dep := range bom.Dependencies {
			if dep.Ref == "root" {
				for _, child := range dep.DependsOn {
					if child == find("widget", "1.2.0") {
						t.Fatal("conditional requirement exported as unconditional dependency")
					}
				}
			}
		}
	case "requirements-url":
		if len(doc.Origins) != 1 || doc.Origins[0].SafeURL != "https://downloads.example.test/direct-lib-1.0.whl" || doc.Origins[0].Kind != "download_url" {
			t.Fatal("direct URL missing or not sanitized")
		}
	case "requirements-constraint":
		found := false
		for _, issue := range doc.Coverage.Issues {
			if issue.Code == "constraint_not_applied" {
				found = true
			}
		}
		if !found {
			t.Fatal("unapplied constraint not reported")
		}
	case "requirements-multihash":
		if len(doc.Components[0].Hashes) != 0 {
			t.Fatal("hashes of multiple distributions assigned to one package")
		}
		found := false
		for _, issue := range doc.Coverage.Issues {
			found = found || issue.Code == "multiple_artifact_hashes_unassigned"
		}
		if !found {
			t.Fatal("unassigned distribution hashes not reported")
		}
	case "pub-basic":
		collection := find("collection", "1.19.1")
		if !connected("root", collection) || connected("root", find("meta", "1.16.0")) {
			t.Fatal("Pub direct and transitive packages were conflated")
		}
		for _, c := range doc.Components {
			if c.ID == collection && (c.PURL != "pkg:pub/collection@1.19.1" || len(c.Hashes) != 1 || c.Hashes[0].Alg != "SHA-256") {
				t.Fatal("Pub hosted package identity or content hash missing")
			}
		}
	case "pub-git":
		if len(doc.Origins) != 2 {
			t.Fatal("Pub Git or hosted source missing")
		}
		var vcs bool
		for _, origin := range doc.Origins {
			if origin.Kind == "vcs" && origin.SafeURL == "https://git.example.test/repo.git" && origin.Revision == "1234567890abcdef1234567890abcdef12345678" {
				vcs = true
			}
		}
		if !vcs {
			t.Fatal("Pub Git origin was not retained or sanitized")
		}
	case "pub-dev":
		var dev bool
		for _, edge := range doc.Edges {
			if edge.To == find("test", "1.25.0") && edge.Condition == "group=dev" {
				dev = true
			}
		}
		if !dev || !connected("root", find("flutter", "0.0.0")) {
			t.Fatal("Pub dev or Flutter SDK dependency missing")
		}
		var sdk bool
		for _, origin := range doc.Origins {
			if origin.Kind == "sdk" && origin.Target == "flutter" {
				sdk = true
			}
		}
		if !sdk {
			t.Fatal("Flutter SDK source missing")
		}
	case "pub-path":
		if !connected("root", find("local_plugin", "0.3.0")) || len(doc.Origins) != 2 {
			t.Fatal("Pub override or path source missing")
		}
	case "pub-old-hosted":
		if len(doc.Origins) != 0 || doc.Coverage.OriginState != "partial" {
			t.Fatal("Pub legacy hosted lock guessed registry URL")
		}
		if doc.Components[0].PURL != "" {
			t.Fatal("Pub legacy hosted lock guessed default-repository PURL")
		}
	case "pub-custom":
		if len(doc.Components) != 1 || doc.Components[0].PURL != "pkg:pub/private_widget@1.0.0?repository_url=https:%2F%2Fpub.example.test%2Frepository" {
			t.Fatalf("custom Pub repository missing from PURL: %#v", doc.Components)
		}
		if len(doc.Origins) != 1 || doc.Origins[0].SafeURL != "https://pub.example.test/repository" {
			t.Fatalf("custom Pub repository URL was not sanitized: %#v", doc.Origins)
		}
	case "gradle-basic":
		guava := find("com.google.guava:guava", "33.2.1-jre")
		if len(doc.Edges) != 0 {
			t.Fatal("Gradle lockfile inventory was presented as a dependency graph")
		}
		for _, c := range doc.Components {
			if c.ID == guava && (c.PURL != "" || c.Context != "configurations=compileClasspath,runtimeClasspath") {
				t.Fatalf("Gradle coordinates or configurations lost: %#v", c)
			}
		}
		var bom struct {
			Components []struct {
				Name       string `json:"name"`
				Properties []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"properties"`
			} `json:"components"`
		}
		if err := json.Unmarshal(bomData, &bom); err != nil {
			t.Fatal(err)
		}
		var preserved bool
		for _, component := range bom.Components {
			if component.Name != "com.google.guava:guava" {
				continue
			}
			for _, property := range component.Properties {
				if property.Name == "ravel:context" && property.Value == "configurations=compileClasspath,runtimeClasspath" {
					preserved = true
				}
			}
		}
		if !preserved {
			t.Fatal("Gradle configurations missing from CycloneDX output")
		}
	case "gradle-versions":
		if find("org.example:widget", "1.0.0") == find("org.example:widget", "2.0.0") || len(doc.Edges) != 0 {
			t.Fatal("Gradle configuration-specific versions were collapsed")
		}
	case "gradle-buildscript":
		if doc.Components[0].Context != "configurations=classpath" {
			t.Fatal("Gradle buildscript configuration missing")
		}
	case "maven-basic":
		api := find("org.slf4j:slf4j-api", "2.0.13")
		if !connected("root", api) || !connected(api, find("org.example:api", "3.0.0")) {
			t.Fatal("Maven resolved dependency tree was not preserved")
		}
	case "maven-pom-basic":
		if len(doc.Edges) != 3 || !connected("root", find("org.slf4j:slf4j-api", "2.0.13")) || !connected("root", find("org.example:property-resolved", "3.2.1")) {
			t.Fatal("Maven POM direct dependencies missing")
		}
		for _, edge := range doc.Edges {
			if edge.To == find("org.junit.jupiter:junit-jupiter", "5.10.2") && edge.Condition != "scope=test && optional=true" {
				t.Fatalf("Maven POM conditions lost: %#v", edge)
			}
		}
		for _, component := range doc.Components {
			if component.Name == "org.example:managed-only" || component.Name == "org.example:property-version" {
				t.Fatalf("unselected Maven declaration included: %#v", component)
			}
		}
	case "maven-pom-module":
		found := false
		for _, issue := range doc.Coverage.Issues {
			found = found || issue.Code == "multi_module_scope_root"
		}
		if !found {
			t.Fatalf("Maven module boundary not reported: %#v", doc.Coverage.Issues)
		}
	case "maven-pom-duplicate":
		if len(doc.Components) != 0 {
			t.Fatalf("Maven duplicate declaration overstated selected versions: %#v", doc.Components)
		}
		found := false
		for _, issue := range doc.Coverage.Issues {
			found = found || issue.Code == "duplicate_spec"
		}
		if !found {
			t.Fatalf("Maven duplicate declaration not reported: %#v", doc.Coverage.Issues)
		}
	case "maven-scopes":
		junit := find("org.junit.jupiter:junit-jupiter", "5.10.2")
		guard := find("org.apiguardian:apiguardian-api", "1.1.2")
		if !connected("root", junit) || !connected(junit, guard) {
			t.Fatal("Maven test-scope tree missing")
		}
		for _, edge := range doc.Edges {
			if edge.To == junit || edge.To == guard {
				if edge.Condition != "scope=test" {
					t.Fatalf("Maven test scope was not propagated: %#v", edge)
				}
			}
		}
	case "maven-classifier":
		if len(doc.Components) != 2 || doc.Components[0].ID == doc.Components[1].ID {
			t.Fatal("Maven classifier occurrence was collapsed")
		}
		for _, c := range doc.Components {
			if c.PURL != "" {
				t.Fatal("Maven artifact without observed repository was assigned Maven Central PURL")
			}
		}
	case "maven-repeated":
		shared := find("org.example:shared", "2.0.0")
		main := find("org.example:main", "1.0.0")
		tests := find("org.example:tests", "1.0.0")
		if !connected(main, shared) || !connected(tests, shared) || len(doc.Components) != 3 {
			t.Fatal("Maven repeated package was duplicated or lost")
		}
		for _, edge := range doc.Edges {
			if (edge.From == tests || edge.To == tests) && edge.Condition != "scope=test" {
				t.Fatal("Maven test scope was not propagated through repeated package")
			}
		}
	case "npm-v3":
		alpha := find("alpha", "1.0.0")
		betaNested := find("beta", "1.1.0")
		betaRoot := find("beta", "2.0.0")
		if !connected(alpha, betaNested) || connected(alpha, betaRoot) || !connected("root", betaRoot) {
			t.Fatal("npm nested dependency resolved to the wrong package version")
		}
		for _, component := range doc.Components {
			if component.PURL != "" {
				t.Fatal("private npm registry package assigned default npm PURL")
			}
		}
	case "npm-optional", "bun-platform":
		var parsed struct {
			Dependencies []struct {
				Ref       string   `json:"ref"`
				DependsOn []string `json:"dependsOn"`
			} `json:"dependencies"`
		}
		if err := json.Unmarshal(bomData, &parsed); err != nil {
			t.Fatal(err)
		}
		if len(parsed.Dependencies) != 1 || parsed.Dependencies[0].Ref != "root" || len(parsed.Dependencies[0].DependsOn) != 1 {
			t.Fatalf("conditional edges became unconditional: %#v", parsed.Dependencies)
		}
	case "bun-git":
		var sawVCS bool
		for _, origin := range doc.Origins {
			if origin.Kind == "vcs" && origin.SafeURL == "https://github.com/team/gitpkg" {
				sawVCS = true
			}
		}
		if !sawVCS {
			t.Fatal("Bun Git source was not preserved")
		}
	case "bun-generated-1_3":
		if len(doc.Components) != 1 || len(doc.Components[0].Hashes) != 1 || doc.Components[0].Hashes[0].Alg != "SHA-512" || len(doc.Origins) != 0 || doc.Components[0].PURL != "" {
			t.Fatalf("generated Bun lockfile integrity or origin was misread: %#v", doc)
		}
	case "deno-v4":
		var found bool
		for _, c := range doc.Components {
			if c.Kind == "module" && c.Name == "https://cdn.example.test/lib/mod.ts" {
				found = true
			}
		}
		if !found {
			t.Fatal("Deno URL import was not retained as a module")
		}
	case "deno-generated-2_9":
		if len(doc.Components) != 1 || len(doc.Components[0].Hashes) != 1 || doc.Components[0].Hashes[0].Alg != "SHA-512" || len(doc.Origins) != 0 || doc.Components[0].PURL != "" {
			t.Fatalf("generated Deno lockfile integrity or source was misread: %#v", doc)
		}
	case "deno-v5":
		for _, component := range doc.Components {
			if strings.HasPrefix(component.Name, "@std/") && component.PURL != "" {
				t.Fatalf("JSR package was conflated with npm: %#v", component)
			}
		}
	case "deno-peer":
		find("typedoc", "0.28.19")
		find("typescript", "6.0.3")
	case "deno-source-only":
		path, bytes := find("@std/path", "1.0.1"), find("@std/bytes", "1.0.2")
		if !connected("root", path) || !connected(path, bytes) ||
			!connected("root", find("chalk", "5.3.0")) ||
			!connected("root", find("is-number", "7.0.0")) ||
			!connected("root", find("https://cdn.example.test/mod.ts", "")) {
			t.Fatal("Deno source imports or lockfile transitive edge missing")
		}
		for _, edge := range doc.Edges {
			if edge.From == "root" && edge.Evidence.Method != "source-import-analysis" {
				t.Fatal("source-only Deno root edge lacks source evidence")
			}
		}
		for _, issue := range doc.Coverage.Issues {
			if issue.Code == "missing_direct_dependencies" || issue.Code == "unresolved_dependency" {
				t.Fatalf("comment, string, or computed import was treated as a resolved dependency: %+v", issue)
			}
		}
		serialized, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(serialized), "secret") || strings.Contains(string(serialized), "hidden") {
			t.Fatal("Deno source or lock URL credentials leaked")
		}
	case "deno-source-mapped":
		if !connected("root", find("@std/path", "1.0.1")) ||
			!connected("root", find("@std/path", "0.100.1")) ||
			!connected("root", find("is-number", "7.0.0")) {
			t.Fatal("Deno import-map aliases or scoped version missing")
		}
		for _, issue := range doc.Coverage.Issues {
			if issue.Code == "unresolved_dependency" {
				t.Fatalf("local or scoped Deno import was not resolved: %+v", issue)
			}
		}
	case "deno-source-importmap":
		if !connected("root", find("chalk", "5.3.0")) || len(doc.Sources) != 3 {
			t.Fatal("separate Deno import map was not included")
		}
	case "deno-source-nested":
		if !connected("root", find("alpha", "1.0.0")) {
			t.Fatal("root Deno import missing")
		}
		if !slices.ContainsFunc(doc.Coverage.Issues, func(issue model.Issue) bool { return issue.Code == "source_scan_limited" }) {
			t.Fatal("nested Deno project was not reported as a separate scope")
		}
	case "deno-source-mismatch":
		if !slices.ContainsFunc(doc.Coverage.Issues, func(issue model.Issue) bool { return issue.Code == "unresolved_dependency" }) {
			t.Fatal("Deno source import with unpinned version was not reported")
		}
	case "swift-v2":
		var sawVCS bool
		for _, origin := range doc.Origins {
			if origin.Kind == "vcs" && origin.SafeURL == "https://github.com/apple/swift-algorithms.git" {
				sawVCS = true
			}
		}
		if !sawVCS {
			t.Fatal("SwiftPM VCS origin was not preserved or sanitized")
		}
	case "swift-v3":
		if doc.Coverage.GraphState != "unknown" || len(doc.Edges) != 0 {
			t.Fatal("SwiftPM pins were incorrectly treated as a dependency graph")
		}
	case "nuget-single":
		core := find("Example.Core", "2.0.0")
		abstractions := find("Example.Abstractions", "1.1.0")
		if !connected("root", core) || !connected(core, abstractions) {
			t.Fatal("NuGet dependency graph was not preserved")
		}
	case "nuget-multi":
		var parsed struct {
			Dependencies []any `json:"dependencies"`
		}
		if err := json.Unmarshal(bomData, &parsed); err != nil {
			t.Fatal(err)
		}
		if len(parsed.Dependencies) != 0 {
			t.Fatal("target framework-specific edges became unconditional")
		}
	case "uv-basic", "pylock-basic":
		first, second := "Requests", "idna"
		if fixture == "pylock-basic" {
			first, second = "click", "colorama"
		}
		a := find(first, map[string]string{"Requests": "2.32.3", "click": "8.1.3"}[first])
		b := find(second, map[string]string{"idna": "3.10", "colorama": "0.4.6"}[second])
		if !connected("root", a) || !connected(a, b) {
			t.Fatal("Python dependency chain was not preserved")
		}
		for _, c := range doc.Components {
			if c.ID == a && (c.PURL != "" || len(c.Hashes) != 1 || c.Hashes[0].Alg != "SHA-256") {
				t.Fatalf("private Python package assigned default PyPI identity or lost hash: %#v", c)
			}
			if c.ID == b && !strings.HasPrefix(c.PURL, "pkg:pypi/"+strings.ToLower(second)+"@") {
				t.Fatalf("default PyPI package identity missing: %#v", c)
			}
		}
	case "uv-generated-0_11":
		alpha := find("alpha", "1.0.0")
		beta := find("beta", "2.0.0")
		if !connected("root", alpha) || !connected(alpha, beta) || len(doc.Origins) != 2 {
			t.Fatal("uv workspace graph or local origins missing")
		}
		for _, component := range doc.Components {
			if component.PURL != "" {
				t.Fatalf("local uv package assigned PyPI PURL: %#v", component)
			}
		}
	case "uv-forked":
		old := find("pandas", "2.3.3")
		newer := find("pandas", "3.0.6")
		if !connected("root", old) || !connected("root", newer) || !connected(old, find("numpy", "1.26.4")) || !connected(newer, find("numpy", "2.4.6")) {
			t.Fatal("uv forked versions resolved incorrectly")
		}
		var parsed struct {
			Dependencies []struct {
				Ref string `json:"ref"`
			} `json:"dependencies"`
		}
		if err := json.Unmarshal(bomData, &parsed); err != nil {
			t.Fatal(err)
		}
		for _, dep := range parsed.Dependencies {
			if dep.Ref == "root" {
				t.Fatal("conditional uv root edges became unconditional")
			}
		}
	case "uv-sources":
		var vcs, archive, local bool
		for _, o := range doc.Origins {
			switch {
			case o.Kind == "vcs" && o.SafeURL == "https://github.com/team/git-lib" && o.Revision == "abcdef1234567890":
				vcs = true
			case o.Kind == "download_url" && o.SafeURL == "https://files.example.test/archive-lib.tar.gz":
				archive = true
			case o.Kind == "local":
				local = true
			}
		}
		if !vcs || !archive || !local {
			t.Fatalf("uv source types missing: %#v", doc.Origins)
		}
	case "pylock-marker":
		if !connected(find("ham", "3.0.0"), find("spam", "1.0.0")) || connected(find("ham", "3.0.0"), find("spam", "1.1.0")) {
			t.Fatal("pylock marker resolution failed")
		}
		var parsed struct {
			Dependencies []any `json:"dependencies"`
		}
		if err := json.Unmarshal(bomData, &parsed); err != nil {
			t.Fatal(err)
		}
		if len(parsed.Dependencies) != 0 {
			t.Fatal("conditional pylock edge became unconditional")
		}
	case "pylock-multiwheel":
		if len(doc.Components[0].Hashes) != 0 {
			t.Fatal("mutually exclusive wheel hashes attached to package")
		}
		if len(doc.Origins) != 2 {
			t.Fatalf("wheel source alternatives missing: %#v", doc.Origins)
		}
	case "bun-workspace":
		if !connected("root", find("alpha", "1.0.0")) || connected("root", find("beta", "1.0.0")) {
			t.Fatal("Bun workspace scope was overstated")
		}
	case "uv-extras":
		if !connected("root", find("base", "1.0.0")) || !connected("root", find("pillow", "11.0.0")) || !connected("root", find("pytest", "8.3.0")) {
			t.Fatal("uv extras or groups missing")
		}
		var parsed struct {
			Dependencies []struct {
				Ref       string   `json:"ref"`
				DependsOn []string `json:"dependsOn"`
			} `json:"dependencies"`
		}
		if err := json.Unmarshal(bomData, &parsed); err != nil {
			t.Fatal(err)
		}
		if len(parsed.Dependencies) != 1 || parsed.Dependencies[0].Ref != "root" || len(parsed.Dependencies[0].DependsOn) != 1 {
			t.Fatal("uv extra/group edges became unconditional")
		}
	case "pylock-vcs":
		if len(doc.Origins) != 1 || doc.Origins[0].Kind != "vcs" || doc.Origins[0].SafeURL != "https://github.com/team/git-package" || doc.Origins[0].Revision != "1234567890abcdef" {
			t.Fatalf("pylock VCS source wrong: %#v", doc.Origins)
		}
	case "nuget-assets-v3":
		core := find("Example.Core", "2.0.0")
		if !connected("root", core) || !connected(core, find("Example.Abstractions", "1.1.0")) {
			t.Fatal("NuGet assets graph missing")
		}
		if len(doc.Origins) != 0 {
			t.Fatal("configured NuGet source was attributed to a package")
		}
		for _, c := range doc.Components {
			if c.ID == core && (len(c.Hashes) != 1 || c.Hashes[0].Alg != "SHA-512") {
				t.Fatalf("NuGet assets hash missing: %#v", c.Hashes)
			}
		}
	case "nuget-assets-v4":
		var parsed struct {
			Dependencies []any `json:"dependencies"`
		}
		if err := json.Unmarshal(bomData, &parsed); err != nil {
			t.Fatal(err)
		}
		if len(parsed.Dependencies) != 0 {
			t.Fatal("NuGet v4 target alias edges became unconditional")
		}
	case "pnpm-basic":
		alpha, beta := find("alpha", "1.0.0"), find("beta", "2.0.0")
		if !connected("root", alpha) || !connected(alpha, beta) {
			t.Fatal("pnpm snapshot graph missing")
		}
		if len(doc.Origins) != 2 {
			t.Fatal("pnpm tarball sources missing")
		}
		for _, c := range doc.Components {
			if c.ID == alpha && (len(c.Hashes) != 1 || c.Hashes[0].Alg != "SHA-512") {
				t.Fatal("pnpm integrity missing")
			}
		}
	case "pnpm-v6-generated-8":
		odd, number := find("is-odd", "3.0.1"), find("is-number", "6.0.0")
		if !connected("root", odd) || !connected(odd, number) {
			t.Fatal("pnpm v6 package dependency graph missing")
		}
		for _, c := range doc.Components {
			if len(c.Hashes) != 1 || c.Hashes[0].Alg != "SHA-512" || c.PURL != "" {
				t.Fatal("pnpm v6 integrity missing or default registry identity invented")
			}
		}
	case "pnpm-v6-workspace-8":
		if !connected("root", find("is-number", "7.0.0")) {
			t.Fatal("pnpm v6 workspace importer dependency missing")
		}
		if !slices.ContainsFunc(doc.Coverage.Issues, func(issue model.Issue) bool { return issue.Code == "unresolved_dependency" }) {
			t.Fatal("pnpm v6 workspace link was not reported as unresolved")
		}
	case "pnpm-v6-peer":
		var widgets []string
		for _, c := range doc.Components {
			if c.Name == "widget" && c.Version == "1.0.0" {
				widgets = append(widgets, c.ID)
			}
		}
		if len(widgets) != 2 || widgets[0] == widgets[1] {
			t.Fatal("pnpm v6 peer occurrences collapsed")
		}
		left, right := find("react", "17.0.2"), find("react", "18.2.0")
		if !(connected(widgets[0], left) && connected(widgets[1], right) || connected(widgets[0], right) && connected(widgets[1], left)) {
			t.Fatal("pnpm v6 peer occurrences linked to wrong React version")
		}
	case "pnpm-peer":
		var widgets []string
		for _, c := range doc.Components {
			if c.Name == "widget" && c.Version == "1.0.0" {
				widgets = append(widgets, c.ID)
			}
		}
		if len(widgets) != 2 || widgets[0] == widgets[1] {
			t.Fatal("peer-specific pnpm occurrences collapsed")
		}
		left, right := find("react", "18.0.0"), find("react", "19.0.0")
		if !(connected(widgets[0], left) && connected(widgets[1], right) || connected(widgets[0], right) && connected(widgets[1], left)) {
			t.Fatal("pnpm peer snapshots linked to wrong version")
		}
	case "pnpm-workspace", "pnpm-optional", "pnpm-two-doc":
		var parsed struct {
			Dependencies []struct {
				Ref       string   `json:"ref"`
				DependsOn []string `json:"dependsOn"`
			} `json:"dependencies"`
		}
		if err := json.Unmarshal(bomData, &parsed); err != nil {
			t.Fatal(err)
		}
		if len(parsed.Dependencies) != 1 || parsed.Dependencies[0].Ref != "root" || len(parsed.Dependencies[0].DependsOn) != 1 {
			t.Fatalf("pnpm conditional edges became unconditional: %#v", parsed.Dependencies)
		}
	case "pnpm-link":
		if doc.Coverage.GraphState != "partial" || len(doc.Edges) != 0 {
			t.Fatal("unresolved pnpm workspace link was treated as complete")
		}
	case "poetry-basic":
		requests, idna := find("Requests", "2.32.3"), find("idna", "3.10")
		if !connected("root", requests) || !connected(requests, idna) {
			t.Fatal("Poetry dependency chain missing")
		}
		for _, c := range doc.Components {
			if c.ID == requests && (len(c.Hashes) != 1 || c.Hashes[0].Alg != "SHA-256" || c.PURL != "") {
				t.Fatal("Poetry private package hash missing or default PyPI PURL invented")
			}
			if c.ID == idna && c.PURL != "pkg:pypi/idna@3.10" {
				t.Fatal("Poetry default PyPI PURL missing")
			}
		}
	case "poetry-groups":
		var parsed struct {
			Dependencies []struct {
				Ref       string   `json:"ref"`
				DependsOn []string `json:"dependsOn"`
			} `json:"dependencies"`
		}
		if err := json.Unmarshal(bomData, &parsed); err != nil {
			t.Fatal(err)
		}
		if len(parsed.Dependencies) != 1 || parsed.Dependencies[0].Ref != "root" || len(parsed.Dependencies[0].DependsOn) != 1 {
			t.Fatal("Poetry conditional group/marker edge became unconditional")
		}
	case "poetry-no-project":
		if len(doc.Origins) != 1 || doc.Origins[0].Kind != "vcs" || doc.Origins[0].SafeURL != "https://github.com/team/git-lib" || doc.Origins[0].Revision != "abcdef1234567890" {
			t.Fatal("Poetry Git origin was not sanitized")
		}
		if doc.Components[0].PURL != "" {
			t.Fatal("Poetry Git package assigned PyPI PURL")
		}
	case "poetry-ambiguous":
		if !connected("root", find("parent", "1.0.0")) || len(doc.Edges) != 1 {
			t.Fatal("Poetry ambiguous dependency was guessed")
		}
	case "yarn-classic-basic", "yarn-berry-basic":
		alpha, beta := find("alpha", "1.1.0"), find("beta", "2.0.0")
		if !connected("root", alpha) || !connected(alpha, beta) {
			t.Fatal("Yarn dependency chain missing")
		}
		for _, c := range doc.Components {
			if c.PURL != "" {
				t.Fatal("Yarn source without confirmed default registry assigned npm PURL")
			}
			if c.ID == alpha {
				if fixture == "yarn-classic-basic" && (len(c.Hashes) != 1 || c.Hashes[0].Alg != "SHA-512") {
					t.Fatal("Yarn Classic integrity missing")
				}
				if fixture == "yarn-berry-basic" && len(c.Hashes) != 0 {
					t.Fatal("Yarn cache checksum was treated as an artifact hash")
				}
			}
		}
	case "yarn-classic-optional", "yarn-berry-optional":
		var parsed struct {
			Dependencies []struct {
				Ref       string   `json:"ref"`
				DependsOn []string `json:"dependsOn"`
			} `json:"dependencies"`
		}
		if err := json.Unmarshal(bomData, &parsed); err != nil {
			t.Fatal(err)
		}
		if len(parsed.Dependencies) != 1 || parsed.Dependencies[0].Ref != "root" || len(parsed.Dependencies[0].DependsOn) != 1 {
			t.Fatal("Yarn optional edge became unconditional")
		}
	case "yarn-classic-ambiguous":
		if len(doc.Components) != 0 || len(doc.Edges) != 0 {
			t.Fatal("conflicting Yarn descriptor was guessed")
		}
	case "yarn-berry-remote":
		if len(doc.Origins) != 1 || doc.Origins[0].SafeURL != "https://files.example.test/foo-1.0.0.tgz" {
			t.Fatal("Yarn remote URL not sanitized")
		}
	case "yarn-berry-workspace":
		web, alpha := find("web", "1.0.0"), find("alpha", "1.0.0")
		if !connected("root", web) || !connected(web, alpha) {
			t.Fatal("Yarn workspace graph missing")
		}
		var parsed struct {
			Components []struct {
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"components"`
		}
		if err := json.Unmarshal(bomData, &parsed); err != nil {
			t.Fatal(err)
		}
		for _, c := range parsed.Components {
			if c.Name == "web" && c.Type != "application" {
				t.Fatal("Yarn workspace exported with wrong component type")
			}
		}
	case "yarn-generated-4":
		alpha, beta := find("@ravel/alpha", "1.0.0"), find("@ravel/beta", "2.0.0")
		if !connected("root", alpha) || !connected(alpha, beta) || len(doc.Sources) != 2 {
			t.Fatalf("Yarn 4 workspace versions or graph wrong: %#v", doc)
		}
	case "poetry-shared-extra":
		if len(doc.Edges) != 3 {
			t.Fatal("Poetry main, extra and group declarations were collapsed")
		}
		for _, e := range doc.Edges {
			if !strings.Contains(e.Condition, "||") {
				t.Fatal("Poetry group markers were joined as an impossible conjunction")
			}
		}
		var parsed struct {
			Dependencies []any `json:"dependencies"`
		}
		if err := json.Unmarshal(bomData, &parsed); err != nil {
			t.Fatal(err)
		}
		if len(parsed.Dependencies) != 0 {
			t.Fatal("Poetry conditional root edges became unconditional")
		}
	case "cargo-basic":
		alpha, beta := find("alpha", "1.0.0"), find("beta", "2.0.0")
		if !connected("root", alpha) || !connected(alpha, beta) {
			t.Fatal("Cargo lock graph missing")
		}
		for _, component := range doc.Components {
			if component.PURL != "" {
				t.Fatalf("alternate Cargo registry was conflated with crates.io: %#v", component)
			}
		}
		for _, c := range doc.Components {
			if c.ID == alpha && (len(c.Hashes) != 1 || c.Hashes[0].Alg != "SHA-256") {
				t.Fatal("Cargo checksum missing")
			}
		}
		var parsed struct {
			Dependencies []struct {
				Ref       string   `json:"ref"`
				DependsOn []string `json:"dependsOn"`
			} `json:"dependencies"`
		}
		if err := json.Unmarshal(bomData, &parsed); err != nil {
			t.Fatal(err)
		}
		if len(parsed.Dependencies) != 1 || parsed.Dependencies[0].Ref != "root" || len(parsed.Dependencies[0].DependsOn) != 1 {
			t.Fatal("Cargo feature/target union was exported unconditionally")
		}
	case "cargo-git":
		if len(doc.Origins) != 1 || doc.Origins[0].Kind != "vcs" || doc.Origins[0].SafeURL != "https://github.com/team/git-lib" || doc.Origins[0].Revision != "abcdef1234567890" {
			t.Fatal("Cargo Git source not sanitized")
		}
		if doc.Components[0].PURL != "" {
			t.Fatal("Cargo Git source was conflated with crates.io")
		}
	case "cargo-sparse-default":
		if len(doc.Components) != 1 || doc.Components[0].PURL != "pkg:cargo/serde@1.0.197" {
			t.Fatalf("default sparse Cargo registry PURL missing: %#v", doc.Components)
		}
	case "cargo-workspace":
		web, alpha := find("web", "1.0.0"), find("alpha", "1.0.0")
		if !connected("root", web) || !connected(web, alpha) {
			t.Fatal("Cargo workspace graph missing")
		}
		var parsed struct {
			Components []struct {
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"components"`
		}
		if err := json.Unmarshal(bomData, &parsed); err != nil {
			t.Fatal(err)
		}
		for _, c := range parsed.Components {
			if c.Name == "web" && c.Type != "application" {
				t.Fatal("Cargo workspace component type wrong")
			}
		}
	case "cargo-ambiguous":
		if len(doc.Edges) != 0 {
			t.Fatal("Cargo ambiguous version was guessed")
		}
	case "composer-basic":
		monolog, psr := find("monolog/monolog", "3.0.0"), find("psr/log", "3.0.0")
		if !connected("root", monolog) || !connected(monolog, psr) {
			t.Fatal("Composer graph missing")
		}
		var vcs, dist bool
		for _, o := range doc.Origins {
			if o.Occurrence == monolog && o.Kind == "vcs" && o.SafeURL == "https://github.com/Seldaek/monolog.git" {
				vcs = true
			}
			if o.Occurrence == monolog && o.Kind == "download_url" && o.SafeURL == "https://api.github.com/repos/Seldaek/monolog/zipball/abcdef1234567890" {
				dist = true
			}
		}
		if !vcs || !dist {
			t.Fatal("Composer source and dist were conflated")
		}
	case "composer-dev":
		var parsed struct {
			Dependencies []struct {
				Ref       string   `json:"ref"`
				DependsOn []string `json:"dependsOn"`
			} `json:"dependencies"`
		}
		if err := json.Unmarshal(bomData, &parsed); err != nil {
			t.Fatal(err)
		}
		if len(parsed.Dependencies) != 1 || parsed.Dependencies[0].Ref != "root" || len(parsed.Dependencies[0].DependsOn) != 1 {
			t.Fatal("Composer dev edges became unconditional")
		}
	case "composer-path":
		if len(doc.Origins) != 1 || doc.Origins[0].Kind != "local" {
			t.Fatal("Composer path source missing")
		}
	case "composer-generated-2":
		alpha, beta := find("acme/alpha", "1.0.0"), find("acme/beta", "2.0.1")
		if !connected("root", alpha) || !connected(alpha, beta) {
			t.Fatal("Composer 2 path graph missing")
		}
		for _, component := range doc.Components {
			if component.PURL != "" {
				t.Fatal("local Composer package was identified as Packagist")
			}
		}
	case "composer-ambiguous":
		if len(doc.Edges) != 0 {
			t.Fatal("Composer duplicate versions were guessed")
		}
	case "cocoapods-basic":
		alpha, beta := find("Alpha", "1.2.3"), find("Beta", "2.0.1")
		if !connected("root", alpha) || !connected(alpha, beta) {
			t.Fatal("CocoaPods dependency graph missing")
		}
		for _, component := range doc.Components {
			if len(component.Hashes) != 0 {
				t.Fatal("podspec checksum was treated as artifact hash")
			}
		}
		var parsed struct {
			Dependencies []any `json:"dependencies"`
		}
		if err := json.Unmarshal(bomData, &parsed); err != nil {
			t.Fatal(err)
		}
		if len(parsed.Dependencies) != 0 {
			t.Fatal("CocoaPods merged target edges became unconditional")
		}
	case "cocoapods-subspec":
		firebase := find("Firebase/CoreOnly", "10.0.0")
		core := find("FirebaseCore", "10.0.0")
		env := find("GoogleUtilities/Environment", "7.0.0")
		if !connected("root", firebase) || !connected(firebase, core) || !connected(core, env) {
			t.Fatal("CocoaPods subspec graph missing")
		}
		for _, component := range doc.Components {
			if component.ID == firebase && component.PURL != "pkg:cocoapods/Firebase@10.0.0#CoreOnly" {
				t.Fatalf("wrong subspec PURL: %s", component.PURL)
			}
		}
	case "cocoapods-git":
		for _, component := range doc.Components {
			if component.Name == "SecretKit" && component.PURL != "" {
				t.Fatal("external CocoaPods Git source was assigned trunk PURL")
			}
		}
		var vcs bool
		for _, origin := range doc.Origins {
			if origin.Kind == "vcs" && origin.SafeURL == "https://github.com/team/SecretKit.git" && origin.Revision == "abcdef1234567890" {
				vcs = true
			}
		}
		if !vcs {
			t.Fatal("CocoaPods Git checkout source missing or unsafe")
		}
	case "cocoapods-path":
		if len(doc.Origins) != 1 || doc.Origins[0].Kind != "local" || doc.Origins[0].SafeURL != "" {
			t.Fatal("CocoaPods local source was not preserved")
		}
	case "cocoapods-ambiguous":
		if len(doc.Edges) != 0 {
			t.Fatal("CocoaPods duplicate pod was guessed")
		}
	case "cocoapods-no-deps":
		if len(doc.Edges) != 0 {
			t.Fatal("CocoaPods missing DEPENDENCIES invented root edges")
		}
	case "cocoapods-custom-repo":
		if len(doc.Origins) != 1 || doc.Origins[0].SafeURL != "https://pods.example.test/specs.git" || doc.Origins[0].Kind != "declared_registry" {
			t.Fatal("CocoaPods custom spec repo was not sanitized")
		}
		if len(doc.Components) != 1 || doc.Components[0].PURL != "pkg:cocoapods/EdgeKit@3.0.0?repository_url=https:%2F%2Fpods.example.test%2Fspecs.git" {
			t.Fatal("CocoaPods custom spec repo missing from PURL")
		}
	case "cocoapods-remote":
		var download, podspec bool
		for _, origin := range doc.Origins {
			if origin.Kind == "download_url" && origin.SafeURL == "https://files.example.test/RemoteKit.zip" {
				download = true
			}
			if origin.Kind == "podspec" && origin.SafeURL == "https://specs.example.test/PodspecKit.podspec" {
				podspec = true
			}
		}
		if !download || !podspec {
			t.Fatal("CocoaPods HTTP and podspec sources were conflated")
		}
	case "cocoapods-ambiguous-repo":
		if len(doc.Origins) != 2 {
			t.Fatal("CocoaPods spec repo alternatives were discarded")
		}
		if len(doc.Components) != 1 || doc.Components[0].PURL != "" {
			t.Fatal("ambiguous CocoaPods spec repos were assigned a single PURL")
		}
		var ambiguous bool
		for _, issue := range doc.Coverage.Issues {
			if issue.Code == "ambiguous_source" {
				ambiguous = true
			}
		}
		if !ambiguous {
			t.Fatal("CocoaPods multiple spec repos were reported as certain")
		}
	case "pipenv-basic":
		requests := find("Requests", "2.32.3")
		if !connected("root", requests) || len(doc.Edges) != 1 {
			t.Fatal("Pipenv flat lockfile invented transitive edges")
		}
		for _, component := range doc.Components {
			if len(component.Hashes) != 0 {
				t.Fatal("Pipenv alternative hashes were attached to a package")
			}
		}
	case "pipenv-groups":
		if !connected("root", find("click", "8.1.3")) || !connected("root", find("pytest", "8.3.0")) || !connected("root", find("sphinx", "8.0.0")) {
			t.Fatal("Pipenv category roots missing")
		}
		for _, edge := range doc.Edges {
			if edge.To == find("pytest", "8.3.0") && (!strings.Contains(edge.Condition, "group=develop") || !strings.Contains(edge.Condition, "marker=")) {
				t.Fatal("Pipenv develop marker lost")
			}
			if edge.To == find("sphinx", "8.0.0") && edge.Condition != "group=docs" {
				t.Fatal("Pipenv custom category lost")
			}
		}
		var parsed struct {
			Dependencies []struct {
				Ref string `json:"ref"`
			} `json:"dependencies"`
		}
		if err := json.Unmarshal(bomData, &parsed); err != nil {
			t.Fatal(err)
		}
		if len(parsed.Dependencies) != 1 || parsed.Dependencies[0].Ref != "root" {
			t.Fatal("Pipenv conditional groups became unconditional")
		}
	case "pipenv-sources":
		var vcs, archive, local bool
		for _, origin := range doc.Origins {
			switch {
			case origin.Kind == "vcs" && origin.SafeURL == "https://github.com/team/git-lib.git" && origin.Revision == "abcdef1234567890":
				vcs = true
			case origin.Kind == "download_url" && origin.SafeURL == "https://files.example.test/archive-lib.tar.gz":
				archive = true
			case origin.Kind == "local":
				local = true
			}
		}
		if !vcs || !archive || !local {
			t.Fatal("Pipenv source types missing or unsafe")
		}
		for _, component := range doc.Components {
			if component.PURL != "" {
				t.Fatal("Pipenv non-registry package assigned PyPI PURL")
			}
		}
	case "pipenv-multisource":
		alpha, beta := find("alpha", "1.0.0"), find("beta", "2.0.0")
		var alphaPrivate, betaSources int
		for _, origin := range doc.Origins {
			if origin.Occurrence == alpha && origin.SafeURL == "https://packages.example.test/simple" {
				alphaPrivate++
			}
			if origin.Occurrence == beta {
				betaSources++
			}
		}
		if alphaPrivate != 1 || betaSources != 2 {
			t.Fatal("Pipenv index and ambiguous sources were conflated")
		}
	case "pipenv-no-manifest":
		if len(doc.Edges) != 0 {
			t.Fatal("Pipenv direct edges invented without Pipfile")
		}
	case "pdm-basic":
		alpha, beta := find("alpha", "1.0.0"), find("beta", "2.0.0")
		if !connected("root", alpha) || !connected(alpha, beta) {
			t.Fatal("PDM dependency graph missing")
		}
		for _, edge := range doc.Edges {
			if edge.From == alpha && !strings.Contains(edge.Condition, "python=(>=3.9)") {
				t.Fatal("PDM package Python constraint lost")
			}
		}
		if len(doc.Origins) != 0 {
			t.Fatal("PDM filenames were treated as download URLs")
		}
		for _, component := range doc.Components {
			if len(component.Hashes) != 0 || component.PURL != "" {
				t.Fatal("PDM wheel hash or default PyPI identity inferred without evidence")
			}
		}
	case "pdm-groups":
		if !connected("root", find("alpha", "1.0.0")) || !connected("root", find("pytest", "8.0.0")) || !connected(find("alpha", "1.0.0"), find("beta", "2.0.0")) {
			t.Fatal("PDM group or marker graph missing")
		}
		for _, edge := range doc.Edges {
			if !strings.Contains(edge.Condition, "target=unselected") {
				t.Fatal("PDM target was lost")
			}
		}
		var parsed struct {
			Dependencies []any `json:"dependencies"`
		}
		if err := json.Unmarshal(bomData, &parsed); err != nil {
			t.Fatal(err)
		}
		if len(parsed.Dependencies) != 0 {
			t.Fatal("PDM target edges became unconditional")
		}
	case "pdm-extras":
		var pluginIDs []string
		for _, component := range doc.Components {
			if component.Name == "plugin" {
				pluginIDs = append(pluginIDs, component.ID)
			}
		}
		if len(pluginIDs) != 2 {
			t.Fatal("PDM extras variant collapsed")
		}
		app, speed := find("app", "1.0.0"), find("speedlib", "2.0.0")
		var variant, base string
		for _, id := range pluginIDs {
			if connected(id, speed) {
				variant = id
			} else {
				base = id
			}
		}
		if variant == "" || base == "" || !connected(app, variant) || !connected(variant, base) {
			t.Fatal("PDM extras dependency linked to wrong occurrence")
		}
	case "pdm-sources":
		var vcs, archive, local bool
		for _, origin := range doc.Origins {
			switch {
			case origin.Kind == "vcs" && origin.SafeURL == "https://github.com/team/git-lib.git" && origin.Revision == "abcdef1234567890":
				vcs = true
			case origin.Kind == "download_url" && origin.SafeURL == "https://files.example.test/archive-lib-1.0.0.tar.gz":
				archive = true
			case origin.Kind == "local":
				local = true
			}
		}
		if !vcs || !archive || !local {
			t.Fatal("PDM source types missing or unsafe")
		}
		for _, component := range doc.Components {
			if component.PURL != "" {
				t.Fatal("PDM non-registry package assigned PyPI PURL")
			}
		}
	case "pdm-no-manifest":
		if len(doc.Edges) != 0 {
			t.Fatal("PDM root edges invented without pyproject.toml")
		}
	case "go-vendor-basic":
		alpha, text := find("github.com/acme/alpha", "v1.2.3"), find("golang.org/x/text", "v0.14.0")
		if !connected("root", alpha) || connected("root", text) || len(doc.Edges) != 1 {
			t.Fatal("Go direct and indirect requirements were conflated")
		}
		for _, issue := range doc.Coverage.Issues {
			if issue.Code == "vendor_manifest_mismatch" {
				t.Fatal("valid unused Go module header was called stale")
			}
		}
		for _, component := range doc.Components {
			if len(component.Hashes) != 0 {
				t.Fatal("go.sum hash was attached to vendored code")
			}
			if component.ID == alpha && component.PURL != "pkg:golang/github.com/acme/alpha@v1.2.3" {
				t.Fatal("Go module PURL missing")
			}
		}
	case "go-vendor-local":
		if len(doc.Origins) != 1 || doc.Origins[0].Kind != "local" || doc.Components[0].PURL != "" {
			t.Fatal("Go local replacement was misidentified")
		}
	case "go-vendor-replacement":
		if len(doc.Origins) != 1 || doc.Origins[0].Kind != "module_replacement" || doc.Origins[0].Target != "example.com/forks/alpha@v1.2.4" || doc.Components[0].PURL != "" {
			t.Fatal("Go module replacement was misidentified")
		}
	case "go-vendor-stale":
		if len(doc.Edges) != 0 {
			t.Fatal("stale Go vendor manifest produced root edge")
		}
		var mismatch bool
		for _, issue := range doc.Coverage.Issues {
			if issue.Code == "vendor_manifest_mismatch" {
				mismatch = true
			}
		}
		if !mismatch {
			t.Fatal("stale Go vendor manifest was not reported")
		}
	case "go-vendor-missing":
		if len(doc.Components) != 0 {
			t.Fatal("missing Go vendor package was invented")
		}
		var missing bool
		for _, issue := range doc.Coverage.Issues {
			if issue.Code == "vendor_package_missing" {
				missing = true
			}
		}
		if !missing {
			t.Fatal("missing Go vendor package not reported")
		}
	case "go-vendor-no-mod", "go-vendor-workspace":
		if len(doc.Edges) != 0 {
			t.Fatal("Go root edges invented without a single go.mod scope")
		}
	}
}

func TestStrictPartialStillWritesOutput(t *testing.T) {
	outFile := filepath.Join(t.TempDir(), "sbom.json")
	cmd := exec.Command(executable, "scan", filepath.Join("..", "testdata", "fixtures", "bundler-ambiguous"), "--strict", "--output", outFile)
	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 3 {
		t.Fatalf("expected exit status 3, got %v", err)
	}
	if _, err := os.Stat(outFile); err != nil {
		t.Fatalf("output not written on partial scan: %v", err)
	}
}

func TestManagerSelectionAndUnsupportedFormats(t *testing.T) {
	project := t.TempDir()
	for _, fixture := range []struct{ source, destination string }{
		{filepath.Join("..", "testdata", "fixtures", "npm-v2", "package-lock.json"), "package-lock.json"},
		{filepath.Join("..", "testdata", "fixtures", "bun-basic", "bun.lock"), "bun.lock"},
		{filepath.Join("..", "testdata", "fixtures", "pnpm-basic", "pnpm-lock.yaml"), "pnpm-lock.yaml"},
		{filepath.Join("..", "testdata", "fixtures", "yarn-classic-basic", "yarn.lock"), "yarn.lock"},
	} {
		data, err := os.ReadFile(fixture.source)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(project, fixture.destination), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := exec.Command(executable, "scan", project, "--output", filepath.Join(t.TempDir(), "out.json")).Run(); err == nil {
		t.Fatal("ambiguous manager was silently selected")
	}
	if err := os.WriteFile(filepath.Join(project, "package.json"), []byte(`{"packageManager":"bun@1.2.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args    []string
		manager string
	}{
		{nil, "bun"},
		{[]string{"--manager", "npm"}, "npm"},
		{[]string{"--manager", "pnpm"}, "pnpm"},
		{[]string{"--manager", "yarn"}, "yarn"},
	} {
		report := filepath.Join(t.TempDir(), "coverage.json")
		args := append([]string{"scan", project, "--output", filepath.Join(t.TempDir(), "sbom.json"), "--report", report}, tc.args...)
		if output, err := exec.Command(executable, args...).CombinedOutput(); err != nil {
			t.Fatalf("manager selection failed: %v: %s", err, output)
		}
		data, err := os.ReadFile(report)
		if err != nil {
			t.Fatal(err)
		}
		var coverage model.Coverage
		if err := json.Unmarshal(data, &coverage); err != nil {
			t.Fatal(err)
		}
		if coverage.Manager != tc.manager {
			t.Fatalf("manager=%s, wanted %s", coverage.Manager, tc.manager)
		}
	}
	if err := os.WriteFile(filepath.Join(project, "package.json"), []byte(`{"packageManager":"pnpm@9.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	pnpmReport := filepath.Join(t.TempDir(), "pnpm-coverage.json")
	if output, err := exec.Command(executable, "scan", project, "--output", filepath.Join(t.TempDir(), "pnpm.json"), "--report", pnpmReport).CombinedOutput(); err != nil {
		t.Fatalf("pnpm auto selection failed: %v: %s", err, output)
	}
	pnpmData, err := os.ReadFile(pnpmReport)
	if err != nil {
		t.Fatal(err)
	}
	var pnpmCoverage model.Coverage
	if err := json.Unmarshal(pnpmData, &pnpmCoverage); err != nil {
		t.Fatal(err)
	}
	if pnpmCoverage.Manager != "pnpm" {
		t.Fatal("packageManager pnpm hint ignored")
	}
	if err := os.WriteFile(filepath.Join(project, "package.json"), []byte(`{"packageManager":"yarn@1.22.0","dependencies":{"alpha":"^1.0.0"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	yarnReport := filepath.Join(t.TempDir(), "yarn-coverage.json")
	if output, err := exec.Command(executable, "scan", project, "--output", filepath.Join(t.TempDir(), "yarn.json"), "--report", yarnReport).CombinedOutput(); err != nil {
		t.Fatalf("Yarn auto selection failed: %v: %s", err, output)
	}
	yarnData, err := os.ReadFile(yarnReport)
	if err != nil {
		t.Fatal(err)
	}
	var yarnCoverage model.Coverage
	if err := json.Unmarshal(yarnData, &yarnCoverage); err != nil {
		t.Fatal(err)
	}
	if yarnCoverage.Manager != "yarn" {
		t.Fatal("packageManager yarn hint ignored")
	}
	for _, name := range []string{"bun-legacy", "uv-unsupported", "pylock-unsupported", "nuget-assets-unsupported", "pnpm-unsupported", "poetry-unsupported", "yarn-unsupported", "cargo-unsupported", "composer-unsupported", "cocoapods-unsupported", "pipenv-unsupported", "pdm-unsupported", "go-vendor-unsupported", "pub-unsupported", "gradle-unsupported", "maven-unsupported", "maven-option-unsupported"} {
		cmd := exec.Command(executable, "scan", filepath.Join("..", "testdata", "fixtures", name), "--output", filepath.Join(t.TempDir(), "sbom.json"))
		if err := cmd.Run(); err == nil {
			t.Fatalf("unsupported format %s unexpectedly succeeded", name)
		}
	}
	pylockDir := t.TempDir()
	for _, name := range []string{"pylock.dev.toml", "pylock.prod.toml"} {
		if err := os.WriteFile(filepath.Join(pylockDir, name), []byte("lock-version = \"1.0\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := exec.Command(executable, "scan", pylockDir, "--manager", "pylock").Run(); err == nil {
		t.Fatal("multiple pylock variants were silently selected")
	}
}

func TestDeterministicOutputAndLockfileProtection(t *testing.T) {
	for _, name := range []string{"npm-v3", "uv-forked", "pylock-multiwheel", "nuget-assets-v4", "poetry-shared-extra", "yarn-berry-basic", "cargo-basic"} {
		t.Run(name, func(t *testing.T) {
			fixture := filepath.Join("..", "testdata", "fixtures", name)
			var first []byte
			for i := 0; i < 3; i++ {
				out := filepath.Join(t.TempDir(), "ravel.json")
				if output, err := exec.Command(executable, "scan", fixture, "--format", "ravel-json", "--output", out).CombinedOutput(); err != nil {
					t.Fatalf("scan failed: %v: %s", err, output)
				}
				data, err := os.ReadFile(out)
				if err != nil {
					t.Fatal(err)
				}
				if i == 0 {
					first = data
				} else if string(data) != string(first) {
					t.Fatal("Ravel JSON is nondeterministic")
				}
			}
		})
	}
	lock := filepath.Join("..", "testdata", "fixtures", "uv-basic", "uv.lock")
	before, err := os.ReadFile(lock)
	if err != nil {
		t.Fatal(err)
	}
	if err := exec.Command(executable, "scan", lock, "--output", lock).Run(); err == nil {
		t.Fatal("scan overwrote its lockfile")
	}
	after, err := os.ReadFile(lock)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("lockfile changed after rejected output path")
	}
}

func TestExplainCLI(t *testing.T) {
	input := filepath.Join(t.TempDir(), "ravel.json")
	fixture := filepath.Join("..", "testdata", "fixtures", "composer-basic")
	if output, err := exec.Command(executable, "scan", fixture, "--format", "ravel-json", "--output", input).CombinedOutput(); err != nil {
		t.Fatalf("scan failed: %v: %s", err, output)
	}
	query := "monolog/monolog"
	output, err := exec.Command(executable, "explain", query, "--input", input).CombinedOutput()
	if err != nil {
		t.Fatalf("explain failed: %v: %s", err, output)
	}
	for _, want := range []string{"monolog/monolog@3.0.0", "https://github.com/Seldaek/monolog.git", "https://api.github.com/repos/Seldaek/monolog/zipball/abcdef1234567890", "required by: composer-basic", "depends on: psr/log@3.0.0", "composer.lock", "composer.json", "coverage: graph=partial"} {
		if !strings.Contains(string(output), want) {
			t.Fatalf("explanation missing %q: %s", want, output)
		}
	}
	if strings.Contains(string(output), "secret") || strings.Contains(string(output), "hidden") {
		t.Fatalf("explanation leaked lockfile credentials: %s", output)
	}
	output, err = exec.Command(executable, "explain", query, "--input", input, "--format", "json").CombinedOutput()
	if err != nil {
		t.Fatalf("JSON explain failed: %v: %s", err, output)
	}
	var detail report.Explanation
	if err := json.Unmarshal(output, &detail); err != nil {
		t.Fatal(err)
	}
	if detail.Component.PURL != "" || len(detail.Origins) != 2 || len(detail.Incoming) != 1 || len(detail.Outgoing) != 1 {
		t.Fatalf("unexpected explanation: %#v", detail)
	}
	if err := exec.Command(executable, "explain", query, "extra", "--input", input).Run(); err == nil {
		t.Fatal("explain accepted an extra package query")
	}
	ambiguous := filepath.Join(t.TempDir(), "ambiguous.json")
	fixture = filepath.Join("..", "testdata", "fixtures", "composer-ambiguous")
	if output, err := exec.Command(executable, "scan", fixture, "--format", "ravel-json", "--output", ambiguous).CombinedOutput(); err != nil {
		t.Fatalf("ambiguous scan failed: %v: %s", err, output)
	}
	if output, err := exec.Command(executable, "explain", "team/foo", "--input", ambiguous).CombinedOutput(); err == nil || !strings.Contains(string(output), "ambiguous") {
		t.Fatalf("ambiguous package name was not rejected: %v: %s", err, output)
	}
}

func TestExplainConfirmedPURL(t *testing.T) {
	input := filepath.Join(t.TempDir(), "ravel.json")
	fixture := filepath.Join("..", "testdata", "fixtures", "npm-generated-12")
	if output, err := exec.Command(executable, "scan", fixture, "--format", "ravel-json", "--output", input).CombinedOutput(); err != nil {
		t.Fatalf("scan failed: %v: %s", err, output)
	}
	query := "pkg:npm/is-number@7.0.0"
	output, err := exec.Command(executable, "explain", query, "--input", input, "--format", "json").CombinedOutput()
	if err != nil {
		t.Fatalf("PURL query failed: %v: %s", err, output)
	}
	var explanation report.Explanation
	if err := json.Unmarshal(output, &explanation); err != nil {
		t.Fatal(err)
	}
	if explanation.Component.PURL != query || explanation.Component.Name != "is-number" {
		t.Fatalf("confirmed PURL query returned wrong package: %#v", explanation.Component)
	}
}

func TestDiffCLI(t *testing.T) {
	fixture := filepath.Join("..", "testdata", "fixtures", "composer-basic")
	before := filepath.Join(t.TempDir(), "before.json")
	if output, err := exec.Command(executable, "scan", fixture, "--format", "ravel-json", "--output", before).CombinedOutput(); err != nil {
		t.Fatalf("before scan failed: %v: %s", err, output)
	}
	identical := filepath.Join(t.TempDir(), "identical.json")
	if output, err := exec.Command(executable, "scan", fixture, "--format", "ravel-json", "--output", identical).CombinedOutput(); err != nil {
		t.Fatalf("identical scan failed: %v: %s", err, output)
	}
	output, err := exec.Command(executable, "diff", before, identical, "--format", "json").CombinedOutput()
	if err != nil {
		t.Fatalf("identical diff failed: %v: %s", err, output)
	}
	var same report.Diff
	if err := json.Unmarshal(output, &same); err != nil {
		t.Fatal(err)
	}
	if len(same.AddedComponents)+len(same.RemovedComponents)+len(same.ChangedComponents)+len(same.AddedEdges)+len(same.RemovedEdges)+len(same.AddedOrigins)+len(same.RemovedOrigins) != 0 {
		t.Fatalf("identical scans differ: %#v", same)
	}
	project := t.TempDir()
	manifest, err := os.ReadFile(filepath.Join(fixture, "composer.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "composer.json"), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	lock, err := os.ReadFile(filepath.Join(fixture, "composer.lock"))
	if err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(string(lock), `"name": "psr/log", "version": "3.0.0"`, `"name": "psr/log", "version": "3.1.0"`, 1)
	if changed == string(lock) {
		t.Fatal("fixture version was not changed")
	}
	if err := os.WriteFile(filepath.Join(project, "composer.lock"), []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	after := filepath.Join(t.TempDir(), "after.json")
	if output, err := exec.Command(executable, "scan", project, "--format", "ravel-json", "--output", after).CombinedOutput(); err != nil {
		t.Fatalf("after scan failed: %v: %s", err, output)
	}
	output, err = exec.Command(executable, "diff", before, after, "--format", "json").CombinedOutput()
	if err != nil {
		t.Fatalf("JSON diff failed: %v: %s", err, output)
	}
	var difference report.Diff
	if err := json.Unmarshal(output, &difference); err != nil {
		t.Fatal(err)
	}
	if len(difference.AddedComponents) != 1 || difference.AddedComponents[0].Name != "psr/log" || difference.AddedComponents[0].Version != "3.1.0" || len(difference.RemovedComponents) != 1 || difference.RemovedComponents[0].Version != "3.0.0" || len(difference.AddedEdges) != 1 || len(difference.RemovedEdges) != 1 {
		t.Fatalf("version upgrade was not reflected in graph diff: %#v", difference)
	}
	output, err = exec.Command(executable, "diff", before, after).CombinedOutput()
	if err != nil {
		t.Fatalf("text diff failed: %v: %s", err, output)
	}
	if !strings.Contains(string(output), "- package psr/log@3.0.0") || !strings.Contains(string(output), "+ package psr/log@3.1.0") || strings.Contains(string(output), "secret") {
		t.Fatalf("unexpected text diff: %s", output)
	}
}

func TestGoVendorGeneratedByGoTool(t *testing.T) {
	project := t.TempDir()
	dependency := filepath.Join(project, "dep")
	if err := os.MkdirAll(dependency, 0o700); err != nil {
		t.Fatal(err)
	}
	for path, content := range map[string]string{
		filepath.Join(project, "go.mod"):    "module example.com/app\n\ngo 1.23\n\nrequire example.com/dep v0.0.0\n\nreplace example.com/dep => ./dep\n",
		filepath.Join(project, "main.go"):   "package main\nimport _ \"example.com/dep\"\nfunc main() {}\n",
		filepath.Join(dependency, "go.mod"): "module example.com/dep\n\ngo 1.23\n",
		filepath.Join(dependency, "dep.go"): "package dep\n",
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manifestBefore, err := os.ReadFile(filepath.Join(project, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(executable, "scan", project, "--manager", "go", "--output", filepath.Join(t.TempDir(), "static.json")).CombinedOutput(); err == nil || !strings.Contains(string(output), "--resolve") {
		t.Fatalf("Go scan without vendor did not require resolver opt-in: %v: %s", err, output)
	}
	if output, err := exec.Command(executable, "scan", project, "--manager", "go", "--resolve", "--output", filepath.Join(t.TempDir(), "denied.json")).CombinedOutput(); err == nil || !strings.Contains(string(output), "--allow-exec") {
		t.Fatalf("Go resolver ran without execution opt-in: %v: %s", err, output)
	}
	resolvedPath := filepath.Join(t.TempDir(), "resolved.json")
	if output, err := exec.Command(executable, "scan", project, "--manager", "go", "--resolve", "--allow-exec", "--format", "ravel-json", "--output", resolvedPath).CombinedOutput(); err != nil {
		t.Fatalf("offline Go resolver failed: %v: %s", err, output)
	}
	resolvedData, err := os.ReadFile(resolvedPath)
	if err != nil {
		t.Fatal(err)
	}
	var resolved model.Document
	if err := json.Unmarshal(resolvedData, &resolved); err != nil {
		t.Fatal(err)
	}
	if len(resolved.Components) != 1 || resolved.Components[0].Name != "example.com/dep" || len(resolved.Edges) != 1 || len(resolved.Origins) != 1 || resolved.Origins[0].Kind != "local" || resolved.Components[0].Evidence[0].Method != "resolver-output" {
		t.Fatalf("offline Go resolver produced wrong graph: %#v", resolved)
	}
	manifestAfter, err := os.ReadFile(filepath.Join(project, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if string(manifestAfter) != string(manifestBefore) {
		t.Fatal("Go resolver changed go.mod")
	}
	cmd := exec.Command("go", "mod", "vendor")
	cmd.Dir = project
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go mod vendor failed: %v: %s", err, output)
	}
	vendorManifest := filepath.Join(project, "vendor", "modules.txt")
	vendorBefore, err := os.ReadFile(vendorManifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := exec.Command(executable, "scan", project, "--manager", "go", "--resolve", "--allow-exec", "--output", vendorManifest).Run(); err == nil {
		t.Fatal("Go resolver overwrote vendor/modules.txt")
	}
	vendorAfter, err := os.ReadFile(vendorManifest)
	if err != nil {
		t.Fatal(err)
	}
	if string(vendorAfter) != string(vendorBefore) {
		t.Fatal("vendor/modules.txt changed after rejected output path")
	}
	if err := exec.Command(executable, "scan", project, "--manager", "go", "--output", filepath.Join(project, "go.mod")).Run(); err == nil {
		t.Fatal("Go vendor scan overwrote go.mod")
	}
	manifestAfter, err = os.ReadFile(filepath.Join(project, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if string(manifestAfter) != string(manifestBefore) {
		t.Fatal("go.mod changed after rejected output path")
	}
	outputPath := filepath.Join(t.TempDir(), "ravel.json")
	if output, err := exec.Command(executable, "scan", project, "--format", "ravel-json", "--output", outputPath).CombinedOutput(); err != nil {
		t.Fatalf("Ravel scan of Go-generated vendor failed: %v: %s", err, output)
	}
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Coverage.Manager != "go" || len(doc.Components) != 1 || doc.Components[0].Name != "example.com/dep" || len(doc.Edges) != 1 || doc.Edges[0].From != "root" || doc.Edges[0].To != doc.Components[0].ID || len(doc.Origins) != 1 || doc.Origins[0].Kind != "local" {
		t.Fatalf("Go-generated vendor was misread: %#v", doc)
	}
}
