package integration_test

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

const ociRubyPlatformPath = "usr/local/lib/ruby/3.3.0/x86_64-linux/rbconfig.rb"

var ociRubyPlatformConfig = []byte("module RbConfig\n  CONFIG[\"ruby_version\"] = \"3.3.0\"\n  CONFIG[\"arch\"] = \"x86_64-linux\"\nend\n")

func TestOCIInstalledRubyPlatformGemDependency(t *testing.T) {
	const home = "usr/local/bundle/specifications/"
	app := ociTestEntry{name: home + "app-1.0.0.gemspec", data: ociTestRubySpecWithDependencies("app", "1.0.0", `  s.add_runtime_dependency(%q<ffi>.freeze, [">= 1.0".freeze])`)}
	runtime := ociTestEntry{name: ociRubyRuntimePath, data: ociTestRubyRuntimeELF("3.3.12")}
	config := ociTestEntry{name: ociRubyPlatformPath, data: ociRubyPlatformConfig}
	gem := func(platform string) ociTestEntry {
		return ociTestEntry{name: home + "ffi-1.17.0-" + platform + ".gemspec", data: ociTestInstalledRubySpec("ffi", "1.17.0", platform)}
	}
	wrongABI := []byte("module RbConfig\n  CONFIG[\"ruby_version\"] = \"3.2.0\"\n  CONFIG[\"arch\"] = \"x86_64-linux\"\nend\n")
	for _, test := range []struct {
		name      string
		entries   []ociTestEntry
		upper     []ociTestEntry
		wantEdge  bool
		wantIssue string
	}{
		{name: "gnu", entries: []ociTestEntry{app, runtime, config, gem("x86_64-linux-gnu")}, wantEdge: true},
		{name: "generic", entries: []ociTestEntry{app, runtime, config, gem("x86_64-linux")}, wantEdge: true},
		{name: "missing_config", entries: []ociTestEntry{app, runtime, gem("x86_64-linux-gnu")}, wantIssue: "ruby_installed_dependency_constraint_unverified"},
		{name: "wrong_abi", entries: []ociTestEntry{app, runtime, {name: ociRubyPlatformPath, data: wrongABI}, gem("x86_64-linux-gnu")}, wantIssue: "ruby_platform_config_invalid"},
		{name: "musl_gem", entries: []ociTestEntry{app, runtime, config, gem("x86_64-linux-musl")}, wantIssue: "ruby_installed_dependency_unresolved"},
		{name: "wrong_cpu_gem", entries: []ociTestEntry{app, runtime, config, gem("aarch64-linux")}, wantIssue: "ruby_installed_dependency_unresolved"},
		{name: "whiteouted_config", entries: []ociTestEntry{app, runtime, config, gem("x86_64-linux-gnu")}, upper: []ociTestEntry{{name: "usr/local/lib/ruby/3.3.0/x86_64-linux/.wh.rbconfig.rb"}}, wantIssue: "ruby_installed_dependency_constraint_unverified"},
		{name: "replaced_config", entries: []ociTestEntry{app, runtime, config, gem("x86_64-linux-gnu")}, upper: []ociTestEntry{{name: ociRubyPlatformPath, data: wrongABI}}, wantIssue: "ruby_platform_config_invalid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			doc := ociTestRubyDependencyScan(t, test.entries, test.upper)
			edges := ociTestRubyDependencyEdges(doc)
			wantCount := 0
			if test.wantEdge {
				wantCount = 1
			}
			if edges["app@1.0.0 -> ffi@1.17.0"] != test.wantEdge || len(edges) != wantCount {
				t.Fatalf("Ruby platform gem relation incorrect: edges=%#v issues=%#v", edges, doc.Coverage.Issues)
			}
			if test.wantEdge {
				found := false
				hash := sha256.Sum256(ociRubyPlatformConfig)
				for _, component := range doc.Components {
					if component.Name == "ffi" && len(component.Evidence) == 2 {
						evidence := component.Evidence[1]
						found = evidence.Collector == "ruby-rbconfig" && evidence.Line == 3 && evidence.InputDigest == "sha256:"+hex.EncodeToString(hash[:]) && strings.HasSuffix(evidence.InputPath, "!/"+ociRubyPlatformPath)
					}
				}
				if !found {
					t.Fatalf("Ruby platform compatibility evidence missing: %#v", doc.Components)
				}
			}
			if test.wantIssue != "" && !ociTestRubyHasIssue(doc, test.wantIssue) {
				t.Fatalf("missing Ruby platform coverage issue: %#v", doc.Coverage.Issues)
			}
		})
	}
}

func TestOCIRubyRuntimeWrongMachineRejected(t *testing.T) {
	wrongMachine := ociTestRubyRuntimeELF("3.3.12")
	binary.LittleEndian.PutUint16(wrongMachine[18:20], 183) // AArch64 in an amd64 image.
	doc := ociTestRubyDependencyScan(t, []ociTestEntry{
		{name: ociRubyRuntimePath, data: wrongMachine},
		{name: ociRubyPlatformPath, data: ociRubyPlatformConfig},
		{name: "usr/local/bundle/specifications/app-1.0.0.gemspec", data: ociTestRubySpecWithDependencies("app", "1.0.0", `  s.add_runtime_dependency(%q<ffi>.freeze, [">= 1.0".freeze])`)},
		{name: "usr/local/bundle/specifications/ffi-1.17.0-x86_64-linux-gnu.gemspec", data: ociTestInstalledRubySpec("ffi", "1.17.0", "x86_64-linux-gnu")},
	}, nil)
	if len(ociTestRubyDependencyEdges(doc)) != 0 || !ociTestRubyHasIssue(doc, "ruby_runtime_invalid") || !ociTestRubyHasIssue(doc, "ruby_installed_dependency_constraint_unverified") {
		t.Fatalf("foreign Ruby runtime trusted for platform matching: %#v", doc)
	}
}

func TestOCIInstalledRubyArm64PlatformGemDependency(t *testing.T) {
	layout := ociTestLayout(t)
	runtime := ociTestRubyRuntimeELF("3.3.12")
	binary.LittleEndian.PutUint16(runtime[18:20], 183) // AArch64.
	image := ociTestImage(t, layout, "linux", "arm64", []ociTestLayer{{entries: []ociTestEntry{
		{name: ociRubyRuntimePath, data: runtime},
		{name: "usr/local/lib/ruby/3.3.0/aarch64-linux/rbconfig.rb", data: []byte("module RbConfig\n  CONFIG[\"ruby_version\"] = \"3.3.0\"\n  CONFIG[\"arch\"] = \"aarch64-linux\"\nend\n")},
		{name: "usr/local/bundle/specifications/app-1.0.0.gemspec", data: ociTestRubySpecWithDependencies("app", "1.0.0", `  s.add_runtime_dependency(%q<ffi>.freeze, [">= 1.0".freeze])`)},
		{name: "usr/local/bundle/specifications/ffi-1.17.0-aarch64-linux.gemspec", data: ociTestInstalledRubySpec("ffi", "1.17.0", "aarch64-linux")},
	}}})
	ociTestIndex(t, layout, image)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || !ociTestRubyDependencyEdges(doc)["app@1.0.0 -> ffi@1.17.0"] {
		t.Fatalf("arm64 Ruby platform gem relation incorrect: code=%d output=%s edges=%#v", code, output, doc.Edges)
	}
}

func TestOCIInstalledRubyMuslPlatformGemDependency(t *testing.T) {
	config := ociTestEntry{name: "usr/local/lib/ruby/3.3.0/x86_64-linux-musl/rbconfig.rb", data: []byte("module RbConfig\n  CONFIG[\"ruby_version\"] = \"3.3.0\"\n  CONFIG[\"arch\"] = \"x86_64-linux-musl\"\nend\n")}
	app := ociTestEntry{name: "usr/local/bundle/specifications/app-1.0.0.gemspec", data: ociTestRubySpecWithDependencies("app", "1.0.0", `  s.add_runtime_dependency(%q<ffi>.freeze, [">= 1.0".freeze])`)}
	runtime := ociTestEntry{name: ociRubyRuntimePath, data: ociTestRubyRuntimeELF("3.3.12")}
	for _, test := range []struct {
		platform string
		wantEdge bool
	}{
		{platform: "x86_64-linux-musl", wantEdge: true},
		{platform: "x86_64-linux"},
		{platform: "x86_64-linux-gnu"},
	} {
		t.Run(test.platform, func(t *testing.T) {
			gem := ociTestEntry{name: "usr/local/bundle/specifications/ffi-1.17.0-" + test.platform + ".gemspec", data: ociTestInstalledRubySpec("ffi", "1.17.0", test.platform)}
			doc := ociTestRubyDependencyScan(t, []ociTestEntry{app, runtime, config, gem}, nil)
			got := ociTestRubyDependencyEdges(doc)["app@1.0.0 -> ffi@1.17.0"]
			if got != test.wantEdge {
				t.Fatalf("musl Ruby platform relation incorrect: want=%v edges=%#v issues=%#v", test.wantEdge, doc.Edges, doc.Coverage.Issues)
			}
		})
	}
}
