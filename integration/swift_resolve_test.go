package integration_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"ravel/internal/model"
)

func TestSwiftResolverWithRealSwift(t *testing.T) {
	if _, err := exec.LookPath("swift"); err != nil {
		t.Skip("SwiftPM is not installed")
	}
	root := t.TempDir()
	for _, pkg := range []struct {
		name, dependency string
	}{
		{"Beta", ""}, {"Alpha", "Beta"}, {"App", "Alpha"},
	} {
		dir := filepath.Join(root, pkg.name)
		sourceDir := filepath.Join(dir, "Sources", pkg.name)
		if err := os.MkdirAll(sourceDir, 0o755); err != nil {
			t.Fatal(err)
		}
		manifest := "// swift-tools-version: 6.0\nimport PackageDescription\nlet package = Package(name: \"" + pkg.name + "\", "
		if pkg.name != "App" {
			manifest += "products: [.library(name: \"" + pkg.name + "\", targets: [\"" + pkg.name + "\"])], "
		}
		if pkg.dependency != "" {
			manifest += "dependencies: [.package(path: \"../" + pkg.dependency + "\")], "
		}
		manifest += "targets: [.target(name: \"" + pkg.name + "\""
		if pkg.dependency != "" {
			manifest += ", dependencies: [\"" + pkg.dependency + "\"]"
		}
		manifest += ")])\n"
		if err := os.WriteFile(filepath.Join(dir, "Package.swift"), []byte(manifest), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sourceDir, pkg.name+".swift"), []byte("public struct "+pkg.name+" {}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	app := filepath.Join(root, "App")
	for _, args := range [][]string{{"scan", app}, {"scan", app, "--resolve"}} {
		if output, err := exec.Command(executable, args...).CombinedOutput(); err == nil || !strings.Contains(string(output), "--allow-exec") {
			t.Fatalf("SwiftPM execution gate failed: %v %s", err, output)
		}
	}
	cmd := exec.Command(executable, "scan", app, "--resolve", "--allow-exec", "--network", "deny", "--format", "ravel-json")
	data, err := cmd.Output()
	if err != nil {
		t.Fatalf("real SwiftPM resolver failed: %v", err)
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Coverage.Manager != "swiftpm" || doc.Coverage.Packages != 2 || doc.Coverage.Edges != 2 || doc.Coverage.GraphState != "complete_for_scope" || len(doc.Origins) != 2 {
		t.Fatalf("SwiftPM package graph missing: %#v", doc.Coverage)
	}
	ids := map[string]string{}
	for _, c := range doc.Components {
		ids[c.Name] = c.ID
		if c.PURL != "" || c.Kind != "application" {
			t.Fatalf("local Swift package assigned remote identity: %#v", c)
		}
	}
	edges := map[string]bool{}
	for _, edge := range doc.Edges {
		edges[edge.From+"->"+edge.To] = true
	}
	if !edges["root->"+ids["Alpha"]] || !edges[ids["Alpha"]+"->"+ids["Beta"]] {
		t.Fatalf("SwiftPM dependency edges missing: %#v", doc.Edges)
	}
	if _, err := os.Stat(filepath.Join(app, "Package.resolved")); !os.IsNotExist(err) {
		t.Fatal("SwiftPM resolver modified or created Package.resolved")
	}
	resolvedPath := filepath.Join(app, "Package.resolved")
	resolvedData := []byte("{\"pins\":[],\"version\":3}\n")
	if err := os.WriteFile(resolvedPath, resolvedData, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command(executable, "scan", app, "--resolve", "--allow-exec", "--network", "deny", "--format", "ravel-json")
	if output, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(output), "\"name\": \"Alpha\"") {
		t.Fatalf("SwiftPM resolver did not prefer Package.swift over Package.resolved: %v %s", err, output)
	}
	unchanged, err := os.ReadFile(resolvedPath)
	if err != nil || string(unchanged) != string(resolvedData) {
		t.Fatal("SwiftPM resolver changed Package.resolved")
	}
	cmd = exec.Command(executable, "scan", app, "--resolve", "--allow-exec", "--output", resolvedPath)
	if output, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(output), "cannot overwrite the lockfile") {
		t.Fatalf("SwiftPM resolver could overwrite Package.resolved: %v %s", err, output)
	}
}

func TestSwiftResolverDoesNotEchoToolOutput(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Package.swift"), []byte("// swift-tools-version: 6.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fakeDir := t.TempDir()
	secret := "swift-private-token-should-not-leak"
	script := "#!/bin/sh\necho '" + secret + "' >&2\nexit 1\n"
	if err := os.WriteFile(filepath.Join(fakeDir, "swift"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "scan", dir, "--resolve", "--allow-exec", "--network", "deny")
	cmd.Env = append(os.Environ(), "PATH="+fakeDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	output, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "SwiftPM show-dependencies failed") || strings.Contains(string(output), secret) {
		t.Fatalf("SwiftPM tool output leaked or failure was hidden: %v %s", err, output)
	}
}
