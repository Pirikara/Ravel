package yarn

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClassicWorkspaceGlobs(t *testing.T) {
	for _, tc := range []struct {
		pattern, directory string
		want               bool
	}{
		{"packages/*", "packages/app", true}, {"packages/*", "packages/app/nested", false},
		{"packages/**", "packages/app/nested", true}, {"tools/**/app", "tools/app", true},
		{"tools/**/app", "tools/nested/app", true}, {"{packages,apps}/*", "apps/web", true},
		{"packages/[ab]*/client?", "packages/alpha/client1", true},
		{"**/app", ".hidden/app", false}, {".hidden/*", ".hidden/app", true},
		{"**/app", "tools/.hidden/app", false},
	} {
		t.Run(tc.pattern+"/"+tc.directory, func(t *testing.T) {
			patterns, err := classicWorkspacePatterns(tc.pattern)
			if err != nil {
				t.Fatal(err)
			}
			got := false
			for _, p := range patterns {
				got = got || classicWorkspaceMatch(p, strings.Split(tc.directory, "/"), false)
			}
			if got != tc.want {
				t.Fatalf("match=%v want %v", got, tc.want)
			}
		})
	}
	for _, pattern := range []string{"../outside", "/absolute", "packages/../../outside", "packages/@(a|b)", "packages/{1..9}", "packages/[", "", "."} {
		if _, err := classicWorkspacePatterns(pattern); err == nil {
			t.Fatalf("unsupported pattern accepted: %q", pattern)
		}
	}
}

func TestClassicWorkspacePartialInputs(t *testing.T) {
	for _, tc := range []struct {
		name, root, first, second string
		apps, edges               int
		issue                     string
	}{
		{"array", "{\"private\":true,\"workspaces\":[\"packages/*\"],\"dependencies\":{\"core\":\"^1.0.0\"}}", "{\"name\":\"core\",\"version\":\"1.2.0\"}", "", 1, 1, ""},
		{"root-only-membership", "{\"private\":true,\"workspaces\":[\"packages/*\"]}", "{\"name\":\"core\",\"version\":\"1.2.0\"}", "", 1, 0, ""},
		{"missing-version", "{\"private\":true,\"workspaces\":[\"packages/*\"],\"dependencies\":{\"core\":\"^1.0.0\"}}", "{\"name\":\"core\"}", "", 1, 0, "workspace_version_unresolved"},
		{"duplicate-name", "{\"private\":true,\"workspaces\":[\"packages/*\"],\"dependencies\":{\"core\":\"^1.0.0\"}}", "{\"name\":\"core\",\"version\":\"1.2.0\"}", "{\"name\":\"core\",\"version\":\"1.3.0\"}", 2, 0, "ambiguous_dependency"},
		{"invalid-child", "{\"private\":true,\"workspaces\":[\"packages/*\"]}", "{", "", 0, 0, "workspace_unresolved"},
		{"public-root", "{\"workspaces\":[\"packages/*\"]}", "{\"name\":\"core\",\"version\":\"1.2.0\"}", "", 0, 0, "workspace_unresolved"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			write := func(file, data string) {
				t.Helper()
				file = filepath.Join(dir, file)
				if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(file, []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			write("package.json", tc.root)
			write("packages/first/package.json", tc.first)
			if tc.second != "" {
				write("packages/second/package.json", tc.second)
			}
			write("yarn.lock", "# yarn lockfile v1\n")
			doc, err := Collect(filepath.Join(dir, "yarn.lock"), "test")
			if err != nil {
				t.Fatal(err)
			}
			if len(doc.Components) != tc.apps || len(doc.Edges) != tc.edges {
				t.Fatalf("components=%d edges=%d", len(doc.Components), len(doc.Edges))
			}
			found := false
			for _, issue := range doc.Coverage.Issues {
				found = found || issue.Code == tc.issue
				if tc.issue == "" && issue.Code == "missing_direct_dependencies" {
					t.Fatal("valid workspace-only root marked as missing direct dependencies")
				}
			}
			if tc.issue != "" && !found {
				t.Fatalf("missing %s: %+v", tc.issue, doc.Coverage)
			}
		})
	}
}

func TestClassicWorkspaceReadBoundaries(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	write := func(file, data string) {
		t.Helper()
		if err := os.WriteFile(file, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(dir, "yarn.lock"), "# yarn lockfile v1\n")
	write(filepath.Join(dir, "package.json"), `{"private":true,"workspaces":["linked","oversized"]}`)
	write(filepath.Join(outside, "package.json"), `{"name":"outside","version":"1.0.0"}`)
	if err := os.Symlink(outside, filepath.Join(dir, "linked")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "oversized"), 0700); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(dir, "oversized", "package.json"), strings.Repeat(" ", 1<<20+1))
	doc, err := Collect(filepath.Join(dir, "yarn.lock"), "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Components) != 0 {
		t.Fatal("out-of-root or oversized manifest collected")
	}
	found := false
	for _, issue := range doc.Coverage.Issues {
		found = found || issue.Code == "workspace_unresolved"
	}
	if !found {
		t.Fatal("incomplete discovery was not reported")
	}
}
