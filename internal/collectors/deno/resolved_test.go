package deno

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Pirikara/Ravel/internal/model"
)

func TestRemoteResolutionFollowsVerifiedImportsAndLeavesStaleRecords(t *testing.T) {
	const base = "https://cdn.example.org/"
	sources := map[string]string{
		base + "a.ts":     `export * from "./b.ts"; import "alias";`,
		base + "b.ts":     `import "./c.ts";`,
		base + "c.ts":     `export const answer = 42;`,
		base + "stale.ts": `export const old = true;`,
	}
	file := writeRemoteFixture(t, sources, `import "`+base+`a.ts";`, `{"imports":{"alias":"`+base+`c.ts"}}`)
	called := map[string]int{}
	doc, err := collectResolved(file, "fixture", func(_ context.Context, raw string) ([]byte, string, error) {
		called[raw]++
		return []byte(sources[raw]), raw, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Components) != 3 || len(doc.Edges) != 5 {
		t.Fatalf("unexpected graph: %d components, %d edges", len(doc.Components), len(doc.Edges))
	}
	if called[base+"stale.ts"] != 0 || called[base+"a.ts"] != 1 || called[base+"b.ts"] != 1 || called[base+"c.ts"] != 1 {
		t.Fatalf("unexpected fetches: %#v", called)
	}
	if !hasIssue(doc, "lock_remote_reachability_unknown", base+"stale.ts") || hasIssue(doc, "lock_remote_reachability_unknown", base+"b.ts") {
		t.Fatalf("reachability issues: %#v", doc.Coverage.Issues)
	}
	for _, edge := range doc.Edges {
		if edge.From != "root" && edge.Evidence.Method != "verified-remote-import" {
			t.Fatalf("remote edge without verified source evidence: %#v", edge)
		}
	}
}

func TestRemoteResolutionRejectsChangedOrUnavailableSource(t *testing.T) {
	const base = "https://cdn.example.org/"
	sources := map[string]string{
		base + "a.ts": `import "./b.ts";`,
		base + "b.ts": `export const b = 1;`,
	}
	file := writeRemoteFixture(t, sources, `import "`+base+`a.ts";`, "")
	for _, tc := range []struct {
		name, issue string
		fetch       remoteFetcher
	}{
		{"mismatch", "remote_source_integrity_mismatch", func(_ context.Context, raw string) ([]byte, string, error) {
			return []byte(`import "./b.ts"; // changed`), raw, nil
		}},
		{"unavailable", "remote_source_unavailable", func(_ context.Context, raw string) ([]byte, string, error) { return nil, "", errors.New("unavailable") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := collectResolved(file, "fixture", tc.fetch)
			if err != nil {
				t.Fatal(err)
			}
			if len(doc.Components) != 1 || len(doc.Edges) != 1 || !hasIssue(doc, tc.issue, base+"a.ts") || !hasIssue(doc, "lock_remote_reachability_unknown", base+"b.ts") {
				t.Fatalf("unexpected graph or issues: %#v", doc)
			}
		})
	}
}

func TestRemoteImportMapRelativeValueDoesNotResolveAgainstRemoteURL(t *testing.T) {
	const base = "https://cdn.example.org/"
	sources := map[string]string{
		base + "a.ts":     `import "alias";`,
		base + "local.ts": `export const wrong = true;`,
	}
	file := writeRemoteFixture(t, sources, `import "`+base+`a.ts";`, `{"imports":{"alias":"./local.ts"}}`)
	doc, err := collectResolved(file, "fixture", func(_ context.Context, raw string) ([]byte, string, error) {
		return []byte(sources[raw]), raw, nil
	})
	if err != nil || len(doc.Components) != 1 || !hasIssue(doc, "remote_import_unresolved", base+"a.ts") || !hasIssue(doc, "lock_remote_reachability_unknown", base+"local.ts") {
		t.Fatalf("relative import-map value was resolved against the remote URL: %v %#v", err, doc)
	}
}

func TestRemoteResolutionRejectsUnpinnedImportAndPrivateFetch(t *testing.T) {
	const base = "https://cdn.example.org/"
	sources := map[string]string{base + "a.ts": `import "./not-locked.ts";`}
	file := writeRemoteFixture(t, sources, `import "`+base+`a.ts";`, "")
	doc, err := collectResolved(file, "fixture", func(_ context.Context, raw string) ([]byte, string, error) { return []byte(sources[raw]), raw, nil })
	if err != nil || len(doc.Components) != 1 || !hasIssue(doc, "remote_import_absent_from_lock", base+"not-locked.ts") {
		t.Fatalf("unpinned remote import was accepted: %v %#v", err, doc)
	}
	for _, address := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "100.100.100.100", "192.0.2.1", "::1", "fc00::1"} {
		if publicIPMust(address) {
			t.Fatalf("non-public address accepted: %s", address)
		}
	}
	if _, _, err := fetchRemote(context.Background(), "https://127.0.0.1/a.ts"); err == nil {
		t.Fatal("private fetch accepted")
	}
	if _, _, err := fetchRemote(context.Background(), "https://user:secret@cdn.example.org/a.ts"); err == nil {
		t.Fatal("credential-bearing URL accepted")
	}
}

func TestRemoteImportsExcludeTypeOnlyAndIncludeReExports(t *testing.T) {
	specs, err := remoteImports("https://cdn.example.org/mod.ts", []byte(`import type { Shape } from "./shape.ts"; export * from "./value.ts";`))
	if err != nil || len(specs) != 1 || specs[0] != "./value.ts" {
		t.Fatalf("remote imports = %#v, %v", specs, err)
	}
}

func TestRemoteJSONModuleHasNoImportEdges(t *testing.T) {
	specs, err := remoteImports("https://cdn.example.org/config.json", []byte(`{"import":"./not-a-module.ts"}`))
	if err != nil || len(specs) != 0 {
		t.Fatalf("remote JSON imports = %#v, %v", specs, err)
	}
}

func TestRemoteSourceImportsLockedJSRAndNPMClosure(t *testing.T) {
	const raw = "https://cdn.example.org/mod.ts"
	source := `import "jsr:@example/lib@1.2.3"; import "npm:chalk@5.3.0";`
	file := writeRemoteFixture(t, map[string]string{raw: source}, `import "`+raw+`";`, "")
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var lock map[string]any
	if err := json.Unmarshal(data, &lock); err != nil {
		t.Fatal(err)
	}
	lock["specifiers"] = map[string]string{"jsr:@example/core@^1.0.0": "1.0.0"}
	lock["jsr"] = map[string]any{
		"@example/lib@1.2.3":  map[string]any{"integrity": strings.Repeat("a", 64), "dependencies": []string{"jsr:@example/core@^1.0.0"}},
		"@example/core@1.0.0": map[string]any{"integrity": strings.Repeat("b", 64)},
	}
	lock["npm"] = map[string]any{"chalk@5.3.0": map[string]any{"integrity": "sha512-" + strings.Repeat("A", 88)}}
	data, err = json.Marshal(lock)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	doc, err := collectResolved(file, "fixture", func(_ context.Context, spec string) ([]byte, string, error) {
		return []byte(source), spec, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Components) != 4 || len(doc.Edges) != 4 || hasIssue(doc, "remote_import_unresolved", raw) {
		t.Fatalf("remote package closure missing: %d components, %d edges, issues=%#v", len(doc.Components), len(doc.Edges), doc.Coverage.Issues)
	}
	for _, want := range []string{"@example/lib", "@example/core", "chalk"} {
		found := false
		for _, component := range doc.Components {
			found = found || component.Name == want
		}
		if !found {
			t.Fatalf("missing %s", want)
		}
	}
	refs := map[string]string{}
	for _, component := range doc.Components {
		refs[component.Name] = component.ID
	}
	wantEdges := map[string]string{
		"root\x00" + refs[raw]:                                "",
		refs[raw] + "\x00" + refs["@example/lib"]:             "verified-remote-import",
		refs[raw] + "\x00" + refs["chalk"]:                    "verified-remote-import",
		refs["@example/lib"] + "\x00" + refs["@example/core"]: "lockfile-analysis",
	}
	for _, edge := range doc.Edges {
		key := edge.From + "\x00" + edge.To
		method, ok := wantEdges[key]
		if !ok || method != "" && edge.Evidence.Method != method {
			t.Fatalf("unexpected edge: %#v", edge)
		}
		delete(wantEdges, key)
	}
	if len(wantEdges) != 0 {
		t.Fatalf("missing edges: %#v", wantEdges)
	}
}

func TestRemoteSourceCannotAddPackageAfterIntegrityMismatch(t *testing.T) {
	const raw = "https://cdn.example.org/mod.ts"
	file := writeRemoteFixture(t, map[string]string{raw: `import "npm:chalk@5.3.0";`}, `import "`+raw+`";`, "")
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var lock map[string]any
	if err := json.Unmarshal(data, &lock); err != nil {
		t.Fatal(err)
	}
	lock["npm"] = map[string]any{"chalk@5.3.0": map[string]any{"integrity": "sha512-" + strings.Repeat("A", 88)}}
	data, err = json.Marshal(lock)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	doc, err := collectResolved(file, "fixture", func(_ context.Context, spec string) ([]byte, string, error) {
		return []byte(`import "npm:chalk@5.3.0"; // changed`), spec, nil
	})
	if err != nil || len(doc.Components) != 1 || len(doc.Edges) != 1 || !hasIssue(doc, "remote_source_integrity_mismatch", raw) {
		t.Fatalf("unverified source added package: %v %#v", err, doc)
	}
}

func TestRemoteSourceResolvesVersionTwoPackagePin(t *testing.T) {
	const raw = "https://cdn.example.org/mod.ts"
	const source = `import "npm:@example/lib@^1.0.0";`
	file := writeRemoteFixture(t, map[string]string{raw: source}, `import "`+raw+`";`, "")
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var lock map[string]any
	if err := json.Unmarshal(data, &lock); err != nil {
		t.Fatal(err)
	}
	lock["version"] = "2"
	lock["npm"] = map[string]any{
		"specifiers": map[string]string{"@example/lib@^1.0.0": "@example/lib@1.2.3"},
		"packages":   map[string]any{"@example/lib@1.2.3": map[string]any{"dependencies": map[string]string{}}},
	}
	data, err = json.Marshal(lock)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	doc, err := collectResolved(file, "fixture", func(_ context.Context, spec string) ([]byte, string, error) {
		return []byte(source), spec, nil
	})
	if err != nil || len(doc.Components) != 2 || len(doc.Edges) != 2 || hasIssue(doc, "remote_import_unresolved", raw) {
		t.Fatalf("v2 pin not resolved: %v %#v", err, doc)
	}
}

func TestRemoteSourceResolvesVersionThreePackagePin(t *testing.T) {
	const raw = "https://cdn.example.org/mod.ts"
	const source = `import "jsr:@example/lib@^1.0.0";`
	file := writeRemoteFixture(t, map[string]string{raw: source}, `import "`+raw+`";`, "")
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var lock map[string]any
	if err := json.Unmarshal(data, &lock); err != nil {
		t.Fatal(err)
	}
	lock["version"] = "3"
	lock["packages"] = map[string]any{
		"specifiers": map[string]string{"jsr:@example/lib@^1.0.0": "jsr:@example/lib@1.2.3"},
		"jsr":        map[string]any{"@example/lib@1.2.3": map[string]any{"integrity": strings.Repeat("a", 64), "dependencies": map[string]string{}}},
	}
	data, err = json.Marshal(lock)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	doc, err := collectResolved(file, "fixture", func(_ context.Context, spec string) ([]byte, string, error) {
		return []byte(source), spec, nil
	})
	if err != nil || len(doc.Components) != 2 || len(doc.Edges) != 2 || hasIssue(doc, "remote_import_unresolved", raw) {
		t.Fatalf("v3 pin not resolved: %v %#v", err, doc)
	}
}

func publicIPMust(raw string) bool {
	addr, err := netip.ParseAddr(raw)
	return err == nil && publicIP(addr)
}

func writeRemoteFixture(t *testing.T, sources map[string]string, main, config string) string {
	t.Helper()
	base := t.TempDir()
	if err := os.WriteFile(filepath.Join(base, "main.ts"), []byte(main), 0o600); err != nil {
		t.Fatal(err)
	}
	if config != "" {
		if err := os.WriteFile(filepath.Join(base, "deno.json"), []byte(config), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	remote := map[string]string{}
	for raw, source := range sources {
		sum := sha256.Sum256([]byte(source))
		remote[raw] = hex.EncodeToString(sum[:])
	}
	data, err := json.Marshal(map[string]any{"version": "5", "remote": remote})
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(base, "deno.lock")
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

func hasIssue(doc model.Document, code, name string) bool {
	for _, issue := range doc.Coverage.Issues {
		if issue.Code == code && strings.EqualFold(issue.Name, name) {
			return true
		}
	}
	return false
}
