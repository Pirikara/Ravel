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

func TestRemoteImportsIncludeTypeOnlyAndReExports(t *testing.T) {
	specs, err := remoteImports("https://cdn.example.org/mod.ts", []byte(`import type { Shape } from "./shape.ts"; export * from "./value.ts";`))
	if err != nil || len(specs) != 2 || specs[0] != "./shape.ts" || specs[1] != "./value.ts" {
		t.Fatalf("remote imports = %#v, %v", specs, err)
	}
}

func TestTypeOnlyImportsIgnoreCommentsAndExamples(t *testing.T) {
	data := []byte("// import type { Fake } from './comment.ts';\n" +
		"/* export type { Fake } from './block.ts'; */\n" +
		"const example = \"import type { Fake } from './string.ts'\";\n" +
		"const pattern = /import type { Fake } from 'regex.ts'/;\n" +
		"import type { Real } from './real.ts';\n" +
		"export { type Other } from './other.ts';\n")
	specs := typeOnlyImportSpecifiers(data)
	if len(specs) != 2 || specs[0] != "./real.ts" || specs[1] != "./other.ts" {
		t.Fatalf("type imports = %#v", specs)
	}
}

func TestLocalTypeOnlyImportIsRemoteRoot(t *testing.T) {
	const raw = "https://cdn.example.org/types.ts"
	file := writeRemoteFixture(t, map[string]string{raw: `export type Shape = { x: number };`}, `import type { Shape } from "`+raw+`";`, "")
	doc, err := Collect(file, "fixture")
	if err != nil || len(doc.Components) != 1 || len(doc.Edges) != 1 {
		t.Fatalf("type-only remote root missed: %v %#v", err, doc)
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
