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

func scanRebar(t *testing.T, input string, extra ...string) model.Document {
	t.Helper()
	args := append([]string{"scan", input, "--format", "ravel-json"}, extra...)
	out, err := exec.Command(executable, args...).Output()
	if err != nil {
		t.Fatalf("rebar scan %v: %v", args, err)
	}
	var doc model.Document
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestRebarLockCLI(t *testing.T) {
	base := filepath.Join("..", "testdata", "fixtures")
	basic := scanRebar(t, filepath.Join(base, "rebar-basic"))
	if basic.Coverage.Manager != "rebar" || basic.Coverage.Packages != 2 || basic.Coverage.Edges != 0 || basic.Coverage.GraphState != "partial" || basic.Coverage.OriginState != "partial" || !dotnetIssue(basic, "rebar_package_hash_unrepresented") {
		t.Fatalf("rebar basic coverage: %#v", basic.Coverage)
	}
	for _, pkg := range basic.Components {
		switch pkg.Name {
		case "certifi":
			if pkg.Version != "2.9.0" || pkg.PURL != "pkg:hex/certifi@2.9.0" || pkg.Context != "lock-depth=0" || len(pkg.Hashes) != 0 {
				t.Fatalf("rebar Hex package: %#v", pkg)
			}
		case "bson":
			if pkg.Version != "14308ab927cfa69324742c3de720578094e0bb19" || pkg.PURL != "" || pkg.Context != "lock-depth=1; source=git" {
				t.Fatalf("rebar Git package: %#v", pkg)
			}
		default:
			t.Fatalf("unexpected rebar package: %#v", pkg)
		}
	}
	if len(basic.Origins) != 1 || basic.Origins[0].SafeURL != "https://example.com/org/bson-erlang.git" {
		t.Fatalf("rebar Git origin: %#v", basic.Origins)
	}
	encoded, err := json.Marshal(basic)
	if err != nil || strings.Contains(string(encoded), "secret") || strings.Contains(string(encoded), "hidden") {
		t.Fatalf("rebar credential leaked: %v", err)
	}
	alias := scanRebar(t, filepath.Join(base, "rebar-alias", "rebar.lock"))
	aliasFound := false
	for _, pkg := range alias.Components {
		if pkg.Name == "certifi" && strings.Contains(pkg.Context, "lock-alias=my_certifi") {
			aliasFound = true
		}
	}
	if alias.Coverage.Packages != 2 || !aliasFound {
		t.Fatalf("rebar alias: %#v", alias.Components)
	}
	partial := scanRebar(t, filepath.Join(base, "rebar-partial"))
	if partial.Coverage.Packages != 1 || !dotnetIssue(partial, "rebar_lock_source_unhandled") {
		t.Fatalf("rebar partial coverage: %#v", partial.Coverage)
	}
}

func TestRebarDiscoveryAndExports(t *testing.T) {
	fixture := filepath.Join("..", "testdata", "fixtures", "rebar-basic", "rebar.lock")
	root := t.TempDir()
	nested := filepath.Join(root, "erlang")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "rebar.lock"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{nested},
		{nested, "--manager", "rebar"},
		{root, "--all", "--recursive"},
	} {
		doc := scanRebar(t, args[0], args[1:]...)
		if doc.Coverage.Packages != 2 {
			t.Fatalf("rebar discovery %v: %#v", args, doc.Coverage)
		}
	}
	for _, format := range []string{"cyclonedx-json", "spdx-json"} {
		out, err := exec.Command(executable, "scan", fixture, "--format", format).Output()
		if err != nil || !json.Valid(out) || strings.Contains(string(out), "secret") {
			t.Fatalf("rebar %s export: %v", format, err)
		}
	}
}
