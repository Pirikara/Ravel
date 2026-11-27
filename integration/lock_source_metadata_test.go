package integration_test

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Pirikara/Ravel/internal/model"
)

func TestHexArchiveHashesAcrossFormats(t *testing.T) {
	for _, tc := range []struct{ fixture, file, name string }{
		{"mix-archive-hashes", "mix.lock", "modern_alias"},
		{"rebar-archive-hashes", "rebar.lock", "real_package"},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			input := filepath.Join("..", "testdata", "fixtures", tc.fixture, tc.file)
			doc := scanDevelopmentSample(t, input)
			if len(doc.Components) != 5 {
				t.Fatal("package inventory changed", doc.Components)
			}
			for _, c := range doc.Components {
				if c.Name == tc.name {
					if len(c.Hashes) != 1 || c.Hashes[0] != (model.Hash{Alg: "SHA-256", Content: strings.Repeat("b", 64)}) {
						t.Fatal("outer archive hash not preserved by lock alias", c)
					}
				} else if len(c.Hashes) != 0 {
					t.Fatal("inner, invalid, conflicting or Git checksum became an archive hash", c)
				}
			}
			for _, format := range []string{"cyclonedx-json", "spdx-json"} {
				out, err := exec.Command(executable, "scan", input, "--format", format).Output()
				if err != nil {
					t.Fatal(err)
				}
				var projected struct {
					Components []struct {
						Name   string
						Hashes []struct{ Alg, Content string }
					}
					Packages []struct {
						Name      string
						Checksums []struct{ Algorithm, ChecksumValue string }
					}
				}
				if err := json.Unmarshal(out, &projected); err != nil {
					t.Fatal(err)
				}
				found := 0
				for _, c := range projected.Components {
					for _, h := range c.Hashes {
						if c.Name != tc.name || h.Alg != "SHA-256" || h.Content != strings.Repeat("b", 64) {
							t.Fatal("CycloneDX archive hash changed", c)
						}
						found++
					}
				}
				for _, c := range projected.Packages {
					for _, h := range c.Checksums {
						if c.Name != tc.name || h.Algorithm != "SHA256" || h.ChecksumValue != strings.Repeat("b", 64) {
							t.Fatal("SPDX archive hash changed", c)
						}
						found++
					}
				}
				if found != 1 {
					t.Fatal("archive checksum missing or duplicated", format, found)
				}
			}
		})
	}
}

func TestRecordedVCSTypesAcrossCollectors(t *testing.T) {
	for _, tc := range []struct{ fixture, file, name, vcs, location string }{
		{"mix-archive-hashes", "mix.lock", "git_source", "git", "git+https://code.example.test/team/library.git@" + strings.Repeat("f", 40)},
		{"rebar-archive-hashes", "rebar.lock", "git_source", "git", "git+https://code.example.test/team/library.git@" + strings.Repeat("f", 40)},
		{"stack-basic", "stack.yaml.lock", "internal-lib", "git", "git+https://example.invalid/repo.git@abcdef0123456789abcdef0123456789abcdef01#packages/internal-lib"},
		{"shards-vcs-types", "shard.lock", "git_package", "git", "git+https://code.example.test/team/library.git@" + strings.Repeat("a", 40)},
		{"shards-vcs-types", "shard.lock", "hg_package", "hg", "hg+https://code.example.test/team/mercurial@" + strings.Repeat("b", 40)},
		{"shards-vcs-types", "shard.lock", "fossil_package", "fossil", "NOASSERTION"},
		{"julia-v2", "Manifest.toml", "Shared", "git", "git+https://example.com/org/shared.git@abc123"},
		{"renv-basic", "renv.lock", "mime", "git", "git+https://example.com/org/mime.git@aabbccddee11223344556677889900aabbccddee"},
		{"pixi-v7", "pixi.lock", "mike", "git", "git+https://github.com/example/mike@2d4ad799442f4592db8ad53b179bfb33db8c69ac"},
	} {
		t.Run(tc.fixture+"/"+tc.name, func(t *testing.T) {
			input := filepath.Join("..", "testdata", "fixtures", tc.fixture, tc.file)
			doc := scanDevelopmentSample(t, input)
			ids := map[string]bool{}
			for _, c := range doc.Components {
				if c.Name == tc.name && (tc.fixture != "julia-v2" || c.Version == "2.0.0") {
					ids[c.ID] = true
				}
			}
			if len(ids) == 0 {
				t.Fatal("expected test package not found", tc.name, doc.Components)
			}
			seen := 0
			for _, o := range doc.Origins {
				if ids[o.Occurrence] {
					seen++
					if o.Kind != "vcs" || o.VCSType != tc.vcs {
						t.Fatal("VCS identity lost", o)
					}
				}
			}
			if seen != len(ids) {
				t.Fatal("VCS source missing", seen, len(ids))
			}
			if tc.location == "" {
				return
			}
			for _, format := range []string{"cyclonedx-json", "spdx-json"} {
				out, err := exec.Command(executable, "scan", input, "--format", format).Output()
				if err != nil {
					t.Fatal(err)
				}
				var projected struct {
					Components []struct {
						Name       string
						References []struct{ Type, URL string } `json:"externalReferences"`
					}
					Packages []struct {
						Name     string
						Location string `json:"downloadLocation"`
					}
				}
				if err := json.Unmarshal(out, &projected); err != nil {
					t.Fatal(err)
				}
				found := 0
				if format == "cyclonedx-json" {
					if tc.location == "NOASSERTION" {
						continue
					}
					for _, c := range projected.Components {
						if c.Name == tc.name {
							for _, r := range c.References {
								if r.Type == "vcs" && r.URL == tc.location {
									found++
								}
							}
						}
					}
				} else {
					for _, c := range projected.Packages {
						if c.Name == tc.name && c.Location == tc.location {
							found++
						}
					}
				}
				if found != len(ids) {
					t.Fatal("standard VCS source lost", format, tc.location, found, len(ids))
				}
			}
		})
	}
}

func TestEmptyLockInputs(t *testing.T) {
	for _, tc := range []struct{ fixture, file, issue string }{
		{"rebar-empty", "rebar.lock", "rebar_dependency_graph_unavailable"},
		{"cabal-index-only", "cabal.project.freeze", "cabal_freeze_version_pins_unavailable"},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			input := filepath.Join("..", "testdata", "fixtures", tc.fixture)
			for _, path := range []string{input, filepath.Join(input, tc.file)} {
				doc := scanDevelopmentSample(t, path)
				if len(doc.Components) != 0 || len(doc.Edges) != 0 || !dotnetIssue(doc, tc.issue) {
					t.Fatal("empty lock scope lost", doc)
				}
			}
			for _, format := range []string{"cyclonedx-json", "spdx-json"} {
				out, err := exec.Command(executable, "scan", input, "--format", format).Output()
				if err != nil || !json.Valid(out) {
					t.Fatal("empty standard export failed", format, err)
				}
			}
		})
	}
}
