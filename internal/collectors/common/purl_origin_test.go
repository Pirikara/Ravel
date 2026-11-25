package common

import (
	"testing"

	"github.com/Pirikara/Ravel/internal/model"
)

func TestSourceQualifiedPURLs(t *testing.T) {
	for _, tc := range []struct{ name, manager, packageName, version, platform, initial, kind, source, vcs, revision, want string }{
		{"private-pypi", "uv", "Acme.Pkg", "1.2+cpu", "", "", "declared_registry", "https://pypi.example.test/simple", "", "", "pkg:pypi/acme-pkg@1.2%2Bcpu?repository_url=https:%2F%2Fpypi.example.test%2Fsimple"},
		{"private-npm-archive", "npm", "@acme/demo", "1.0.0", "", "", "download_url", "https://registry.example.test/npm/@acme/demo/-/demo-1.0.0.tgz", "", "", "pkg:npm/%40acme/demo@1.0.0?download_url=https:%2F%2Fregistry.example.test%2Fnpm%2F%40acme%2Fdemo%2F-%2Fdemo-1.0.0.tgz"},
		{"private-gem-platform", "bundler", "native", "1.2.3", "aarch64-linux", "", "declared_registry", "https://gems.example.test/ruby", "", "", "pkg:gem/native@1.2.3?platform=aarch64-linux&repository_url=https:%2F%2Fgems.example.test%2Fruby"},
		{"private-nuget", "nuget", "Acme.Core", "1.2.3", "", "pkg:nuget/Acme.Core@1.2.3", "declared_registry", "https://nuget.example.test/v3/index.json", "", "", "pkg:nuget/Acme.Core@1.2.3?repository_url=https:%2F%2Fnuget.example.test%2Fv3%2Findex.json"},
		{"private-composer", "composer", "Acme/Demo", "1.2.3", "", "", "download_url", "https://repo.example.test/demo.zip", "", "", "pkg:composer/acme/demo@1.2.3?download_url=https:%2F%2Frepo.example.test%2Fdemo.zip"},
		{"private-maven-classifier", "gradle", "org.example:demo", "1.2.3", "", "pkg:maven/org.example/demo@1.2.3?classifier=sources", "declared_registry", "https://maven.example.test/releases", "", "", "pkg:maven/org.example/demo@1.2.3?classifier=sources&repository_url=https:%2F%2Fmaven.example.test%2Freleases"},
		{"cargo-git", "cargo", "demo", "1.2.3", "", "", "vcs", "https://git.example.test/org/demo.git", "git", "abcdef1234567", "pkg:cargo/demo@1.2.3?vcs_url=git%2Bhttps:%2F%2Fgit.example.test%2Forg%2Fdemo.git%40abcdef1234567"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := NewDocument("lock", "test", tc.manager, nil)
			doc.Components = []model.Component{{ID: "p", Kind: "package", Name: tc.packageName, Version: tc.version, Platform: tc.platform, PURL: tc.initial, Hashes: []model.Hash{{Alg: "SHA-256", Content: "observed"}}}}
			doc.Origins = []model.Origin{{Occurrence: "p", Kind: tc.kind, SafeURL: tc.source, VCSType: tc.vcs, Revision: tc.revision, Status: "declared"}}
			Finalize(&doc)
			if c := doc.Components[0]; c.PURL != tc.want || c.PURLBasis != "source_qualified" || c.Name != tc.packageName || c.Version != tc.version || len(c.Hashes) != 1 || c.Hashes[0].Content != "observed" {
				t.Fatalf("qualified identity: %#v", c)
			}
			Finalize(&doc)
			if doc.Components[0].PURL != tc.want {
				t.Fatalf("normalization is not idempotent: %s", doc.Components[0].PURL)
			}
		})
	}
}

func TestDefaultUnknownAndAmbiguousPURLSources(t *testing.T) {
	for _, tc := range []struct {
		name    string
		origins []model.Origin
		want    string
	}{
		{"unknown", nil, "pkg:pypi/demo@1.0"},
		{"public", []model.Origin{{Kind: "declared_registry", SafeURL: "https://pypi.org/simple"}}, "pkg:pypi/demo@1.0"},
		{"ambiguous", []model.Origin{{Kind: "declared_registry", SafeURL: "https://one.example.test/simple"}, {Kind: "declared_registry", SafeURL: "https://two.example.test/simple"}}, "pkg:generic/pypi/demo@1.0"},
		{"local", []model.Origin{{Kind: "local"}}, "pkg:generic/pypi/demo@1.0"},
		{"unsupported-vcs", []model.Origin{{Kind: "vcs", VCSType: "unknown", SafeURL: "https://code.example.test/demo"}}, "pkg:generic/pypi/demo@1.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := NewDocument("metadata", "test", "python-installed", nil)
			doc.Components = []model.Component{{ID: "p", Kind: "package", Name: "demo", Version: "1.0", PURL: "pkg:pypi/demo@1.0", PURLBasis: "ecosystem_inferred"}}
			doc.Origins = tc.origins
			for i := range doc.Origins {
				doc.Origins[i].Occurrence = "p"
			}
			Finalize(&doc)
			Finalize(&doc)
			if doc.Components[0].PURL != tc.want {
				t.Fatalf("source distinction: %#v", doc.Components[0])
			}
		})
	}
}

func TestVCSLocationPreservesToolCommitAndSubdirectory(t *testing.T) {
	o := model.Origin{Kind: "vcs", VCSType: "hg", SafeURL: "https://user:secret@hg.example.test/project?token=hidden", Revision: "abcdef1234567", Target: "subdirectory=packages/demo"}
	if got := VCSLocation(o); got != "hg+https://hg.example.test/project@abcdef1234567#packages/demo" {
		t.Fatal(got)
	}
	o.Revision = "bad?token=secret"
	if VCSLocation(o) != "" {
		t.Fatal("unsafe revision became URL syntax")
	}
}

func TestAmbiguousSourceRetainsVariant(t *testing.T) {
	doc := NewDocument("lock", "test", "bundler", nil)
	doc.Components = []model.Component{{ID: "p", Kind: "package", Name: "native", Version: "1.0", PURL: "pkg:gem/native@1.0?platform=aarch64-linux&repository_url=https:%2F%2Fold.example.test"}}
	doc.Origins = []model.Origin{{Occurrence: "p", Kind: "declared_registry", SafeURL: "https://one.example.test"}, {Occurrence: "p", Kind: "declared_registry", SafeURL: "https://two.example.test"}}
	Finalize(&doc)
	Finalize(&doc)
	if c := doc.Components[0]; c.PURL != "pkg:generic/gem/native@1.0?platform=aarch64-linux" || c.PURLBasis != "source_ambiguous" || len(doc.Coverage.Issues) != 1 || doc.Coverage.OriginState != "partial" {
		t.Fatalf("variant or ambiguity lost: %#v", doc)
	}
}
