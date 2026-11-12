package oci

import (
	"fmt"
	"strings"
	"testing"
)

const rTestDescription = "Package: MASS\nVersion: 7.3-65\nDepends: R (>= 4.4.0), stats,\n graphics\nImports: methods\nBuilt: R 4.5.1; aarch64-unknown-linux-gnu; 2025-10-31; unix\n"
const rTestPath = "usr/local/lib/R/library/MASS/DESCRIPTION"

func TestInstalledRDescriptionIdentityAndContinuation(t *testing.T) {
	record, installed, err := inspectInstalledRDescription([]byte(rTestDescription), "oci:sha256:layer!/"+rTestPath, rTestPath, nil)
	if err != nil || !installed {
		t.Fatalf("installed R package rejected: installed=%v err=%v", installed, err)
	}
	if record.component.Name != "MASS" || record.component.Version != "7.3-65" || record.fields["Depends"].value != "R (>= 4.4.0), stats, graphics" || record.component.PURL != "" || !strings.Contains(record.component.Context, "/R/library/MASS") {
		t.Fatalf("R DESCRIPTION identity or provenance incorrect: %#v", record)
	}
}

func TestInstalledRDescriptionRequiresBuiltAndMatchingDirectory(t *testing.T) {
	for _, test := range []struct {
		name      string
		path      string
		data      string
		installed bool
		invalid   bool
	}{
		{name: "translation directory", path: "usr/local/lib/R/library/translations/DESCRIPTION", data: "Package: translations\nVersion: 4.5.1\n"},
		{name: "wrong directory", path: rTestPath, data: strings.Replace(rTestDescription, "Package: MASS", "Package: other", 1), invalid: true},
		{name: "duplicate identity", path: rTestPath, data: rTestDescription + "Package: other\n", invalid: true},
		{name: "bad version", path: rTestPath, data: strings.Replace(rTestDescription, "Version: 7.3-65", "Version: dynamic", 1), invalid: true},
		{name: "site library", path: "opt/conda/lib/R/site-library/MASS/DESCRIPTION", data: rTestDescription, installed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, installed, err := inspectInstalledRDescription([]byte(test.data), "oci:layer!/"+test.path, test.path, nil)
			if installed != test.installed || (err != nil) != test.invalid {
				t.Fatalf("unexpected R DESCRIPTION result: installed=%v err=%v", installed, err)
			}
		})
	}
}

func TestCompareRVersions(t *testing.T) {
	for _, test := range []struct {
		a, b string
		want int
		ok   bool
	}{
		{"7.3-65", "7.3.64", 1, true},
		{"1.2", "1.2.0", 0, true},
		{"1.2.3", "1.2.10", -1, true},
		{"1.2rc", "1.2", 0, false},
	} {
		got, ok := compareRVersions(test.a, test.b)
		if got != test.want || ok != test.ok {
			t.Fatalf("compareRVersions(%q, %q) = %d, %v", test.a, test.b, got, ok)
		}
	}
}

func TestInstalledRConfiguredLibraryRoots(t *testing.T) {
	roots, issues := installedRLibraryRoots([]string{
		"R_LIBS=/old/lib", "R_LIBS=/opt/ravel-test/Rlibs:/opt/other/lib",
		"R_LIBS_SITE=/usr/local/lib/R/host-site-library", "R_HOME=/opt/R/4.5/lib/R",
		"R_LIBS_USER=~/R/library/%v",
	})
	if len(roots) != 5 || len(issues) != 1 || issues[0].Name != "R_LIBS_USER" {
		t.Fatalf("configured R roots or unresolved path reporting incorrect: roots=%#v issues=%#v", roots, issues)
	}
	for _, test := range []struct {
		name, wantSource string
		found            bool
	}{
		{"opt/ravel-test/Rlibs/docopt/DESCRIPTION", "R_LIBS", true},
		{"usr/local/lib/R/host-site-library/littler/DESCRIPTION", "R_LIBS_SITE", true},
		{"opt/R/4.5/lib/R/library/base/DESCRIPTION", "", true},
		{"opt/R/4.5/lib/R/site-library/other/DESCRIPTION", "", true},
		{"old/lib/stale/DESCRIPTION", "", false},
		{"opt/ravel-test/Rlibs/nested/docopt/DESCRIPTION", "", false},
		{"opt/elsewhere/source/DESCRIPTION", "", false},
	} {
		got, found := rDescriptionLibrarySource(test.name, roots)
		if got != test.wantSource || found != test.found {
			t.Fatalf("R library path %q: source=%q found=%v", test.name, got, found)
		}
	}
}

func TestInstalledRLibraryRootsRejectUnsafeAndExcessivePaths(t *testing.T) {
	roots, issues := installedRLibraryRoots([]string{"R_LIBS=/safe:/opt/../outside:relative:/tmp/%v:/tmp/~/pkg", "R_LIBS_SITE=NULL"})
	if len(roots) != 1 || roots[0].dir != "safe" || len(issues) != 1 || issues[0].Name != "R_LIBS" {
		t.Fatalf("unsafe R roots accepted: roots=%#v issues=%#v", roots, issues)
	}
	paths := make([]string, maxRLibraryRoots+1)
	for i := range paths {
		paths[i] = fmt.Sprintf("/opt/Rlibs/%d", i)
	}
	roots, issues = installedRLibraryRoots([]string{"R_LIBS=" + strings.Join(paths, ":")})
	if len(roots) != maxRLibraryRoots || len(issues) != 1 || issues[0].Name != "R_LIBS" {
		t.Fatalf("unbounded R roots accepted: roots=%d issues=%#v", len(roots), issues)
	}
}

func TestInstalledRStartupFilesAcceptOnlyLiteralPaths(t *testing.T) {
	paths, issues := rStartupPaths([]string{
		"R_ENVIRON=../tmp/Renviron.site", "R_ENVIRON=/opt/R/Renviron.site",
		"R_PROFILE=/opt/R/%v/Rprofile.site",
	})
	if paths["R_ENVIRON"] != "opt/R/Renviron.site" || len(paths) != 1 || len(issues) != 1 || issues[0].Name != "R_PROFILE" {
		t.Fatalf("startup file path validation incorrect: paths=%#v issues=%#v", paths, issues)
	}
	roots, issues := applyRStartupRoots([]string{"R_LIBS=/old/lib"}, map[string][]byte{
		"R_ENVIRON": []byte("# startup variables\nR_LIBS=/opt/new/lib\n"),
		"R_PROFILE": []byte("# site profile\n.libPaths(c('/opt/profile/lib', .libPaths()))\n"),
	})
	if len(roots) != 2 || roots[0].dir != "opt/new/lib" || roots[0].variable != "R_ENVIRON" || roots[1].dir != "opt/profile/lib" || roots[1].variable != "R_PROFILE" || len(issues) != 0 {
		t.Fatalf("literal startup roots incorrect: roots=%#v issues=%#v", roots, issues)
	}
	for _, content := range []string{
		"if (FALSE) .libPaths(c('/opt/profile/lib', .libPaths()))\n",
		".libPaths(c('/opt/profile/lib', .libPaths()))\n.libPaths('/other')\n",
		".libPaths(c('../relative', .libPaths()))\n",
	} {
		if _, ok := rStartupProfileRoots([]byte(content)); ok {
			t.Fatalf("dynamic or unsafe startup profile accepted: %q", content)
		}
	}
	if _, ok := rStartupEnvironment([]byte("R_LIBS=${HOME}/R/library\n")); ok {
		t.Fatal("expanded startup environment path accepted")
	}
}
