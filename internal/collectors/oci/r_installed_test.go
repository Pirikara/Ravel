package oci

import (
	"strings"
	"testing"
)

const rTestDescription = "Package: MASS\nVersion: 7.3-65\nDepends: R (>= 4.4.0), stats,\n graphics\nImports: methods\nBuilt: R 4.5.1; aarch64-unknown-linux-gnu; 2025-10-31; unix\n"
const rTestPath = "usr/local/lib/R/library/MASS/DESCRIPTION"

func TestInstalledRDescriptionIdentityAndContinuation(t *testing.T) {
	record, installed, err := inspectInstalledRDescription([]byte(rTestDescription), "oci:sha256:layer!/"+rTestPath, rTestPath)
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
			_, installed, err := inspectInstalledRDescription([]byte(test.data), "oci:layer!/"+test.path, test.path)
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
