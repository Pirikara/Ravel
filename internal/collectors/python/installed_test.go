package python

import "testing"

func TestInstalledMetadataInferredPURL(t *testing.T) {
	for _, tc := range []struct{ path, name, version, purl string }{
		{"usr/local/lib/python3.13/site-packages/acme_package__name-1.2+local.5.dist-info/METADATA", "Acme.Package__Name", "1.2+local.5", "pkg:pypi/acme-package-name@1.2%2Blocal.5"},
		{"usr/lib/python3/dist-packages/legacy_pkg.egg-info/PKG-INFO", "Legacy_Pkg", "1.0", "pkg:pypi/legacy-pkg@1.0"},
		{"usr/lib/python3/dist-packages/old_pkg-2.0.egg-info", "old-pkg", "2.0", "pkg:pypi/old-pkg@2.0"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			data := []byte("Metadata-Version: 2.3\nName: " + tc.name + "\nVersion: " + tc.version + "\n")
			doc, err := CollectInstalledMetadata(data, "oci:sha256:layer!/"+tc.path, "image", tc.path)
			if err != nil {
				t.Fatal(err)
			}
			component := doc.Components[0]
			if component.Name != tc.name || component.Version != tc.version || component.PURL != tc.purl || component.PURLBasis != "ecosystem_inferred" || len(component.Hashes) != 0 {
				t.Fatalf("installed identity or inferred coordinate: %#v", component)
			}
			if len(doc.Origins) != 0 || doc.Coverage.OriginState != "partial" || len(doc.Coverage.Issues) != 1 || doc.Coverage.Issues[0].Code != "distribution_source_unavailable" {
				t.Fatalf("PURL was promoted to distribution evidence: %#v", doc)
			}
		})
	}
}

func TestInstalledMetadataPaths(t *testing.T) {
	for _, name := range []string{
		"usr/lib/python3.13/site-packages/legacy_pkg.egg-info/PKG-INFO",
		"usr/lib/python3/dist-packages/legacy_pkg-1.0-py3.egg-info/PKG-INFO",
		"usr/lib/python3/dist-packages/legacy_pkg-1.0.egg-info",
		"opt/venv/lib/python3.13/site-packages/modern_pkg-1.0.dist-info/METADATA",
	} {
		if !IsInstalledMetadataPath(name) {
			t.Errorf("installed metadata rejected: %s", name)
		}
	}
	for _, name := range []string{
		"src/legacy_pkg.egg-info/PKG-INFO",
		"usr/lib/python3.13/site-packages/.egg-info/PKG-INFO",
		"usr/lib/python3/dist-packages/.egg-info",
		"usr/lib/python3.13/site-packages/legacy_pkg.egg-info/requires.txt",
		"usr/lib/python3.13/site-packages/../legacy_pkg.egg-info/PKG-INFO",
	} {
		if IsInstalledMetadataPath(name) {
			t.Errorf("non-installed metadata accepted: %s", name)
		}
	}
}

func TestInstalledEggRequirementsPaths(t *testing.T) {
	if !IsInstalledEggRequirementsPath("usr/lib/python3/dist-packages/legacy_pkg.egg-info/requires.txt") {
		t.Fatal("installed egg-info requirements rejected")
	}
	for _, name := range []string{
		"src/legacy_pkg.egg-info/requires.txt",
		"usr/lib/python3/dist-packages/.egg-info/requires.txt",
		"usr/lib/python3/dist-packages/legacy_pkg.egg-info/PKG-INFO",
	} {
		if IsInstalledEggRequirementsPath(name) {
			t.Errorf("non-installed egg-info requirements accepted: %s", name)
		}
	}
}
