package python

import "testing"

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
