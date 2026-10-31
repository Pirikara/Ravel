package composer

import "testing"

func TestInstalledManifestPath(t *testing.T) {
	for _, name := range []string{"vendor/composer/installed.json", "srv/app/vendor/composer/installed.json", "srv/app/dependencies/composer/installed.json", "composer/installed.json"} {
		if !IsInstalledManifestPath(name) {
			t.Errorf("Composer installed manifest rejected: %s", name)
		}
	}
	for _, name := range []string{"/srv/app/vendor/composer/installed.json", "../vendor/composer/installed.json", "srv/app/../vendor/composer/installed.json", "src/composer/installed.php", "other/installed.json"} {
		if IsInstalledManifestPath(name) {
			t.Errorf("non-installed Composer path accepted: %s", name)
		}
	}
}

func TestInstalledManifestRequiresPackageArray(t *testing.T) {
	for _, data := range [][]byte{[]byte(`{}`), []byte(`{"packages":null}`), []byte(`{"packages":{}}`), []byte(`[{"name":"acme/a","version":"1.0"},{"name":"acme/a","version":"2.0"}]`)} {
		if _, err := CollectInstalled(data, "test", "project", "vendor/composer/installed.json"); err == nil {
			t.Errorf("invalid Composer installed metadata accepted: %s", data)
		}
	}
	for _, data := range [][]byte{[]byte(`[]`), []byte(`{"packages":[]}`)} {
		doc, err := CollectInstalled(data, "test", "project", "vendor/composer/installed.json")
		if err != nil || doc.Coverage.Packages != 0 {
			t.Errorf("empty Composer installation rejected: %v, coverage=%#v", err, doc.Coverage)
		}
	}
}
