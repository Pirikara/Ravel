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

func TestInstalledPackageManifestPaths(t *testing.T) {
	data := []byte(`{"packages":[
		{"name":"acme/alpha","version":"1.0.0","install-path":"../acme/alpha"},
		{"name":"acme/beta","version":"1.0.0","install-path":null},
		{"name":"acme/escape","version":"1.0.0","install-path":"../../../other"},
		{"name":"acme/absolute","version":"1.0.0","install-path":"/tmp/absolute"},
		{"name":"acme/private","version":"1.0.0","install-path":"../user:secret"},
		{"name":"acme/metadata","version":"1.0.0","install-path":"."}
	]}`)
	paths := InstalledPackageManifestPaths(data, "app/dependencies/composer/installed.json")
	if len(paths) != 1 || paths["acme/alpha"] != "app/dependencies/acme/alpha/composer.json" {
		t.Fatalf("unsafe Composer install paths were selected: %#v", paths)
	}
	rootData := []byte(`[{"name":"acme/alpha","version":"1.0.0","install-path":"../acme/alpha"},{"name":"acme/escape","version":"1.0.0","install-path":"../../other"}]`)
	rootPaths := InstalledPackageManifestPaths(rootData, "composer/installed.json")
	if len(rootPaths) != 1 || rootPaths["acme/alpha"] != "acme/alpha/composer.json" {
		t.Fatalf("Composer root vendor path escaped: %#v", rootPaths)
	}
}
